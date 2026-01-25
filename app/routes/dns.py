from flask import Blueprint, render_template, redirect, url_for, flash, request
from flask_login import login_required, current_user
from sqlalchemy import func, or_
from datetime import datetime, timezone
from app.extensions import db
from app.models import ApiToken, Domain, DnsRecord
from app.forms import DnsRecordForm

bp = Blueprint('dns', __name__)


@bp.route('/token/<int:token_id>/domains')
@login_required
def view_domains(token_id):
    token = ApiToken.query.filter_by(id=token_id, user_id=current_user.id).first_or_404()

    if token.status != 'valid':
        flash(f'凭证 "{token.name}" 状态不是 "valid"。请先验证或尝试直接获取。', 'warning')

    try:
        provider = token.get_provider()
        if not provider:
            flash('无法解密此凭证。', 'danger')
            return redirect(url_for('main.index'))

        zones_from_api = provider.get_zones()

        if not zones_from_api:
            flash(f'无法从 {token.get_provider_display_name()} 获取凭证 "{token.name}" 的域名列表。请检查凭证权限或 API 连接。', 'warning')

        updated_domains = []
        existing_zone_ids = {d.zone_id for d in token.domains}

        for zone_data in zones_from_api:
            zone_id = zone_data.get('id')
            if not zone_id:
                continue

            domain = Domain.query.filter_by(zone_id=zone_id).first()

            if domain:
                domain.name = zone_data.get('name')
                domain.status = zone_data.get('status')
                domain.fetched_at = datetime.now(timezone.utc)
                if domain not in token.domains:
                    token.domains.append(domain)
                updated_domains.append(domain)
                if zone_id in existing_zone_ids:
                    existing_zone_ids.remove(zone_id)
            else:
                new_domain = Domain(
                    zone_id=zone_id,
                    name=zone_data.get('name'),
                    status=zone_data.get('status'),
                    fetched_at=datetime.now(timezone.utc),
                    api_token=token
                )
                db.session.add(new_domain)
                updated_domains.append(new_domain)

        try:
            db.session.commit()
            if zones_from_api:
                flash(f'已同步凭证 "{token.name}" 的域名列表。', 'info')
        except Exception as e:
            db.session.rollback()
            flash(f'同步域名列表时发生数据库错误: {e}', 'danger')

    except Exception as e:
        flash(f'获取域名列表时发生错误: {str(e)}', 'danger')

    # 获取排序参数
    sort_by = request.args.get('sort', 'custom')
    
    query = Domain.query.filter_by(api_token_id=token.id)
    
    if sort_by == 'name':
        query = query.order_by(Domain.name.asc())
    elif sort_by == 'name_desc':
        query = query.order_by(Domain.name.desc())
    elif sort_by == 'status':
        query = query.order_by(Domain.status.asc(), Domain.name.asc())
    elif sort_by == 'date':
        query = query.order_by(Domain.fetched_at.desc())
    else:
        # 自定义排序：sort_order 优先，然后按域名名称
        query = query.order_by(Domain.sort_order.asc(), Domain.name.asc())
    
    domains_in_db = query.all()

    return render_template('domains.html', 
                          title=f'域名列表 - {token.name}', 
                          token=token, 
                          domains=domains_in_db,
                          current_sort=sort_by)


@bp.route('/zone/<zone_id>/dns', methods=['GET', 'POST'])
@login_required
def manage_dns_records(zone_id):
    domain = Domain.query.filter_by(zone_id=zone_id).first_or_404()
    token = domain.api_token
    if token.user_id != current_user.id:
        flash("无权访问此域名的 DNS 记录。", "danger")
        return redirect(url_for('main.index'))

    try:
        provider = token.get_provider()
    except Exception as e:
        flash(f'获取 Provider 失败: {str(e)}', 'danger')
        provider = None

    # 创建表单时传入 provider 以获取正确的记录类型和 TTL 选项
    add_form = DnsRecordForm(provider=provider)

    if add_form.validate_on_submit():
        if not provider:
            flash('无法获取凭证信息来执行操作。', 'danger')
        else:
            record_data = {
                'type': add_form.record_type.data,
                'name': add_form.name.data,
                'content': add_form.content.data,
                'ttl': add_form.ttl.data,
                'proxied': add_form.proxied.data if provider.supports_proxy() else False,
                'priority': add_form.priority.data if add_form.record_type.data in ['MX', 'SRV'] and add_form.priority.data is not None else None
            }
            success, result = provider.create_dns_record(zone_id, record_data)
            if success:
                flash(f"DNS 记录 ({record_data['type']} {record_data['name']}) 创建成功！", 'success')
                page = request.args.get('page', 1, type=int)
                return redirect(url_for('dns.manage_dns_records', zone_id=zone_id, page=page))
            else:
                flash(f"创建 DNS 记录失败: {result}", 'danger')

    # 获取搜索和筛选参数
    search_query = request.args.get('q', '').strip()
    filter_type = request.args.get('type', '').strip()
    page = request.args.get('page', 1, type=int)
    per_page = 20

    records_from_api = []
    sync_error = False
    
    if provider:
        if token.status != 'valid':
            flash(f'关联的凭证 "{token.name}" 状态不是 "valid"，获取最新记录可能失败。', 'warning')
        
        records_from_api = provider.get_dns_records(zone_id)
        if not records_from_api and token.status == 'valid':
            flash(f'未能从 {token.get_provider_display_name()} 获取域名 "{domain.name}" 的 DNS 记录。可能凭证权限不足或 API 暂时不可用。', 'warning')
            sync_error = True

        if not sync_error:
            existing_record_ids = {r.record_id for r in domain.dns_records}
            api_record_ids = set()
            for record_data in records_from_api:
                record_id = record_data.get('id')
                if not record_id:
                    continue
                api_record_ids.add(record_id)
                record = DnsRecord.query.filter_by(record_id=record_id).first()
                if record:
                    record.type = record_data.get('type')
                    record.name = record_data.get('name')
                    record.content = record_data.get('content')
                    record.ttl = record_data.get('ttl')
                    record.proxied = record_data.get('proxied', False)
                    record.priority = record_data.get('priority')
                    if record not in domain.dns_records:
                        domain.dns_records.append(record)
                else:
                    record = DnsRecord(
                        record_id=record_id,
                        type=record_data.get('type'),
                        name=record_data.get('name'),
                        content=record_data.get('content'),
                        ttl=record_data.get('ttl'),
                        proxied=record_data.get('proxied', False),
                        priority=record_data.get('priority'),
                        domain=domain
                    )
                    db.session.add(record)
                if record_id in existing_record_ids:
                    existing_record_ids.remove(record_id)
            try:
                db.session.commit()
            except Exception as e:
                db.session.rollback()
                flash(f'同步 DNS 记录时发生数据库错误: {e}', 'danger')
                sync_error = True
    else:
        flash('无法获取凭证信息，无法获取最新记录。', 'danger')
        sync_error = True

    # 构建查询，支持搜索和筛选
    try:
        query = DnsRecord.query.filter_by(domain_id=domain.id)
        
        # 按类型筛选
        if filter_type:
            query = query.filter(DnsRecord.type == filter_type)
        
        # 搜索（名称或内容）
        if search_query:
            search_pattern = f'%{search_query}%'
            query = query.filter(
                or_(
                    DnsRecord.name.ilike(search_pattern),
                    DnsRecord.content.ilike(search_pattern)
                )
            )
        
        # 排序和分页
        query = query.order_by(func.lower(DnsRecord.type), func.lower(DnsRecord.name))
        pagination = query.paginate(page=page, per_page=per_page, error_out=False)
        records_on_page = pagination.items
        
        # 获取所有记录类型（用于筛选下拉框）
        all_types = db.session.query(DnsRecord.type).filter_by(domain_id=domain.id).distinct().order_by(DnsRecord.type).all()
        available_types = [t[0] for t in all_types]
        
        # 统计信息
        total_records = DnsRecord.query.filter_by(domain_id=domain.id).count()
        filtered_count = pagination.total
        
    except Exception as e:
        flash(f"查询本地 DNS 记录时出错: {e}", "danger")
        pagination = None
        records_on_page = []
        available_types = []
        total_records = 0
        filtered_count = 0

    return render_template('dns_records.html',
                           title=f'DNS 记录 - {domain.name}',
                           domain=domain,
                           token=token,
                           records=records_on_page,
                           add_form=add_form,
                           pagination=pagination,
                           supports_proxy=provider.supports_proxy() if provider else False,
                           # 搜索筛选相关
                           search_query=search_query,
                           filter_type=filter_type,
                           available_types=available_types,
                           total_records=total_records,
                           filtered_count=filtered_count)


@bp.route('/dns_record/<record_id>/delete', methods=['POST'])
@login_required
def delete_dns_record_route(record_id):
    record = DnsRecord.query.filter_by(record_id=record_id).first_or_404()
    domain = record.domain
    token = domain.api_token
    if token.user_id != current_user.id:
        flash("无权删除此 DNS 记录。", "danger")
        return redirect(url_for('main.index'))

    try:
        provider = token.get_provider()
        if not provider:
            flash('无法获取凭证信息来执行删除操作。', 'danger')
            return redirect(url_for('dns.manage_dns_records', zone_id=domain.zone_id))

        success, message = provider.delete_dns_record(domain.zone_id, record_id)

        if success:
            db.session.delete(record)
            db.session.commit()
            flash(f"DNS 记录 ({record.type} {record.name}) 删除成功！", 'success')
        else:
            flash(f"删除 DNS 记录失败: {message}", 'danger')
    except Exception as e:
        flash(f'删除 DNS 记录时发生错误: {str(e)}', 'danger')

    return redirect(url_for('dns.manage_dns_records', zone_id=domain.zone_id))


@bp.route('/dns_record/<record_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_dns_record_route(record_id):
    record = DnsRecord.query.filter_by(record_id=record_id).first_or_404()
    domain = record.domain
    token = domain.api_token
    if token.user_id != current_user.id:
        flash("无权编辑此 DNS 记录。", "danger")
        return redirect(url_for('main.index'))

    try:
        provider = token.get_provider()
    except Exception as e:
        flash(f'获取 Provider 失败: {str(e)}', 'danger')
        provider = None

    form = DnsRecordForm(provider=provider, obj=record)

    if form.validate_on_submit():
        if not provider:
            flash('无法获取凭证信息来执行操作。', 'danger')
        else:
            updated_data = {
                'type': request.form.get('record_type'),
                'name': form.name.data,
                'content': form.content.data,
                'ttl': form.ttl.data,
                'proxied': form.proxied.data if provider.supports_proxy() else False,
                'priority': record.priority if record.type in ['MX', 'SRV'] else None
            }
            success, result = provider.update_dns_record(domain.zone_id, record_id, updated_data)
            if success:
                api_result = result or {}
                record.type = api_result.get('type', request.form.get('record_type'))
                record.name = api_result.get('name', form.name.data)
                record.content = api_result.get('content', form.content.data)
                record.ttl = api_result.get('ttl', form.ttl.data)
                record.proxied = api_result.get('proxied', form.proxied.data)
                db.session.commit()
                flash(f"DNS 记录 ({record.type} {record.name}) 更新成功！", 'success')
                return redirect(url_for('dns.manage_dns_records', zone_id=domain.zone_id))
            else:
                flash(f"更新 DNS 记录失败: {result}", 'danger')

    return render_template('edit_dns_record.html',
                           title=f'编辑 DNS 记录 - {record.name}',
                           form=form,
                           record=record,
                           domain=domain,
                           token=token,
                           supports_proxy=provider.supports_proxy() if provider else False)


@bp.route('/zone/<zone_id>/dns/bulk_delete', methods=['POST'])
@login_required
def bulk_delete_dns_records(zone_id):
    domain = Domain.query.filter_by(zone_id=zone_id).first_or_404()
    token = domain.api_token
    if token.user_id != current_user.id:
        flash("无权执行此操作。", "danger")
        return redirect(url_for('main.index'))

    record_ids_to_delete = request.form.getlist('record_ids')
    if not record_ids_to_delete:
        flash("没有选择任何要删除的记录。", "warning")
        return redirect(url_for('dns.manage_dns_records', zone_id=zone_id))

    try:
        provider = token.get_provider()
        if not provider:
            flash('无法获取凭证信息来执行删除操作。', 'danger')
            return redirect(url_for('dns.manage_dns_records', zone_id=zone_id))
    except Exception as e:
        flash(f'获取 Provider 失败: {str(e)}', 'danger')
        return redirect(url_for('dns.manage_dns_records', zone_id=zone_id))

    success_count = 0
    fail_count = 0
    error_messages = []

    for record_id in record_ids_to_delete:
        success, message = provider.delete_dns_record(zone_id, record_id)
        if success:
            record_to_delete = DnsRecord.query.filter_by(record_id=record_id, domain_id=domain.id).first()
            if record_to_delete:
                db.session.delete(record_to_delete)
            success_count += 1
        else:
            fail_count += 1
            failed_record = DnsRecord.query.filter_by(record_id=record_id, domain_id=domain.id).first()
            record_name = f"{failed_record.type} {failed_record.name}" if failed_record else f"ID: {record_id}"
            error_messages.append(f"{record_name}: {message}")

    if success_count > 0:
        try:
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            flash(f"删除记录后更新数据库时出错: {e}", "danger")
            fail_count += success_count
            success_count = 0
            error_messages.append("数据库更新失败")

    if fail_count == 0:
        flash(f"成功删除了 {success_count} 条 DNS 记录。", "success")
    else:
        error_details = "; ".join(error_messages)
        flash(f"批量删除操作完成：成功 {success_count} 条，失败 {fail_count} 条。错误详情: {error_details}", "warning")

    return redirect(url_for('dns.manage_dns_records', zone_id=zone_id))
