from flask import Blueprint, abort, current_app, render_template, redirect, url_for, flash, request
from flask_login import login_required, current_user
from flask_wtf import FlaskForm
from sqlalchemy import func, or_
from sqlalchemy.exc import MultipleResultsFound
from app.dns_sync import advance_record_cache, sync_domains, sync_records
from app.extensions import db
from app.models import ApiToken, Domain, DnsRecord
from app.forms import DnsRecordForm

bp = Blueprint('dns', __name__)


def owned_domain(domain_id, zone_id=None):
    query = Domain.query.join(ApiToken).filter(ApiToken.user_id == current_user.id)
    if domain_id is not None:
        return query.filter(Domain.id == domain_id).first_or_404()
    try:
        domain = query.filter(Domain.zone_id == zone_id).one_or_none()
    except MultipleResultsFound:
        abort(404)
    return domain or abort(404)


def owned_record(record_pk, record_id):
    query = DnsRecord.query.join(Domain).join(ApiToken).filter(ApiToken.user_id == current_user.id)
    if record_pk is not None:
        return query.filter(DnsRecord.id == record_pk).first_or_404()
    try:
        record = query.filter(DnsRecord.record_id == record_id).one_or_none()
    except MultipleResultsFound:
        abort(404)
    return record or abort(404)


def provider_for(token):
    try:
        provider = token.get_provider()
    except Exception:
        current_app.logger.exception('无法初始化 DNS 服务商')
        provider = None
    if provider is None:
        flash('无法读取服务商凭证，请检查凭证配置。', 'danger')
    return provider


def refresh_records(domain, provider):
    try:
        sync_records(domain, provider)
    except Exception:
        db.session.rollback()
        current_app.logger.exception('同步 DNS 记录失败')
        return False
    return True


@bp.route('/token/<int:token_id>/domains', methods=['GET', 'POST'])
@login_required
def view_domains(token_id):
    token = ApiToken.query.filter_by(id=token_id, user_id=current_user.id).first_or_404()
    action_form = FlaskForm()
    sort_by = request.args.get('sort', 'custom')

    if request.method == 'POST':
        if not action_form.validate_on_submit():
            abort(400)
        provider = provider_for(token)
        if provider is not None:
            try:
                sync_domains(token, provider)
                flash('已刷新域名列表。', 'success')
            except Exception:
                db.session.rollback()
                current_app.logger.exception('同步域名列表失败')
                flash('同步失败，已保留本地列表。', 'warning')
        return redirect(url_for('dns.view_domains', token_id=token_id, sort=sort_by))
    
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
                          action_form=action_form,
                          current_sort=sort_by)


@bp.route('/zone/<zone_id>/dns', methods=['GET', 'POST'])
@bp.route('/domains/<int:domain_id>/dns', methods=['GET', 'POST'])
@login_required
def manage_dns_records(domain_id=None, zone_id=None):
    domain = owned_domain(domain_id, zone_id)
    token = domain.api_token
    provider = provider_for(token)

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
            success, result = provider.create_dns_record(domain.zone_id, record_data)
            if success:
                flash(f"DNS 记录 ({record_data['type']} {record_data['name']}) 创建成功！", 'success')
                if not refresh_records(domain, provider):
                    flash('云端已创建，本地刷新失败，请稍后重试刷新。', 'warning')
                page = request.args.get('page', 1, type=int)
                return redirect(url_for('dns.manage_dns_records', domain_id=domain.id, page=page))
            else:
                flash(f"创建 DNS 记录失败: {result}", 'danger')

    # 获取搜索和筛选参数
    search_query = request.args.get('q', '').strip()
    filter_type = request.args.get('type', '').strip()
    page = request.args.get('page', 1, type=int)
    per_page = 20

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
                           action_form=FlaskForm(),
                           pagination=pagination,
                           supports_proxy=provider.supports_proxy() if provider else False,
                           # 搜索筛选相关
                           search_query=search_query,
                           filter_type=filter_type,
                           available_types=available_types,
                           total_records=total_records,
                           filtered_count=filtered_count)


@bp.route('/domains/<int:domain_id>/dns/sync', methods=['POST'])
@login_required
def sync_domain_records(domain_id):
    domain = owned_domain(domain_id)
    if not FlaskForm().validate_on_submit():
        abort(400)
    provider = provider_for(domain.api_token)
    if provider is not None:
        if refresh_records(domain, provider):
            flash('已刷新 DNS 记录。', 'success')
        else:
            flash('同步失败，已保留本地记录。', 'warning')
    return redirect(url_for('dns.manage_dns_records', domain_id=domain_id,
                            q=request.args.get('q') or None, type=request.args.get('type') or None))


@bp.route('/dns_record/<record_id>/delete', methods=['POST'])
@bp.route('/records/<int:record_pk>/delete', methods=['POST'])
@login_required
def delete_dns_record_route(record_pk=None, record_id=None):
    record = owned_record(record_pk, record_id)
    if not FlaskForm().validate_on_submit():
        abort(400)
    domain = record.domain
    provider = provider_for(domain.api_token)
    if provider is not None:
        success, message = provider.delete_dns_record(domain.zone_id, record.record_id)
        if success:
            flash(f"DNS 记录 ({record.type} {record.name}) 删除成功！", 'success')
            save_deleted_records(domain.id, [record])
        else:
            flash(f"删除 DNS 记录失败: {message}", 'danger')

    return redirect(url_for('dns.manage_dns_records', domain_id=domain.id))


def save_deleted_records(domain_id, records):
    try:
        advance_record_cache(domain_id)
        for record in records:
            db.session.delete(record)
        db.session.commit()
    except Exception:
        db.session.rollback()
        current_app.logger.exception('更新已删除记录的缓存失败')
        flash('云端已删除，本地更新失败，请稍后重试刷新。', 'warning')


@bp.route('/dns_record/<record_id>/edit', methods=['GET', 'POST'])
@bp.route('/records/<int:record_pk>/edit', methods=['GET', 'POST'])
@login_required
def edit_dns_record_route(record_pk=None, record_id=None):
    record = owned_record(record_pk, record_id)
    domain = record.domain
    token = domain.api_token
    provider = provider_for(token)
    from_search = request.args.get('source') == 'search'
    search_query = request.args.get('q') or None
    if from_search:
        return_url = url_for('main.index', q=search_query, sort=request.args.get('sort'))
    else:
        return_url = url_for('dns.manage_dns_records', domain_id=domain.id, q=search_query,
                             type=request.args.get('type') or None, page=request.args.get('page', type=int))

    form = DnsRecordForm(provider=provider, obj=record)

    if form.validate_on_submit():
        if not provider:
            flash('无法获取凭证信息来执行操作。', 'danger')
        elif form.record_type.data != record.type:
            abort(400)
        else:
            updated_data = {
                'type': record.type,
                'name': form.name.data,
                'content': form.content.data,
                'ttl': form.ttl.data,
                'proxied': form.proxied.data if provider.supports_proxy() else False,
                'priority': record.priority if record.type in ['MX', 'SRV'] else None
            }
            success, result = provider.update_dns_record(domain.zone_id, record.record_id, updated_data)
            if success:
                flash(f"DNS 记录 ({updated_data['type']} {updated_data['name']}) 更新成功！", 'success')
                if not refresh_records(domain, provider):
                    flash('云端已更新，本地刷新失败，请稍后重试刷新。', 'warning')
                return redirect(return_url)
            else:
                flash(f"更新 DNS 记录失败: {result}", 'danger')

    return render_template('edit_dns_record.html',
                           title=f'编辑 DNS 记录 - {record.name}',
                           form=form,
                           record=record,
                           domain=domain,
                           token=token,
                           return_url=return_url,
                           from_search=from_search,
                           supports_proxy=provider.supports_proxy() if provider else False)


@bp.route('/zone/<zone_id>/dns/bulk_delete', methods=['POST'])
@bp.route('/domains/<int:domain_id>/dns/bulk_delete', methods=['POST'])
@login_required
def bulk_delete_dns_records(domain_id=None, zone_id=None):
    domain = owned_domain(domain_id, zone_id)
    if not FlaskForm().validate_on_submit():
        abort(400)
    redirect_url = url_for('dns.manage_dns_records', domain_id=domain.id)

    record_ids = set(request.form.getlist('record_ids'))
    if not record_ids:
        flash("没有选择任何要删除的记录。", "warning")
        return redirect(redirect_url)

    records = DnsRecord.query.filter(DnsRecord.domain_id == domain.id, DnsRecord.record_id.in_(record_ids)).all()
    if len(records) != len(record_ids):
        flash('所选记录已变更，请刷新后重新选择。', 'warning')
        return redirect(redirect_url)

    provider = provider_for(domain.api_token)
    if provider is None:
        return redirect(redirect_url)

    deleted_records = []
    error_messages = []

    for record in records:
        success, message = provider.delete_dns_record(domain.zone_id, record.record_id)
        if success:
            deleted_records.append(record)
        else:
            error_messages.append(f"{record.type} {record.name}: {message}")

    if deleted_records:
        save_deleted_records(domain.id, deleted_records)
    if not error_messages:
        flash(f"成功删除了 {len(deleted_records)} 条 DNS 记录。", "success")
    else:
        error_details = "; ".join(error_messages)
        flash(f"批量删除操作完成：成功 {len(deleted_records)} 条，失败 {len(error_messages)} 条。错误详情: {error_details}", "warning")

    return redirect(redirect_url)
