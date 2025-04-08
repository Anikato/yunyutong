import os
from dotenv import load_dotenv

# 在所有其他导入和代码之前加载 .env 文件
load_dotenv()

# 导入 Flask 相关的和其他需要的模块
from flask import Flask, render_template, url_for, flash, redirect, request
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, current_user, logout_user, login_required # 导入 Flask-Login 相关
# 导入模型和表单
from models import User, ApiToken, Domain, DnsRecord, db # 确保 db 也被导入或正确初始化
from forms import RegistrationForm, LoginForm, ApiTokenForm, EditApiTokenForm, DnsRecordForm, ChangePasswordForm # 导入 EditApiTokenForm 和 ChangePasswordForm
from utils import verify_api_token, get_zones_for_token, get_dns_records, create_dns_record, delete_dns_record, update_dns_record
from datetime import datetime, timezone # 需要导入 datetime 处理 fetched_at
from sqlalchemy.orm import selectinload # 需要导入 selectinload
from sqlalchemy import func # 需要导入 func for case-insensitive sort
from werkzeug.security import generate_password_hash, check_password_hash

# 加载 .env 文件中的环境变量
# load_dotenv()

# 初始化 Flask 应用
app = Flask(__name__)

# 配置数据库
# 使用 SQLite，数据库文件将存储在项目根目录下的 yunyutong.db
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///yunyutong.db'
# 关闭 SQLAlchemy 的事件通知系统，如果不使用可以节省资源
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
# 设置一个用于 session 和 CSRF 保护的密钥
# 我们从环境变量加载，如果未设置则使用一个默认值（仅供开发）
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-key-replace-in-production')

# 初始化 SQLAlchemy 扩展
db.init_app(app)

# 配置 Flask-Login
login_manager = LoginManager(app)
login_manager.login_view = 'login' # 指定登录页面的端点名
login_manager.login_message = '请先登录以访问此页面。' # 未登录访问受保护页面时的提示消息
login_manager.login_message_category = 'info' # 消息的类别 (用于 flash 消息样式)

@login_manager.user_loader
def load_user(user_id):
    # Flask-Login 通过 session 存储 user_id，这个函数根据 id 加载用户对象
    return User.query.get(int(user_id))

# --- 新的首页路由 ---
@app.route('/')
@app.route('/index')
def index():
    tokens = []
    if current_user.is_authenticated:
        # 使用 options(selectinload(ApiToken.domains)) 来预加载域名
        tokens = ApiToken.query.filter_by(user_id=current_user.id)\
            .options(selectinload(ApiToken.domains))\
            .order_by(ApiToken.added_at.desc()).all()
    return render_template('index.html', title='主页', tokens=tokens)


# --- 用户认证路由 ---
@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated: # 如果用户已登录，重定向到首页
        return redirect(url_for('index'))
    form = RegistrationForm()
    if form.validate_on_submit(): # POST 请求且表单验证通过
        user = User(username=form.username.data)
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        flash(f'账户 {form.username.data} 创建成功！现在可以登录了。', 'success')
        return redirect(url_for('login')) # 注册成功后重定向到登录页
    return render_template('register.html', title='注册', form=form) # GET 请求或验证失败，显示注册表单

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated: # 如果用户已登录，重定向到首页
        return redirect(url_for('index'))
    form = LoginForm()
    if form.validate_on_submit(): # POST 请求且表单验证通过
        user = User.query.filter_by(username=form.username.data).first()
        if user and user.check_password(form.password.data):
            # 用户存在且密码正确，登录用户
            login_user(user, remember=form.remember.data) # remember 参数来自表单
            # 处理 next 参数
            next_page = request.args.get('next')
            flash('登录成功！', 'success')
            # 确保 next_page 是一个安全的 URL (防止开放重定向攻击)
            # 简单的检查：只重定向到本站的相对路径
            if next_page and not next_page.startswith('/'):
                 next_page = None # 如果 next 参数不是相对路径，忽略它
            return redirect(next_page) if next_page else redirect(url_for('index')) # 重定向到目标页或首页
        else:
            flash('登录失败，请检查用户名和密码。', 'danger')
    return render_template('login.html', title='登录', form=form) # GET 请求或验证失败，显示登录表单

@app.route('/logout')
def logout():
    logout_user() # 登出用户
    flash('您已成功登出。', 'info')
    return redirect(url_for('login')) # 登出后重定向到登录页

# --- API Token 路由 ---
@app.route('/add_token', methods=['GET', 'POST'])
@login_required # 确保用户已登录
def add_token():
    form = ApiTokenForm()
    if form.validate_on_submit(): # POST 请求且表单验证通过
        # 创建新的 ApiToken 实例
        new_token = ApiToken(
            name=form.name.data,
            remarks=form.remarks.data,
            owner=current_user # 直接关联当前登录的用户
        )
        # 使用模型中的 set_token 方法来加密和设置 token
        new_token.set_token(form.token.data)
        # (可选) 在这里添加验证 Token 有效性的代码

        # 将新 Token 添加到数据库会话并提交
        db.session.add(new_token)
        db.session.commit()

        flash(f'API Token "{form.name.data}" 添加成功！', 'success')
        return redirect(url_for('index')) # 添加成功后重定向回主页

    # GET 请求或表单验证失败，渲染添加 Token 的页面
    return render_template('add_token.html', title='添加 API Token', form=form)

@app.route('/token/<int:token_id>/verify', methods=['POST']) # 只允许 POST 请求
@login_required
def verify_token(token_id):
    # 查找 token，确保它存在且属于当前用户
    token = ApiToken.query.filter_by(id=token_id, user_id=current_user.id).first_or_404()

    # 解密 token
    decrypted_token = token.get_token()
    if not decrypted_token:
        flash('无法解密此 Token，请检查应用的加密密钥配置。', 'danger')
        return redirect(url_for('index'))

    # 调用工具函数验证 token
    is_valid = verify_api_token(decrypted_token)

    # 更新数据库中的状态
    if is_valid:
        token.status = 'valid'
        flash(f'Token "{token.name}" 验证成功！', 'success')
    else:
        token.status = 'invalid'
        flash(f'Token "{token.name}" 验证失败或无效。请检查 Token 是否正确或拥有足够权限。', 'danger')

    db.session.commit() # 提交状态更改

    return redirect(url_for('index')) # 重定向回主页

@app.route('/token/<int:token_id>/domains')
@login_required
def view_domains(token_id):
    token = ApiToken.query.filter_by(id=token_id, user_id=current_user.id).first_or_404()

    # 验证 Token 状态，如果不是 valid，可以选择提示用户先验证或尝试获取
    if token.status != 'valid':
        flash(f'Token "{token.name}" 状态不是 "valid"。请先验证或尝试直接获取。', 'warning')
        # return redirect(url_for('index')) # 或者可以选择继续尝试

    decrypted_token = token.get_token()
    if not decrypted_token:
        flash('无法解密此 Token。', 'danger')
        return redirect(url_for('index'))

    # 从 Cloudflare API 获取 Zones
    zones_from_api = get_zones_for_token(decrypted_token)

    if not zones_from_api:
        flash(f'无法从 Cloudflare 获取 Token "{token.name}" 的域名列表。请检查 Token 权限或 API 连接。', 'warning')

    # 将获取到的 Zones 同步到数据库
    updated_domains = []
    existing_zone_ids = {d.zone_id for d in token.domains} # 获取数据库中已存在的 Zone ID

    for zone_data in zones_from_api:
        zone_id = zone_data.get('id')
        if not zone_id: continue # 跳过无效数据

        # 检查数据库中是否已存在该 Zone ID
        domain = Domain.query.filter_by(zone_id=zone_id).first()

        if domain:
            # 更新现有域名的信息
            domain.name = zone_data.get('name')
            domain.status = zone_data.get('status')
            domain.fetched_at = datetime.now(timezone.utc)
            # 确保它关联到当前的 token (如果之前没关联的话)
            if domain not in token.domains:
                 token.domains.append(domain)
            updated_domains.append(domain)
            if zone_id in existing_zone_ids:
                 existing_zone_ids.remove(zone_id) # 从待删除集合中移除
        else:
            # 创建新的域名记录
            new_domain = Domain(
                zone_id=zone_id,
                name=zone_data.get('name'),
                status=zone_data.get('status'),
                fetched_at=datetime.now(timezone.utc),
                api_token=token # 关联到当前 Token
            )
            db.session.add(new_domain)
            updated_domains.append(new_domain)

    # (可选) 处理在 Cloudflare 上已不存在但在数据库中存在的域名
    # for zone_id_to_remove in existing_zone_ids:
    #     domain_to_remove = Domain.query.filter_by(zone_id=zone_id_to_remove, api_token_id=token.id).first()
    #     if domain_to_remove:
    #         db.session.delete(domain_to_remove)
    #         print(f"从数据库中移除 Zone: {domain_to_remove.name} (ID: {zone_id_to_remove})")

    try:
        db.session.commit()
        if zones_from_api: # 只有成功获取到 API 数据时才提示同步
             flash(f'已同步 Token "{token.name}" 的域名列表。', 'info')
    except Exception as e:
        db.session.rollback() # 如果出错则回滚
        flash(f'同步域名列表时发生数据库错误: {e}', 'danger')
        print(f"数据库错误: {e}")

    # 重新从数据库查询该 token 关联的所有域名，以确保显示最新数据
    domains_in_db = Domain.query.filter_by(api_token_id=token.id).order_by(Domain.name).all()

    return render_template('domains.html', title=f'域名列表 - {token.name}', token=token, domains=domains_in_db)

@app.route('/token/<int:token_id>/delete', methods=['POST'])
@login_required
def delete_token(token_id):
    token = ApiToken.query.filter_by(id=token_id, user_id=current_user.id).first_or_404()
    try:
        token_name = token.name
        db.session.delete(token)
        db.session.commit()
        flash(f'API Token "{token_name}" 及其关联的域名和记录已成功删除。', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'删除 API Token 时发生错误: {e}', 'danger')
        print(f"删除 Token 时数据库错误: {e}")
    return redirect(url_for('index'))

@app.route('/edit_token/<int:token_id>', methods=['GET', 'POST'])
@login_required
def edit_token(token_id):
    token_to_edit = ApiToken.query.get_or_404(token_id)
    # 确保当前用户是这个 Token 的所有者
    if token_to_edit.user_id != current_user.id:
        flash('无权编辑此 Token。', 'danger')
        return redirect(url_for('index'))

    form = EditApiTokenForm(obj=token_to_edit) # 使用 obj 预填充表单

    # 新增：解密 Token 以便在模板中使用
    decrypted_token_value = ""
    try:
        # 使用模型自带的 get_token() 方法进行解密
        decrypted_token_value = token_to_edit.get_token()
        if decrypted_token_value is None:
             # 如果 get_token() 返回 None，说明解密失败
             raise ValueError("get_token() returned None, decryption failed.")
    except Exception as e:
        # 处理解密失败的情况
        flash('无法解密此 Token 用于复制，请检查环境变量 ENCRYPTION_KEY 是否设置正确。', 'warning')
        print(f"Error decrypting token {token_id} using get_token(): {e}") # 记录错误日志
        decrypted_token_value = "" # 确保传递空字符串而不是 None

    if form.validate_on_submit():
        # 更新 Token 名称和备注
        token_to_edit.name = form.name.data
        token_to_edit.remarks = form.remarks.data
        db.session.commit()
        flash('Token 信息已更新。', 'success')
        return redirect(url_for('index'))
    elif request.method == 'GET':
        # 预填充表单 (如果上面 obj 方式无效，或者确保填充最新)
        form.name.data = token_to_edit.name
        form.remarks.data = token_to_edit.remarks

    # 将解密后的 Token 值传递给模板
    return render_template('edit_token.html',
                           title='编辑 API Token',
                           form=form,
                           token=token_to_edit, # 传递原始 token 对象
                           decrypted_token=decrypted_token_value) # 传递解密后的值

# --- DNS 记录路由 ---
@app.route('/zone/<zone_id>/dns', methods=['GET', 'POST'])
@login_required
def manage_dns_records(zone_id):
    domain = Domain.query.filter_by(zone_id=zone_id).first_or_404()
    token = domain.api_token
    if token.user_id != current_user.id:
        flash("无权访问此域名的 DNS 记录。", "danger")
        return redirect(url_for('index'))

    add_form = DnsRecordForm()
    decrypted_token = token.get_token() # Get decrypted token early

    # --- 处理 POST 请求 (添加记录) ---
    if add_form.validate_on_submit():
        if not decrypted_token:
            flash('无法解密关联的 Token 来执行操作。', 'danger')
        else:
            record_data = {
                'type': add_form.record_type.data,
                'name': add_form.name.data,
                'content': add_form.content.data,
                'ttl': add_form.ttl.data,
                'proxied': add_form.proxied.data,
                'priority': add_form.priority.data if add_form.record_type.data in ['MX', 'SRV'] and add_form.priority.data is not None else None
            }
            success, result = create_dns_record(decrypted_token, zone_id, record_data)
            if success:
                flash(f"DNS 记录 ({record_data['type']} {record_data['name']}) 创建成功！", 'success')
                page = request.args.get('page', 1, type=int)
                return redirect(url_for('manage_dns_records', zone_id=zone_id, page=page))
            else:
                flash(f"创建 DNS 记录失败: {result}", 'danger')
                # Fall through to re-render GET with form errors

    # --- 处理 GET 请求 ---
    page = request.args.get('page', 1, type=int)
    per_page = 20

    # Step 1: Attempt to fetch latest records from Cloudflare and sync to DB
    records_from_api = []
    sync_error = False
    if decrypted_token:
        if token.status != 'valid':
             flash(f'关联的 Token "{token.name}" 状态不是 "valid"，获取最新记录可能失败。', 'warning')
        records_from_api = get_dns_records(decrypted_token, zone_id)
        if not records_from_api and token.status == 'valid':
             flash(f'未能从 Cloudflare 获取 Zone "{domain.name}" 的 DNS 记录。可能 Token 权限不足或 API 暂时不可用。', 'warning')
             sync_error = True

        if not sync_error:
            existing_record_ids = {r.record_id for r in domain.dns_records}
            api_record_ids = set()
            for record_data in records_from_api:
                record_id = record_data.get('id')
                if not record_id: continue
                api_record_ids.add(record_id)
                record = DnsRecord.query.filter_by(record_id=record_id).first()
                if record:
                    record.type = record_data.get('type'); record.name = record_data.get('name'); record.content = record_data.get('content'); record.ttl = record_data.get('ttl'); record.proxied = record_data.get('proxied', False)
                    if record not in domain.dns_records: domain.dns_records.append(record)
                else:
                    record = DnsRecord(record_id=record_id, type=record_data.get('type'), name=record_data.get('name'), content=record_data.get('content'), ttl=record_data.get('ttl'), proxied=record_data.get('proxied', False), domain=domain)
                    db.session.add(record)
                if record_id in existing_record_ids: existing_record_ids.remove(record_id)
            # Optional deletion of stale records
            # ...
            try:
                db.session.commit()
            except Exception as e:
                db.session.rollback()
                flash(f'同步 DNS 记录时发生数据库错误: {e}', 'danger')
                sync_error = True
    else:
         flash('无法解密关联的 Token，无法获取最新记录。', 'danger')
         sync_error = True

    # Step 2: Paginate records FROM THE DATABASE
    try:
        pagination = DnsRecord.query.filter_by(domain_id=domain.id)\
            .order_by(func.lower(DnsRecord.type), func.lower(DnsRecord.name))\
            .paginate(page=page, per_page=per_page, error_out=False)
        records_on_page = pagination.items
    except Exception as e:
        flash(f"查询本地 DNS 记录时出错: {e}", "danger")
        pagination = None
        records_on_page = []

    if not pagination or pagination.total == 0:
         pass

    return render_template('dns_records.html',
                           title=f'DNS 记录 - {domain.name}',
                           domain=domain,
                           token=token,
                           records=records_on_page,
                           add_form=add_form,
                           pagination=pagination)

@app.route('/dns_record/<record_id>/delete', methods=['POST'])
@login_required
def delete_dns_record_route(record_id):
    # 查找要删除的记录
    record = DnsRecord.query.filter_by(record_id=record_id).first_or_404()
    # 获取关联的 Domain 和 Token，并验证所有权
    domain = record.domain
    token = domain.api_token
    if token.user_id != current_user.id:
        flash("无权删除此 DNS 记录。", "danger")
        return redirect(url_for('index'))

    # 获取解密后的 Token
    decrypted_token = token.get_token()
    if not decrypted_token:
        flash('无法解密关联的 Token 来执行删除操作。', 'danger')
        return redirect(url_for('manage_dns_records', zone_id=domain.zone_id))

    # 调用 API 删除记录
    success, message = delete_dns_record(decrypted_token, domain.zone_id, record_id)

    if success:
        # 从数据库中也删除该记录
        db.session.delete(record)
        db.session.commit()
        flash(f"DNS 记录 ({record.type} {record.name}) 删除成功！", 'success')
    else:
        flash(f"删除 DNS 记录失败: {message}", 'danger')

    # 重定向回 DNS 管理页面
    return redirect(url_for('manage_dns_records', zone_id=domain.zone_id))

@app.route('/dns_record/<record_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_dns_record_route(record_id):
    record = DnsRecord.query.filter_by(record_id=record_id).first_or_404()
    domain = record.domain
    token = domain.api_token
    if token.user_id != current_user.id:
        flash("无权编辑此 DNS 记录。", "danger")
        return redirect(url_for('index'))

    form = DnsRecordForm(obj=record)

    if form.validate_on_submit():
        decrypted_token = token.get_token()
        if not decrypted_token:
            flash('无法解密关联的 Token 来执行操作。', 'danger')
        else:
            updated_data = {
                # 从隐藏字段获取 type
                'type': request.form.get('record_type'), # <--- 从 request.form 获取
                'name': form.name.data,
                'content': form.content.data,
                'ttl': form.ttl.data,
                'proxied': form.proxied.data,
                # 保留原始 priority，通常不在编辑时修改
                'priority': record.priority if record.type in ['MX', 'SRV'] else None
            }
            success, result = update_dns_record(decrypted_token, domain.zone_id, record_id, updated_data)
            if success:
                api_result = result or {}
                # 更新数据库记录时也从 request.form 获取 type
                record.type = api_result.get('type', request.form.get('record_type'))
                record.name = api_result.get('name', form.name.data)
                record.content = api_result.get('content', form.content.data)
                record.ttl = api_result.get('ttl', form.ttl.data)
                record.proxied = api_result.get('proxied', form.proxied.data)
                db.session.commit()
                flash(f"DNS 记录 ({record.type} {record.name}) 更新成功！", 'success')
                return redirect(url_for('manage_dns_records', zone_id=domain.zone_id))
            else:
                 flash(f"更新 DNS 记录失败: {result}", 'danger')

    # GET 请求或 POST 验证失败
    return render_template('edit_dns_record.html',
                           title=f'编辑 DNS 记录 - {record.name}',
                           form=form,
                           record=record,
                           domain=domain,
                           token=token)

@app.route('/zone/<zone_id>/dns/bulk_delete', methods=['POST'])
@login_required
def bulk_delete_dns_records(zone_id):
    domain = Domain.query.filter_by(zone_id=zone_id).first_or_404()
    token = domain.api_token
    if token.user_id != current_user.id:
        flash("无权执行此操作。", "danger")
        return redirect(url_for('index'))

    record_ids_to_delete = request.form.getlist('record_ids')
    if not record_ids_to_delete:
        flash("没有选择任何要删除的记录。", "warning")
        return redirect(url_for('manage_dns_records', zone_id=zone_id))

    decrypted_token = token.get_token()
    if not decrypted_token:
        flash('无法解密关联的 Token 来执行删除操作。', 'danger')
        return redirect(url_for('manage_dns_records', zone_id=zone_id))

    success_count = 0
    fail_count = 0
    error_messages = []

    for record_id in record_ids_to_delete:
        success, message = delete_dns_record(decrypted_token, zone_id, record_id)
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

    return redirect(url_for('manage_dns_records', zone_id=zone_id))

@app.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    form = ChangePasswordForm()
    if form.validate_on_submit():
        # 1. 验证当前密码是否正确
        if check_password_hash(current_user.password_hash, form.current_password.data):
            # 2. 如果正确，更新密码
            current_user.password_hash = generate_password_hash(form.new_password.data)
            db.session.commit()
            flash('密码修改成功！', 'success')
            return redirect(url_for('index')) # 修改成功后重定向到主页
        else:
            flash('当前密码不正确，请重试。', 'danger')
    # 如果是 GET 请求或表单验证失败，则渲染表单页面
    return render_template('change_password.html', title='修改密码', form=form)

# --- 运行 Flask 应用 ---
if __name__ == '__main__':
    with app.app_context():
        db.create_all() # 确保所有表都已创建
    app.run(debug=True) # debug=True 会在代码更改时自动重启服务器，并提供更详细的错误信息 