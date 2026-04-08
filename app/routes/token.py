import json
import os
import io
import base64
from datetime import datetime, timezone

from flask import Blueprint, render_template, redirect, url_for, flash, request, send_file
from flask_login import login_required, current_user
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet, InvalidToken

from app.extensions import db
from app.models import ApiToken
from app.forms import ApiTokenForm, EditApiTokenForm
from app.providers import get_provider, get_provider_name

bp = Blueprint('token', __name__)

EXPORT_FORMAT_VERSION = '1.0'


def _derive_export_key(password: str, salt: bytes) -> bytes:
    """从用户导出密码派生 Fernet 密钥（PBKDF2-SHA256, 600k 轮）"""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=600000,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode('utf-8')))


@bp.route('/add_token', methods=['GET', 'POST'])
@login_required
def add_token():
    form = ApiTokenForm()
    if form.validate_on_submit():
        new_token = ApiToken(
            name=form.name.data,
            provider_type=form.provider_type.data,
            remarks=form.remarks.data,
            owner=current_user
        )
        # 使用新的凭证存储方法
        credentials = form.get_credentials()
        new_token.set_credentials(credentials)
        
        db.session.add(new_token)
        db.session.commit()

        provider_name = get_provider_name(form.provider_type.data)
        flash(f'{provider_name} 凭证 "{form.name.data}" 添加成功！', 'success')
        return redirect(url_for('main.index'))

    return render_template('add_token.html', title='添加 DNS 服务商凭证', form=form)


@bp.route('/token/<int:token_id>/verify', methods=['POST'])
@login_required
def verify_token(token_id):
    token = ApiToken.query.filter_by(id=token_id, user_id=current_user.id).first_or_404()
    
    try:
        provider = token.get_provider()
        if not provider:
            flash('无法获取凭证信息，请检查应用的加密密钥配置。', 'danger')
            return redirect(url_for('main.index'))

        is_valid = provider.verify_credentials()

        if is_valid:
            token.status = 'valid'
            flash(f'凭证 "{token.name}" 验证成功！', 'success')
        else:
            token.status = 'invalid'
            flash(f'凭证 "{token.name}" 验证失败或无效。请检查凭证是否正确或拥有足够权限。', 'danger')

        db.session.commit()
    except Exception as e:
        flash(f'验证凭证时发生错误: {str(e)}', 'danger')
    
    return redirect(url_for('main.index'))


@bp.route('/token/<int:token_id>/delete', methods=['POST'])
@login_required
def delete_token(token_id):
    token = ApiToken.query.filter_by(id=token_id, user_id=current_user.id).first_or_404()
    try:
        token_name = token.name
        db.session.delete(token)
        db.session.commit()
        flash(f'凭证 "{token_name}" 及其关联的域名和记录已成功删除。', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'删除凭证时发生错误: {e}', 'danger')
    return redirect(url_for('main.index'))


@bp.route('/edit_token/<int:token_id>', methods=['GET', 'POST'])
@login_required
def edit_token(token_id):
    token_to_edit = ApiToken.query.get_or_404(token_id)
    if token_to_edit.user_id != current_user.id:
        flash('无权编辑此凭证。', 'danger')
        return redirect(url_for('main.index'))

    form = EditApiTokenForm(obj=token_to_edit)
    
    # 获取完整凭证信息
    credentials = token_to_edit.get_credentials()
    
    # 生成隐藏版本用于默认显示
    masked_credentials = {}
    for key, value in credentials.items():
        if value and len(str(value)) > 8:
            masked_credentials[key] = str(value)[:4] + '****' + str(value)[-4:]
        else:
            masked_credentials[key] = '****'

    if form.validate_on_submit():
        token_to_edit.name = form.name.data
        token_to_edit.remarks = form.remarks.data
        db.session.commit()
        flash('凭证信息已更新。', 'success')
        return redirect(url_for('main.index'))
    elif request.method == 'GET':
        form.name.data = token_to_edit.name
        form.remarks.data = token_to_edit.remarks

    return render_template('edit_token.html',
                           title='编辑凭证',
                           form=form,
                           token=token_to_edit,
                           masked_credentials=masked_credentials,
                           credentials=credentials)


# ─────────────────────────────────────────────
#  导出凭证
# ─────────────────────────────────────────────

@bp.route('/tokens/export', methods=['GET', 'POST'])
@login_required
def export_tokens():
    tokens = ApiToken.query.filter_by(user_id=current_user.id).all()
    token_count = len(tokens)

    if request.method == 'POST':
        password = request.form.get('export_password', '').strip()
        confirm  = request.form.get('confirm_password', '').strip()

        if len(password) < 8:
            flash('导出密码至少需要 8 位字符。', 'danger')
            return render_template('export_tokens.html', title='导出凭证', token_count=token_count)

        if password != confirm:
            flash('两次输入的密码不一致。', 'danger')
            return render_template('export_tokens.html', title='导出凭证', token_count=token_count)

        if not tokens:
            flash('没有可导出的凭证。', 'warning')
            return redirect(url_for('main.index'))

        export_data = {
            'version': EXPORT_FORMAT_VERSION,
            'app': 'yunyutong',
            'exported_at': datetime.now(timezone.utc).isoformat(),
            'exported_by': current_user.username,
            'tokens': []
        }

        for t in tokens:
            credentials = t.get_credentials()
            if not credentials:
                continue

            # 每个 token 独立 salt，用导出密码二次加密
            salt = os.urandom(16)
            key  = _derive_export_key(password, salt)
            fernet = Fernet(key)
            encrypted = fernet.encrypt(json.dumps(credentials, ensure_ascii=False).encode('utf-8'))
            # 存储格式：urlsafe_b64(salt) + "." + fernet_token
            credentials_encrypted = base64.urlsafe_b64encode(salt).decode() + '.' + encrypted.decode()

            export_data['tokens'].append({
                'name': t.name,
                'provider_type': t.provider_type,
                'remarks': t.remarks or '',
                'sort_order': t.sort_order,
                'credentials_encrypted': credentials_encrypted
            })

        filename = f'yunyutong_tokens_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json'
        json_bytes = json.dumps(export_data, ensure_ascii=False, indent=2).encode('utf-8')
        return send_file(
            io.BytesIO(json_bytes),
            mimetype='application/json',
            as_attachment=True,
            download_name=filename
        )

    return render_template('export_tokens.html', title='导出凭证', token_count=token_count)


# ─────────────────────────────────────────────
#  导入凭证
# ─────────────────────────────────────────────

@bp.route('/tokens/import', methods=['GET', 'POST'])
@login_required
def import_tokens():
    if request.method == 'POST':
        password = request.form.get('import_password', '').strip()
        file = request.files.get('import_file')

        if not file or not file.filename:
            flash('请选择导入文件。', 'danger')
            return render_template('import_tokens.html', title='导入凭证')

        if not file.filename.lower().endswith('.json'):
            flash('请上传 .json 格式的导出文件。', 'danger')
            return render_template('import_tokens.html', title='导入凭证')

        try:
            data = json.loads(file.read().decode('utf-8'))
        except Exception:
            flash('文件格式错误，无法解析 JSON。', 'danger')
            return render_template('import_tokens.html', title='导入凭证')

        if data.get('app') != 'yunyutong' or 'tokens' not in data:
            flash('文件不是有效的云域通导出文件。', 'danger')
            return render_template('import_tokens.html', title='导入凭证')

        success_count = 0
        skip_count = 0
        error_msgs = []

        for item in data.get('tokens', []):
            item_name = item.get('name', '未知')
            try:
                raw = item.get('credentials_encrypted', '')
                salt_b64, fernet_token = raw.split('.', 1)
                salt = base64.urlsafe_b64decode(salt_b64 + '==')  # 补齐 padding
                key  = _derive_export_key(password, salt)
                fernet = Fernet(key)
                credentials = json.loads(fernet.decrypt(fernet_token.encode()).decode('utf-8'))
            except InvalidToken:
                error_msgs.append(f'「{item_name}」密码错误，已跳过')
                skip_count += 1
                continue
            except Exception as e:
                error_msgs.append(f'「{item_name}」解密失败（{e}），已跳过')
                skip_count += 1
                continue

            # 重名处理：自动追加后缀
            name = item_name
            if ApiToken.query.filter_by(user_id=current_user.id, name=name).first():
                name = f'{name} (imported)'

            new_token = ApiToken(
                name=name,
                provider_type=item.get('provider_type', 'cloudflare'),
                remarks=item.get('remarks', ''),
                sort_order=item.get('sort_order', 0),
                owner=current_user
            )
            new_token.set_credentials(credentials)
            db.session.add(new_token)
            success_count += 1

        try:
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            flash(f'保存时出错：{e}', 'danger')
            return render_template('import_tokens.html', title='导入凭证')

        msg = f'导入完成：成功 {success_count} 个'
        if skip_count:
            msg += f'，跳过 {skip_count} 个'
        flash(msg, 'success' if success_count > 0 else 'warning')
        for err in error_msgs:
            flash(err, 'warning')

        return redirect(url_for('main.index'))

    return render_template('import_tokens.html', title='导入凭证')
