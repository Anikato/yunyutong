from flask import Blueprint, render_template, redirect, url_for, flash, request
from flask_login import login_required, current_user
from app.extensions import db
from app.models import ApiToken
from app.forms import ApiTokenForm, EditApiTokenForm
from app.providers import get_provider, get_provider_name

bp = Blueprint('token', __name__)


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
    
    # 获取凭证信息用于显示（部分隐藏）
    credentials = token_to_edit.get_credentials()
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
                           masked_credentials=masked_credentials)
