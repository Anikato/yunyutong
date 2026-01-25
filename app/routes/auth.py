from flask import Blueprint, render_template, redirect, url_for, flash, request
from flask_login import login_user, logout_user, current_user, login_required
from werkzeug.security import generate_password_hash, check_password_hash
from app.extensions import db
from app.models import User
from app.forms import RegistrationForm, LoginForm, ChangePasswordForm

bp = Blueprint('auth', __name__)

@bp.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('main.index'))
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(username=form.username.data)
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        flash(f'账户 {form.username.data} 创建成功！现在可以登录了。', 'success')
        return redirect(url_for('auth.login'))
    return render_template('register.html', title='注册', form=form)

@bp.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('main.index'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and user.check_password(form.password.data):
            login_user(user, remember=form.remember.data)
            next_page = request.args.get('next')
            flash('登录成功！', 'success')
            if next_page and not next_page.startswith('/'):
                 next_page = None
            return redirect(next_page) if next_page else redirect(url_for('main.index'))
        else:
            flash('登录失败，请检查用户名和密码。', 'danger')
    return render_template('login.html', title='登录', form=form)

@bp.route('/logout')
def logout():
    logout_user()
    flash('您已成功登出。', 'info')
    return redirect(url_for('auth.login'))

@bp.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    form = ChangePasswordForm()
    if form.validate_on_submit():
        if check_password_hash(current_user.password_hash, form.current_password.data):
            current_user.set_password(form.new_password.data)
            db.session.commit()
            flash('密码修改成功！', 'success')
            return redirect(url_for('main.index'))
        else:
            flash('当前密码不正确，请重试。', 'danger')
    return render_template('change_password.html', title='修改密码', form=form)
