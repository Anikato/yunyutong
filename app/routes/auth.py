import time
import random
import string

from flask import Blueprint, render_template, redirect, url_for, flash, request
from flask_login import login_user, logout_user, current_user, login_required
from werkzeug.security import generate_password_hash, check_password_hash
from app.extensions import db
from app.models import User
from app.forms import RegistrationForm, LoginForm, ChangePasswordForm

bp = Blueprint('auth', __name__)

# ─── 防爆破配置 ──────────────────────────────────────────────────────────────
CAPTCHA_AFTER  = 3      # 连续失败几次后弹出验证码
LOCKOUT_AFTER  = 10     # 连续失败几次后锁定 IP
LOCKOUT_SECS   = 900    # 锁定时长（秒）= 15 分钟
CAPTCHA_TTL    = 300    # 验证码有效期（秒）= 5 分钟

# 内存存储（重启后清零，满足轻量级需求）
_login_attempts: dict = {}   # ip -> {'count': int, 'locked_until': float}
_captcha_store:  dict = {}   # captcha_id -> {'answer': int, 'question': str, 'expires': float}


def _client_ip() -> str:
    """获取客户端真实 IP
    优先读 X-Real-IP（nginx 用 $remote_addr 填充，不可伪造）；
    直连时退回到 remote_addr。
    不使用 X-Forwarded-For 的第一个值，因为客户端可以伪造该字段绕过限速。
    """
    return (
        request.headers.get('X-Real-IP')
        or request.remote_addr
        or '0.0.0.0'
    )


def _attempt_info(ip: str) -> dict:
    """获取 IP 的登录失败信息，自动解锁到期的锁定"""
    now = time.time()
    info = _login_attempts.get(ip, {'count': 0, 'locked_until': 0.0})
    if info.get('locked_until', 0) and info['locked_until'] < now:
        info = {'count': 0, 'locked_until': 0.0}
        _login_attempts[ip] = info
    return info


def _new_captcha() -> tuple:
    """生成一道简单算术题，返回 (captcha_id, question_str)"""
    a = random.randint(2, 20)
    b = random.randint(1, a)
    op = random.choice(['+', '-'])
    answer  = a + b if op == '+' else a - b
    question = f"{a} {op} {b}"

    captcha_id = ''.join(random.choices(string.ascii_lowercase + string.digits, k=20))
    _captcha_store[captcha_id] = {
        'answer':   answer,
        'question': question,
        'expires':  time.time() + CAPTCHA_TTL,
    }

    # 顺手清理过期验证码，避免内存泄漏
    now = time.time()
    expired = [k for k, v in list(_captcha_store.items()) if v['expires'] < now]
    for k in expired:
        _captcha_store.pop(k, None)

    return captcha_id, question


def _verify_captcha(captcha_id: str, user_answer: str) -> bool:
    """验证用户输入的验证码，验证后立即销毁（一次性）"""
    entry = _captcha_store.get(captcha_id)
    if not entry:
        return False
    if entry['expires'] < time.time():
        _captcha_store.pop(captcha_id, None)
        return False
    try:
        ok = int(user_answer.strip()) == entry['answer']
    except (ValueError, AttributeError):
        ok = False
    if ok:
        _captcha_store.pop(captcha_id, None)   # 验证成功即销毁
    return ok


# ─────────────────────────────────────────────────────────────────────────────

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

    ip   = _client_ip()
    info = _attempt_info(ip)
    now  = time.time()

    # ── 被锁定 ──────────────────────────────────────────────
    if info.get('locked_until', 0) > now:
        remaining    = int(info['locked_until'] - now)
        mins, secs   = divmod(remaining, 60)
        lock_msg     = f"{mins} 分 {secs} 秒"
        return render_template('login.html', title='登录', form=LoginForm(),
                               locked=True, lock_remaining=lock_msg,
                               need_captcha=False, captcha_id='', captcha_question='',
                               fail_count=info.get('count', 0))

    fail_count   = info.get('count', 0)
    need_captcha = fail_count >= CAPTCHA_AFTER
    form         = LoginForm()

    if form.validate_on_submit():
        # ── 验证码校验 ──────────────────────────────────────
        if need_captcha:
            captcha_id  = request.form.get('captcha_id', '')
            user_answer = request.form.get('captcha_answer', '').strip()
            if not _verify_captcha(captcha_id, user_answer):
                flash('验证码错误，请重新计算后输入。', 'warning')
                new_id, new_q = _new_captcha()
                return render_template('login.html', title='登录', form=form,
                                       locked=False, need_captcha=True,
                                       captcha_id=new_id, captcha_question=new_q,
                                       fail_count=fail_count)

        # ── 用户名/密码校验 ─────────────────────────────────
        user = User.query.filter_by(username=form.username.data).first()
        if user and user.check_password(form.password.data):
            _login_attempts.pop(ip, None)
            login_user(user, remember=form.remember.data)
            next_page = request.args.get('next')
            flash('登录成功！', 'success')
            if next_page and not next_page.startswith('/'):
                next_page = None
            return redirect(next_page or url_for('main.index'))

        # ── 登录失败：增加计数 ──────────────────────────────
        fail_count += 1
        info['count'] = fail_count
        _login_attempts[ip] = info

        if fail_count >= LOCKOUT_AFTER:
            info['locked_until'] = now + LOCKOUT_SECS
            _login_attempts[ip]  = info
            mins = LOCKOUT_SECS // 60
            flash(f'连续失败 {fail_count} 次，IP 已被锁定 {mins} 分钟。', 'danger')
            return render_template('login.html', title='登录', form=form,
                                   locked=True, lock_remaining=f"{mins} 分 0 秒",
                                   need_captcha=False, captcha_id='', captcha_question='',
                                   fail_count=fail_count)

        # 失败提示
        if fail_count < CAPTCHA_AFTER:
            flash(f'用户名或密码错误（第 {fail_count} 次，{CAPTCHA_AFTER - fail_count} 次后需要验证码）。', 'danger')
        else:
            flash(f'用户名或密码错误（第 {fail_count} 次，{LOCKOUT_AFTER - fail_count} 次后将被锁定）。', 'danger')

    # ── 渲染页面 ─────────────────────────────────────────────
    # 每次（重新）渲染都刷新验证码，避免复用已用过的题目
    need_captcha = fail_count >= CAPTCHA_AFTER
    captcha_id, captcha_question = ('', '')
    if need_captcha:
        captcha_id, captcha_question = _new_captcha()

    return render_template('login.html', title='登录', form=form,
                           locked=False, need_captcha=need_captcha,
                           captcha_id=captcha_id, captcha_question=captcha_question,
                           fail_count=fail_count)


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
