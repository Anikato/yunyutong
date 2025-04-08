# /Users/kevin/Data/YunYuTong/forms.py
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField, TextAreaField, SelectField, IntegerField
from wtforms.validators import DataRequired, Length, EqualTo, ValidationError, Optional, Regexp, NumberRange
from models import User # 需要导入 User 模型来检查用户名是否已存在
import ipaddress # 用于验证 IP 地址
import re # 用于验证域名

class RegistrationForm(FlaskForm):
    username = StringField('用户名',
                           validators=[DataRequired(message="用户名不能为空"), Length(min=2, max=20, message="用户名长度需在 2 到 20 个字符之间")])
    password = PasswordField('密码', validators=[DataRequired(message="密码不能为空"), Length(min=6, message="密码长度至少需要 6 位")])
    confirm_password = PasswordField('确认密码',
                                     validators=[DataRequired(message="请再次输入密码"), EqualTo('password', message="两次输入的密码不匹配")])
    submit = SubmitField('注册')

    # 自定义验证器，检查用户名是否已被注册
    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('该用户名已被注册，请选用其他用户名。')

class LoginForm(FlaskForm):
    username = StringField('用户名', validators=[DataRequired(message="用户名不能为空")])
    password = PasswordField('密码', validators=[DataRequired(message="密码不能为空")])
    remember = BooleanField('记住我') # 记住登录状态选项
    submit = SubmitField('登录')

class ApiTokenForm(FlaskForm):
    name = StringField('Token 名称',
                       validators=[DataRequired(message="请为这个 Token 起一个名字，方便识别。"), Length(min=1, max=100)])
    token = TextAreaField('Cloudflare API Token',
                          validators=[DataRequired(message="请输入 Cloudflare API Token。")],
                          render_kw={"rows": 5, "placeholder": "粘贴你的 Cloudflare API Token 到这里..."})
    remarks = TextAreaField('备注 (可选)', validators=[Optional()], render_kw={"rows": 3})
    submit = SubmitField('添加 Token')

class EditApiTokenForm(FlaskForm):
    name = StringField('Token 名称',
                       validators=[DataRequired(message="名称不能为空。"), Length(min=1, max=100)])
    remarks = TextAreaField('备注 (可选)', validators=[Optional()], render_kw={"rows": 3})
    submit = SubmitField('保存更改')

class ChangePasswordForm(FlaskForm):
    current_password = PasswordField('当前密码', validators=[DataRequired(message="请输入您当前的密码。")])
    new_password = PasswordField('新密码', validators=[
        DataRequired(message="新密码不能为空。"),
        Length(min=6, message="新密码长度至少需要 6 位。")
    ])
    confirm_new_password = PasswordField('确认新密码', validators=[
        DataRequired(message="请再次输入新密码。"),
        EqualTo('new_password', message="两次输入的新密码不匹配。")
    ])
    submit = SubmitField('确认修改密码')

# Cloudflare 支持的常见 DNS 记录类型
RECORD_TYPES = [
    ('A', 'A (IPv4 Address)'),
    ('AAAA', 'AAAA (IPv6 Address)'),
    ('CNAME', 'CNAME (Canonical Name)'),
    ('TXT', 'TXT (Text Record)'),
    ('MX', 'MX (Mail Exchange)'),
    ('SRV', 'SRV (Service Record)'),
    ('NS', 'NS (Name Server)'),
]

# Cloudflare TTL 值 (1 表示 Auto)
TTL_CHOICES = [
    (1, 'Auto'),
    (60, '1 min'),
    (120, '2 mins'),
    (300, '5 mins'),
    (600, '10 mins'),
    (900, '15 mins'),
    (1800, '30 mins'),
    (3600, '1 hr'),
    (7200, '2 hrs'),
    (18000, '5 hrs'),
    (43200, '12 hrs'),
    (86400, '1 day'),
]

# 简单的域名验证正则表达式
DOMAIN_REGEX = re.compile(
    r'^((?!-)[A-Za-z0-9\-\u00a1-\uffff]{1,63}(?<!-)\.)+' # 子域名部分
    r'([A-Za-z\u00a1-\uffff]{2,63})$' # 顶级域名部分
)

class DnsRecordForm(FlaskForm):
    record_type = SelectField('记录类型', choices=RECORD_TYPES, validators=[DataRequired()])
    name = StringField('名称', validators=[DataRequired(message="名称不能为空"), Regexp(r'^([a-zA-Z0-9@_\-\.\*]+)$', message="名称包含无效字符")])
    content = TextAreaField('内容', validators=[DataRequired(message="内容不能为空")], render_kw={"rows": 3})
    ttl = SelectField('TTL', choices=TTL_CHOICES, coerce=int, default=1)
    proxied = BooleanField('代理状态 (Proxied)', default=False)
    priority = IntegerField('优先级 (MX/SRV)', validators=[Optional(), NumberRange(min=0, max=65535)])
    submit = SubmitField('添加记录')

    def validate(self, extra_validators=None):
        initial_validation = super(DnsRecordForm, self).validate(extra_validators=extra_validators)
        if not initial_validation:
            return False

        record_type = self.record_type.data
        content = self.content.data
        is_valid = True

        if record_type == 'A':
            try:
                ipaddress.IPv4Address(content)
            except ipaddress.AddressValueError:
                self.content.errors.append("内容必须是有效的 IPv4 地址。")
                is_valid = False
        elif record_type == 'AAAA':
            try:
                ipaddress.IPv6Address(content)
            except ipaddress.AddressValueError:
                self.content.errors.append("内容必须是有效的 IPv6 地址。")
                is_valid = False
        elif record_type == 'CNAME' or record_type == 'MX' or record_type == 'NS':
             if not DOMAIN_REGEX.match(content):
                 self.content.errors.append("内容必须是有效的主机名/域名。")
                 is_valid = False
        elif record_type == 'TXT':
             pass

        if record_type in ['MX', 'SRV']:
            if self.priority.data is None:
                self.priority.errors.append("MX 和 SRV 记录必须提供优先级。")
                is_valid = False

        return is_valid 