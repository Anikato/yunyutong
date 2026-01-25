# /Users/kevin/Data/Project/yunyutong/app/forms.py
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField, TextAreaField, SelectField, IntegerField
from wtforms.validators import DataRequired, Length, EqualTo, ValidationError, Optional, Regexp, NumberRange
from .models import User
import ipaddress
import re


class RegistrationForm(FlaskForm):
    username = StringField('用户名',
                           validators=[DataRequired(message="用户名不能为空"), Length(min=2, max=20, message="用户名长度需在 2 到 20 个字符之间")])
    password = PasswordField('密码', validators=[DataRequired(message="密码不能为空"), Length(min=6, message="密码长度至少需要 6 位")])
    confirm_password = PasswordField('确认密码',
                                     validators=[DataRequired(message="请再次输入密码"), EqualTo('password', message="两次输入的密码不匹配")])
    submit = SubmitField('注册')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('该用户名已被注册，请选用其他用户名。')


class LoginForm(FlaskForm):
    username = StringField('用户名', validators=[DataRequired(message="用户名不能为空")])
    password = PasswordField('密码', validators=[DataRequired(message="密码不能为空")])
    remember = BooleanField('记住我')
    submit = SubmitField('登录')


# Provider 选项 - 从 providers 模块导入
def get_provider_choices():
    from .providers import PROVIDER_CHOICES
    return PROVIDER_CHOICES


class ApiTokenForm(FlaskForm):
    """添加 API Token/凭证的表单"""
    name = StringField('名称',
                       validators=[DataRequired(message="请为这个凭证起一个名字，方便识别。"), Length(min=1, max=100)],
                       render_kw={"placeholder": "例如：我的阿里云账号"})
    
    provider_type = SelectField('DNS 服务商',
                                validators=[DataRequired(message="请选择 DNS 服务商")],
                                choices=[])  # 动态填充
    
    # Cloudflare 凭证字段
    api_token = TextAreaField('Cloudflare API Token',
                              validators=[Optional()],
                              render_kw={"rows": 3, "placeholder": "粘贴你的 Cloudflare API Token..."})
    
    # 阿里云凭证字段
    access_key_id = StringField('Access Key ID',
                                validators=[Optional()],
                                render_kw={"placeholder": "输入阿里云 AccessKey ID..."})
    access_key_secret = PasswordField('Access Key Secret',
                                      validators=[Optional()],
                                      render_kw={"placeholder": "输入阿里云 AccessKey Secret..."})
    
    remarks = TextAreaField('备注 (可选)', validators=[Optional()], render_kw={"rows": 2})
    submit = SubmitField('添加')
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.provider_type.choices = get_provider_choices()
    
    def validate(self, extra_validators=None):
        """自定义验证：根据 provider_type 验证必填字段"""
        initial_validation = super().validate(extra_validators=extra_validators)
        if not initial_validation:
            return False
        
        provider = self.provider_type.data
        is_valid = True
        
        if provider == 'cloudflare':
            if not self.api_token.data or not self.api_token.data.strip():
                self.api_token.errors.append("请输入 Cloudflare API Token")
                is_valid = False
        elif provider == 'aliyun':
            if not self.access_key_id.data or not self.access_key_id.data.strip():
                self.access_key_id.errors.append("请输入 Access Key ID")
                is_valid = False
            if not self.access_key_secret.data or not self.access_key_secret.data.strip():
                self.access_key_secret.errors.append("请输入 Access Key Secret")
                is_valid = False
        
        return is_valid
    
    def get_credentials(self) -> dict:
        """根据 provider_type 获取凭证字典"""
        provider = self.provider_type.data
        if provider == 'cloudflare':
            return {'api_token': self.api_token.data.strip()}
        elif provider == 'aliyun':
            return {
                'access_key_id': self.access_key_id.data.strip(),
                'access_key_secret': self.access_key_secret.data.strip()
            }
        return {}


class EditApiTokenForm(FlaskForm):
    """编辑 API Token/凭证的表单（只能编辑名称和备注）"""
    name = StringField('名称',
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


# 默认 DNS 记录类型（会被具体 Provider 覆盖）
RECORD_TYPES = [
    ('A', 'A (IPv4 Address)'),
    ('AAAA', 'AAAA (IPv6 Address)'),
    ('CNAME', 'CNAME (Canonical Name)'),
    ('TXT', 'TXT (Text Record)'),
    ('MX', 'MX (Mail Exchange)'),
    ('SRV', 'SRV (Service Record)'),
    ('NS', 'NS (Name Server)'),
]

# 默认 TTL 选项
TTL_CHOICES = [
    (1, 'Auto'),
    (60, '1 分钟'),
    (120, '2 分钟'),
    (300, '5 分钟'),
    (600, '10 分钟'),
    (900, '15 分钟'),
    (1800, '30 分钟'),
    (3600, '1 小时'),
    (7200, '2 小时'),
    (18000, '5 小时'),
    (43200, '12 小时'),
    (86400, '1 天'),
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
    
    def __init__(self, provider=None, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # 如果提供了 provider，使用其支持的记录类型和 TTL
        if provider:
            self.record_type.choices = provider.get_supported_record_types()
            self.ttl.choices = provider.get_ttl_choices()
            # 如果 provider 不支持代理，隐藏该字段
            self._supports_proxy = provider.supports_proxy()
        else:
            self._supports_proxy = True
    
    def supports_proxy(self):
        return getattr(self, '_supports_proxy', True)

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
