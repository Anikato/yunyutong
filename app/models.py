# /Users/kevin/Data/Project/yunyutong/app/models.py
from datetime import datetime, timezone
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.fernet import Fernet
import os
import sys
import json
from flask_login import UserMixin
from .extensions import db

# 密钥管理逻辑：生产环境强制要求设置 ENCRYPTION_KEY
ENCRYPTION_KEY_ENV = os.environ.get('ENCRYPTION_KEY')
FLASK_ENV = os.environ.get('FLASK_ENV', 'production')
FLASK_DEBUG = os.environ.get('FLASK_DEBUG', '0')

if not ENCRYPTION_KEY_ENV:
    # 只有在明确是开发环境时，才允许使用临时密钥
    if FLASK_ENV == 'development' or FLASK_DEBUG == '1':
        print("\033[93m[警告] 未设置 ENCRYPTION_KEY 环境变量。")
        print("正在使用临时生成的密钥。重启应用后，之前保存的 Token 将无法解密！\033[0m")
        encryption_key = Fernet.generate_key()
    else:
        print("\033[91m[严重错误] 生产环境下必须设置 ENCRYPTION_KEY 环境变量！\033[0m")
        print("请在 .env 文件或系统环境变量中设置 ENCRYPTION_KEY。")
        print("你可以运行以下命令生成一个新的密钥：")
        print("\033[92mpython3 -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())'\033[0m")
        sys.exit(1) # 阻止应用启动
else:
    try:
        encryption_key = ENCRYPTION_KEY_ENV.encode() # Fernet 需要 bytes
        # 尝试验证密钥格式是否正确
        Fernet(encryption_key)
    except Exception as e:
        print(f"\033[91m[严重错误] 提供的 ENCRYPTION_KEY 无效: {e}\033[0m")
        sys.exit(1)

cipher_suite = Fernet(encryption_key)


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    tokens = db.relationship('ApiToken', backref='owner', lazy=True, cascade="all, delete-orphan")

    def set_password(self, password):
        # 强制使用 pbkdf2:sha256，因为当前环境的 hashlib 可能不支持 scrypt
        self.password_hash = generate_password_hash(password, method='pbkdf2:sha256')

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f'<User {self.username}>'


class ApiToken(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    
    # Provider 类型 (cloudflare, aliyun 等)
    provider_type = db.Column(db.String(50), nullable=False, default='cloudflare')
    
    # 加密存储的凭证 (JSON 格式，支持不同 provider 的不同凭证结构)
    encrypted_credentials = db.Column(db.LargeBinary, nullable=False)
    
    # 兼容旧字段 - 保留用于数据迁移
    encrypted_token = db.Column(db.LargeBinary, nullable=True)
    
    status = db.Column(db.String(20), default='unknown', nullable=False)
    remarks = db.Column(db.Text, nullable=True)
    added_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    domains = db.relationship('Domain', backref='api_token', lazy=True, cascade="all, delete-orphan")

    def set_credentials(self, credentials: dict):
        """
        设置凭证（加密存储）
        
        Args:
            credentials: 凭证字典，根据 provider_type 不同有不同结构
                - Cloudflare: {'api_token': 'xxx'}
                - 阿里云: {'access_key_id': 'xxx', 'access_key_secret': 'xxx'}
        """
        credentials_json = json.dumps(credentials, ensure_ascii=False)
        self.encrypted_credentials = cipher_suite.encrypt(credentials_json.encode('utf-8'))
    
    def get_credentials(self) -> dict:
        """
        获取解密后的凭证
        
        Returns:
            凭证字典，失败时返回空字典
        """
        try:
            # 优先使用新的 encrypted_credentials 字段
            if self.encrypted_credentials:
                decrypted = cipher_suite.decrypt(self.encrypted_credentials).decode('utf-8')
                return json.loads(decrypted)
            
            # 兼容旧的 encrypted_token 字段 (Cloudflare)
            if self.encrypted_token:
                token = cipher_suite.decrypt(self.encrypted_token).decode()
                return {'api_token': token}
            
            return {}
        except Exception as e:
            print(f"解密凭证时出错 (ID: {self.id}): {e}")
            return {}
    
    # 保留旧方法以兼容现有代码
    def set_token(self, token):
        """兼容旧代码：设置 Cloudflare API Token"""
        self.set_credentials({'api_token': token})
        # 同时设置旧字段以保持兼容
        self.encrypted_token = cipher_suite.encrypt(token.encode())

    def get_token(self):
        """兼容旧代码：获取 Cloudflare API Token"""
        credentials = self.get_credentials()
        return credentials.get('api_token')
    
    def get_provider(self):
        """
        获取此 Token 对应的 DNS Provider 实例
        
        Returns:
            DNSProvider 子类实例
        """
        from .providers import get_provider
        credentials = self.get_credentials()
        if not credentials:
            return None
        return get_provider(self.provider_type, credentials)
    
    def get_provider_display_name(self) -> str:
        """获取 Provider 显示名称"""
        from .providers import get_provider_name
        return get_provider_name(self.provider_type)

    def __repr__(self):
        return f'<ApiToken {self.name} ({self.provider_type}) User ID: {self.user_id}>'


class Domain(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    zone_id = db.Column(db.String(100), unique=True, nullable=False)
    name = db.Column(db.String(255), nullable=False)
    status = db.Column(db.String(50), nullable=True)
    fetched_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    api_token_id = db.Column(db.Integer, db.ForeignKey('api_token.id'), nullable=False)
    dns_records = db.relationship('DnsRecord', backref='domain', lazy=True, cascade="all, delete-orphan")

    def __repr__(self):
        return f'<Domain {self.name} (Zone ID: {self.zone_id})>'


class DnsRecord(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    record_id = db.Column(db.String(100), unique=True, nullable=False)
    type = db.Column(db.String(20), nullable=False)
    name = db.Column(db.String(255), nullable=False)
    content = db.Column(db.String(1000), nullable=False)
    ttl = db.Column(db.Integer, nullable=True)
    proxied = db.Column(db.Boolean, default=False)
    priority = db.Column(db.Integer, nullable=True)  # MX/SRV 记录优先级
    domain_id = db.Column(db.Integer, db.ForeignKey('domain.id'), nullable=False)

    def __repr__(self):
        return f'<DnsRecord {self.type} {self.name} -> {self.content[:30]}>'
