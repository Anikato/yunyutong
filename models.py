# /Users/kevin/Data/YunYuTong/models.py
from datetime import datetime, timezone
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.fernet import Fernet
import os
from flask_sqlalchemy import SQLAlchemy # <-- 导入 SQLAlchemy
from flask_login import UserMixin # 导入 UserMixin

# 在这里定义 db 对象
db = SQLAlchemy()

# 考虑从环境变量加载加密密钥，如果未设置则生成一个（仅用于开发）
# 注意：在生产中，密钥必须稳定且安全存储，否则无法解密旧数据
ENCRYPTION_KEY_ENV = os.environ.get('ENCRYPTION_KEY')
if not ENCRYPTION_KEY_ENV:
    print("警告：未设置 ENCRYPTION_KEY 环境变量，将生成临时密钥。生产环境中请务必设置！")
    # 生成一个临时密钥，但这意着每次重启应用（如果没设置环境变量）加密的令牌都可能无法解密
    # 更好的做法是在 .env 文件中设置一个固定的 ENCRYPTION_KEY
    encryption_key = Fernet.generate_key()
else:
    encryption_key = ENCRYPTION_KEY_ENV.encode() # Fernet 需要 bytes

cipher_suite = Fernet(encryption_key)

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    tokens = db.relationship('ApiToken', backref='owner', lazy=True, cascade="all, delete-orphan") # 添加关系和级联删除

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f'<User {self.username}>'

class ApiToken(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    encrypted_token = db.Column(db.LargeBinary, nullable=False) # 存储加密后的 bytes
    status = db.Column(db.String(20), default='unknown', nullable=False) # e.g., unknown, valid, invalid
    remarks = db.Column(db.Text, nullable=True) # <-- 添加备注字段
    added_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    domains = db.relationship('Domain', backref='api_token', lazy=True, cascade="all, delete-orphan") # 添加关系和级联删除

    def set_token(self, token):
        self.encrypted_token = cipher_suite.encrypt(token.encode())

    def get_token(self):
        try:
            return cipher_suite.decrypt(self.encrypted_token).decode()
        except Exception as e:
            print(f"解密 Token 时出错 (ID: {self.id}): {e}")
            # 可以考虑在此处将 status 设置为 invalid
            return None

    def __repr__(self):
        return f'<ApiToken {self.name} (User ID: {self.user_id})>'

class Domain(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    zone_id = db.Column(db.String(100), unique=True, nullable=False) # Zone ID 在 Cloudflare 中是唯一的
    name = db.Column(db.String(255), nullable=False)
    status = db.Column(db.String(50), nullable=True) # e.g., active, pending
    fetched_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    api_token_id = db.Column(db.Integer, db.ForeignKey('api_token.id'), nullable=False)
    dns_records = db.relationship('DnsRecord', backref='domain', lazy=True, cascade="all, delete-orphan") # 添加关系和级联删除

    def __repr__(self):
        return f'<Domain {self.name} (Zone ID: {self.zone_id})>'

class DnsRecord(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    record_id = db.Column(db.String(100), unique=True, nullable=False) # Record ID 在 Cloudflare 中是唯一的
    type = db.Column(db.String(20), nullable=False)
    name = db.Column(db.String(255), nullable=False) # 通常是子域名或 '@'
    content = db.Column(db.String(1000), nullable=False)
    ttl = db.Column(db.Integer, nullable=True)
    proxied = db.Column(db.Boolean, default=False)
    domain_id = db.Column(db.Integer, db.ForeignKey('domain.id'), nullable=False)

    def __repr__(self):
        return f'<DnsRecord {self.type} {self.name} -> {self.content[:30]}>' 