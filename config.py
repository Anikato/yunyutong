import os
from dotenv import load_dotenv

basedir = os.path.abspath(os.path.dirname(__file__))
load_dotenv(os.path.join(basedir, '.env'))


class Config:
    """基础配置类"""
    # Flask 核心配置
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev-secret-key-replace-in-production'
    
    # 数据库配置
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or \
        'sqlite:///' + os.path.join(basedir, 'yunyutong.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # API Token 加密密钥
    ENCRYPTION_KEY = os.environ.get('ENCRYPTION_KEY')
    
    # 环境标识
    FLASK_ENV = os.environ.get('FLASK_ENV', 'production')
    FLASK_DEBUG = os.environ.get('FLASK_DEBUG', '0') == '1'
    
    @staticmethod
    def is_production():
        """判断是否为生产环境"""
        return os.environ.get('FLASK_ENV', 'production') == 'production'


class DevelopmentConfig(Config):
    """开发环境配置"""
    DEBUG = True
    FLASK_ENV = 'development'
    FLASK_DEBUG = True
    
    # 开发环境可以使用默认密钥
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev-secret-key-for-development-only'


class ProductionConfig(Config):
    """生产环境配置"""
    DEBUG = False
    FLASK_ENV = 'production'
    FLASK_DEBUG = False
    
    # 生产环境必须设置 SECRET_KEY
    @property
    def SECRET_KEY(self):
        key = os.environ.get('SECRET_KEY')
        if not key:
            raise ValueError("生产环境必须设置 SECRET_KEY 环境变量!")
        return key


class TestingConfig(Config):
    """测试环境配置"""
    TESTING = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'
    WTF_CSRF_ENABLED = False


# 配置映射
config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'testing': TestingConfig,
    'default': Config
}


def get_config():
    """根据环境变量获取对应的配置类"""
    env = os.environ.get('FLASK_ENV', 'production')
    return config.get(env, Config)
