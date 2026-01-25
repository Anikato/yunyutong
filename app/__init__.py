from flask import Flask
from config import Config
from app.extensions import db, login_manager
from app.models import User
import logging
from logging.handlers import RotatingFileHandler
import os

def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)

    # 初始化扩展
    db.init_app(app)
    login_manager.init_app(app)

    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))

    # 注册蓝图
    from app.routes.auth import bp as auth_bp
    app.register_blueprint(auth_bp)

    from app.routes.main import bp as main_bp
    app.register_blueprint(main_bp)

    from app.routes.token import bp as token_bp
    app.register_blueprint(token_bp)
    
    from app.routes.dns import bp as dns_bp
    app.register_blueprint(dns_bp)
    
    from app.routes.api import bp as api_bp
    app.register_blueprint(api_bp)

    # 配置日志
    if not app.debug and not app.testing:
        if not os.path.exists('logs'):
            os.mkdir('logs')
        file_handler = RotatingFileHandler('logs/yunyutong.log', maxBytes=10240, backupCount=10)
        file_handler.setFormatter(logging.Formatter(
            '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'))
        file_handler.setLevel(logging.INFO)
        app.logger.addHandler(file_handler)

        app.logger.setLevel(logging.INFO)
        app.logger.info('YunYuTong startup')

    return app
