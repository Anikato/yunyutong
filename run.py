#!/usr/bin/env python3
"""
云域通 (YunYuTong) 启动脚本

开发环境:
    python3 run.py
    
生产环境:
    gunicorn --workers 3 --bind unix:yunyutong.sock run:app
"""
import os
from app import create_app
from config import get_config

# 创建应用实例
app = create_app()

if __name__ == '__main__':
    # 获取配置
    config = get_config()
    is_dev = os.environ.get('FLASK_ENV', 'production') == 'development'
    
    # 开发服务器配置
    host = os.environ.get('FLASK_HOST', '127.0.0.1')
    port = int(os.environ.get('FLASK_PORT', 5000))
    
    print(f"""
╔═══════════════════════════════════════════════════════════╗
║                     云域通 (YunYuTong)                      ║
║                   DNS 多平台管理系统                        ║
╚═══════════════════════════════════════════════════════════╝

  环境: {'开发环境' if is_dev else '生产环境'}
  地址: http://{host}:{port}
  
  {'⚠️  开发服务器仅供测试，生产环境请使用 Gunicorn!' if is_dev else ''}
""")
    
    # 启动开发服务器
    app.run(
        host=host,
        port=port,
        debug=is_dev
    )
