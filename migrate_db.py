#!/usr/bin/env python3
"""
数据库迁移脚本
用于将现有数据库升级到支持多 Provider 的新结构

使用方法:
    python migrate_db.py

此脚本会:
1. 备份现有数据库
2. 添加新的 provider_type 和 encrypted_credentials 字段
3. 迁移现有 Cloudflare Token 数据到新格式
"""

import os
import sys
import shutil
import sqlite3
from datetime import datetime

# 数据库路径
DB_PATH = os.path.join(os.path.dirname(__file__), 'yunyutong.db')
BACKUP_PATH = os.path.join(os.path.dirname(__file__), f'yunyutong_backup_{datetime.now().strftime("%Y%m%d_%H%M%S")}.db')


def backup_database():
    """备份数据库"""
    if os.path.exists(DB_PATH):
        shutil.copy2(DB_PATH, BACKUP_PATH)
        print(f"✅ 数据库已备份到: {BACKUP_PATH}")
        return True
    else:
        print("⚠️  数据库文件不存在，将创建新数据库")
        return False


def check_column_exists(cursor, table, column):
    """检查表中是否存在指定列"""
    cursor.execute(f"PRAGMA table_info({table})")
    columns = [row[1] for row in cursor.fetchall()]
    return column in columns


def migrate():
    """执行迁移"""
    print("=" * 50)
    print("云域通数据库迁移工具")
    print("=" * 50)
    
    # 备份
    backup_database()
    
    # 连接数据库
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    try:
        # 检查 api_token 表是否存在
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='api_token'")
        if not cursor.fetchone():
            print("⚠️  api_token 表不存在，请先运行应用以创建表结构")
            print("   运行: flask db upgrade 或 python run.py")
            return
        
        migrations_needed = []
        
        # 检查是否需要添加 provider_type 字段
        if not check_column_exists(cursor, 'api_token', 'provider_type'):
            migrations_needed.append('provider_type')
        
        # 检查是否需要添加 encrypted_credentials 字段
        if not check_column_exists(cursor, 'api_token', 'encrypted_credentials'):
            migrations_needed.append('encrypted_credentials')
        
        # 检查是否需要添加 dns_record.priority 字段
        if not check_column_exists(cursor, 'dns_record', 'priority'):
            migrations_needed.append('dns_record_priority')
        
        if not migrations_needed:
            print("✅ 数据库已是最新版本，无需迁移")
            return
        
        print(f"\n需要执行的迁移: {migrations_needed}")
        
        # 添加 provider_type 字段
        if 'provider_type' in migrations_needed:
            print("\n📦 添加 provider_type 字段...")
            cursor.execute("""
                ALTER TABLE api_token 
                ADD COLUMN provider_type VARCHAR(50) NOT NULL DEFAULT 'cloudflare'
            """)
            print("   ✅ provider_type 字段已添加")
        
        # 添加 encrypted_credentials 字段
        if 'encrypted_credentials' in migrations_needed:
            print("\n📦 添加 encrypted_credentials 字段...")
            cursor.execute("""
                ALTER TABLE api_token 
                ADD COLUMN encrypted_credentials BLOB
            """)
            print("   ✅ encrypted_credentials 字段已添加")
            
            # 迁移现有数据：将 encrypted_token 的值复制到 encrypted_credentials
            # 需要将单个 token 转换为 JSON 格式 {"api_token": "xxx"}
            print("\n📦 迁移现有 Token 数据...")
            
            # 注意：由于加密，我们不能在 SQL 中直接转换格式
            # 需要在应用启动时由 Python 代码处理
            # 这里我们只是确保字段存在，实际迁移由应用代码在首次访问时处理
            print("   ⚠️  现有 Token 将在首次访问时自动迁移")
        
        # 添加 dns_record.priority 字段
        if 'dns_record_priority' in migrations_needed:
            print("\n📦 添加 dns_record.priority 字段...")
            cursor.execute("""
                ALTER TABLE dns_record 
                ADD COLUMN priority INTEGER
            """)
            print("   ✅ dns_record.priority 字段已添加")
        
        # 提交更改
        conn.commit()
        print("\n" + "=" * 50)
        print("✅ 数据库迁移完成!")
        print("=" * 50)
        print("\n下一步:")
        print("1. 重新启动应用: python run.py")
        print("2. 现有的 Cloudflare Token 将自动兼容")
        print("3. 你现在可以添加阿里云等其他 DNS 服务商的凭证了")
        
    except Exception as e:
        conn.rollback()
        print(f"\n❌ 迁移失败: {e}")
        print(f"   数据库备份位于: {BACKUP_PATH}")
        print("   你可以恢复备份后重试")
        sys.exit(1)
    finally:
        conn.close()


if __name__ == '__main__':
    migrate()
