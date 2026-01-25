import sys
from app import create_app, db
from app.models import User

app = create_app()

def list_users():
    with app.app_context():
        users = User.query.all()
        if not users:
            print("没有找到用户。")
            return
        print(f"{'ID':<5} {'用户名':<20} {'Hash Method'}")
        print("-" * 40)
        for user in users:
            hash_method = user.password_hash.split(':')[0] if user.password_hash else 'N/A'
            print(f"{user.id:<5} {user.username:<20} {hash_method}")

def reset_password(username, new_password):
    with app.app_context():
        user = User.query.filter_by(username=username).first()
        if not user:
            print(f"用户 {username} 不存在。")
            return
        
        print(f"正在重置用户 {username} 的密码...")
        user.set_password(new_password)
        db.session.commit()
        print(f"用户 {username} 的密码已成功重置为: {new_password}")
        print(f"新的 Hash 方法: {user.password_hash.split(':')[0]}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("用法:")
        print("  python manage_user.py list")
        print("  python manage_user.py reset <username> <new_password>")
        sys.exit(1)

    command = sys.argv[1]

    if command == "list":
        list_users()
    elif command == "reset":
        if len(sys.argv) != 4:
            print("用法: python manage_user.py reset <username> <new_password>")
            sys.exit(1)
        reset_password(sys.argv[2], sys.argv[3])
    else:
        print("未知命令。")
