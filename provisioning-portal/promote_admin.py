import os
from app import app, db, User

def promote_user(username):
    with app.app_context():
        user = User.query.filter_by(username=username).first()
        if user:
            user.is_admin = True
            db.session.commit()
            print(f"Usuario {username} ahora es ADMIN.")
        else:
            print(f"Usuario {username} no encontrado.")

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        promote_user(sys.argv[1])
    else:
        print("Uso: python promote_admin.py <username>")
