import sqlite3
import bcrypt
import re

def validate_email(email):
    pattern = r'^[\w\.-]+@[\w\.-]+\.\w+$'
    return re.match(pattern, email) is not None

def main():
    print("=== Add New User API Tool ===")
    username = input("Enter username: ").strip()
    if not username:
        print("Error: Username cannot be empty.")
        return

    email = input("Enter email: ").strip()
    if not email or not validate_email(email):
        print("Error: Invalid email format.")
        return

    password = input("Enter password: ").strip()
    if not password:
        print("Error: Password cannot be empty.")
        return

    role = input("Enter role (admin/user) [default: user]: ").strip().lower()
    if role not in ['admin', 'user']:
        role = 'user'

    try:
        conn = sqlite3.connect('backend/secureauth.db')
        cursor = conn.cursor()

        # Check if user already exists
        cursor.execute("SELECT id FROM users WHERE username = ? OR email = ?", (username, email))
        if cursor.fetchone():
            print("Error: User with this username or email already exists.")
            return

        print("\nHashing password...")
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt(12)).decode('utf-8')

        print("Adding user to database...")
        cursor.execute(
            "INSERT INTO users (username, email, password_hash, role) VALUES (?, ?, ?, ?)",
            (username, email, hashed_password, role)
        )
        conn.commit()

        print(f"\nSuccess! User '{username}' has been successfully added with role '{role}'.")
        print("You can now login with these credentials.")

    except sqlite3.Error as e:
        print(f"Database error occurred: {e}")
    finally:
        if 'conn' in locals():
            conn.close()

if __name__ == "__main__":
    main()
