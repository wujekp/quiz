import json
import os
import getpass
from werkzeug.security import generate_password_hash

USERS_FILE = "users.json"


def load_users():
    if not os.path.exists(USERS_FILE):
        return []

    with open(USERS_FILE, "r", encoding="utf-8") as f:
        return json.load(f)


def save_users(users):
    with open(USERS_FILE, "w", encoding="utf-8") as f:
        json.dump(users, f, ensure_ascii=False, indent=4)


def main():
    users = load_users()

    login = input("Podaj login: ").strip()
    if not login:
        print("Login nie może być pusty.")
        return

    for user in users:
        if user["login"] == login:
            print("Taki użytkownik już istnieje.")
            return

    password = getpass.getpass("Podaj hasło: ")
    password2 = getpass.getpass("Powtórz hasło: ")

    if not password:
        print("Hasło nie może być puste.")
        return

    if password != password2:
        print("Hasła nie są takie same.")
        return

    users.append({
        "login": login,
        "password_hash": generate_password_hash(password)
    })

    save_users(users)
    print(f"Dodano użytkownika: {login}")


if __name__ == "__main__":
    main()