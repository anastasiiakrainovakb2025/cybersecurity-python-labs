import csv
import hashlib
import json
import os
from datetime import datetime, timezone

# for my settings
PERSONAL_SALT = "00010"
MIN_PASS_LEN = 11

DATA_DIR = os.path.join(os.path.dirname(__file__), "data")
CSV_PATH = os.path.join(DATA_DIR, "users.csv")
LOG_PATH = os.path.join(DATA_DIR, "log.json")


def generate_hash(password: str) -> str:
    if not password or not password.strip():
        raise ValueError("Пароль не може бути порожнім!")
    if len(password) < MIN_PASS_LEN:
        raise ValueError(f"Пароль закороткий (мінімум {MIN_PASS_LEN} символів)!")
    return hashlib.sha3_384((password + PERSONAL_SALT).encode()).hexdigest()


def log_event(func):
    def wrapper(username, password):
        result = func(username, password)
        status = "success" if result else "failure"

        log_username = username.strip() if (username and username.strip()) else "<EMPTY>"

        entry = {
            "event": "login",
            "user": log_username,
            "result": status,
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
        }

        logs = []
        if os.path.exists(LOG_PATH):
            try:
                with open(LOG_PATH, "r", encoding="utf-8") as f:
                    logs = json.load(f)
            except (FileNotFoundError, json.JSONDecodeError, OSError):
                logs = []

        logs.append(entry)
        os.makedirs(DATA_DIR, exist_ok=True)
        with open(LOG_PATH, "w", encoding="utf-8") as f:
            json.dump(logs, f, indent=4, ensure_ascii=False)

        return result

    return wrapper


users_to_register = [
    ("iot_specialist", "S0cial@Engineer1"),
    ("mobile_analyst", "Phish1ng@D3tect_Pass"),
    ("web_developer", "Ransomwar3@Protect_123"),
    ("api_consumer", "Bug@B0unty_2023"),
    ("test_user1", "ValidPass#2023"),
    ("jdjdjdjdjdjdjd",""), 
]


def create_users(users_list):
    os.makedirs(DATA_DIR, exist_ok=True)
    with open(CSV_PATH, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["username", "password_hash"])
        for user, password in users_list:
            u_show = user if (user and user.strip()) else "<EMPTY>"
            p_show = password if (password and password.strip()) else "<EMPTY>"

            if not user or not user.strip() or not password or not password.strip():
                print(f"[REGISTRATION ERROR]: Cannot register user='{u_show}', pass='{p_show}' -> Fields cannot be empty!")
                continue

            try:
                pass_hash = generate_hash(password)
                writer.writerow([user, pass_hash])
            except ValueError as e:
                print(f"[REGISTRATION ERROR]: Cannot register user='{u_show}': {e}")


@log_event
def login(username: str, password: str) -> bool:
    show_user = username.strip() if (username and username.strip()) else "<EMPTY>"
    show_pass = password.strip() if (password and password.strip()) else "<EMPTY>"

    print(f"\n[LOGIN INPUT]: Username = '{show_user}' | Password = '{show_pass}'")

    if not username or not username.strip():
        print("[ERROR]: Логін не може бути порожнім!")
        return False

    if not password or not password.strip():
        print("[ERROR]: Пароль не може бути порожнім!")
        return False

    if not os.path.exists(CSV_PATH):
        print("[ERROR]: База даних користувачів відсутня!")
        return False

    try:
        input_hash = generate_hash(password)
    except ValueError as e:
        print(f"[ERROR]: {e}")
        return False

    user_found = False

    with open(CSV_PATH, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            if row["username"] == username:
                user_found = True
                if row["password_hash"] == input_hash:
                    return True

    if not user_found:
        print("[ERROR]: Невірний логін (користувача не знайдено)!")
    else:
        print("[ERROR]: Невірний пароль!")

    return False


def run_task3():
    print("--- REGISTRATION PROCESS ---")
    create_users(users_to_register)

    # path CSV
    print(f"\n[OK] Database successfully created/updated at the path:\n  {CSV_PATH}\n")

    print("--- Contents of the structured CSV database ---")
    print(f"{'Username':<18} | SHA3-384 Hash")
    print("-" * 70)

    if os.path.exists(CSV_PATH):
        with open(CSV_PATH, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                print(f"{row['username']:<18} | {row['password_hash']}")

    print("\nAUTHENTICATION (LOGIN)")
    user_input = input("Enter username: ")
    pass_input = input("Enter password: ")

    if login(user_input, pass_input):
        print(f"[SUCCESS]: Login successful! Welcome, {user_input}.")
    else:
        print("[FAILURE]: Access denied.")


if __name__ == "__main__":
    run_task3()