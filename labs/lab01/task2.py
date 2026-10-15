# labs/lab01/task2.py
import os
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))
from shared.student import GROUP_NAME, STUDENT_NAME, VARIANT_NUMBER

users = {
    "iot_specialist": {"role": "iot_security", "clearance": 3, "department": "IoT", "active": True},
    "mobile_analyst": {"role": "mobile_security", "clearance": 3, "department": "Mobile", "active": True},
    "web_developer": {"role": "web_developer", "clearance": 2, "department": "Web", "active": True},
    "api_consumer": {"role": "api_user", "clearance": 2, "department": "Integration", "active": True},
    "demo_account": {"role": "demonstration", "clearance": 1, "department": "Demo", "active": False},
}

resources = [
    ("iot_firmware", 3),
    ("mobile_policies", 3),
    ("web_applications", 2),
    ("api_gateway", 2),
    ("device_certificates", 3),
    ("app_store", 1),
    ("vulnerability_database", 3),
    ("device_management", 3),
    ("integration_docs", 2),
    ("demo_content", 1),
]

security_levels = ("Consumer", "Business", "Enterprise", "Critical Systems")
blocked_users = {"demo_account", "compromised_device", "malicious_app"}


def run_task2():
    print(
        f"\n--- Завдання 2 | Студент: {STUDENT_NAME} ({GROUP_NAME}), Варіант: {VARIANT_NUMBER} ---"
    )

    print("\n[ 1. Список ресурсів системи ]")
    for res_name, level in resources:
        level_text = security_levels[level - 1]
        print(f"Ресурс: {res_name:<25} | Рівень: {level_text}")

    print("\n[ 2. Перевірка доступу ]")
    check_users_list = list(users.keys()) + ["compromised_device"]  #test forbidden user

    for user_id in check_users_list:
        for res_name, res_level in resources:
            if user_id not in users:
                status = "DENY (User not found)"
            elif user_id in blocked_users:
                status = "DENY (User is blocked)"
            elif not users[user_id]["active"]:
                status = "DENY (Account inactive)"
            elif users[user_id]["clearance"] >= res_level:
                status = "ALLOW"
            else:
                status = "DENY (Insufficient clearance)"

            print(f"user={user_id:<15} resource={res_name:<23} -> {status}")


if __name__ == "__main__":
    run_task2()