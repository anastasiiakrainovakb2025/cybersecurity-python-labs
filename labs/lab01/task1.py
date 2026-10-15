# labs/lab01/task1.py
import os  #initialize path for files and folders
import random
import sys  #for control path lists

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))
from shared.student import GROUP_NAME, STUDENT_NAME, VARIANT_NUMBER

#path for student inf DRY 
passwords = [    #list    is easy changed 
    "S0cial@Engineer", "basic", "Phish1ng@D3tect", "client",
    "Ransomwar3@Protect", "general", "Zero@D4y", "generic",
    "Bug@B0unty", "standard123", "Nastya13455"
]
criteria = {       #dict cause every word need to have key, if it be list, it would be harder to read
    "min_length": 11,
    "require_digits": True,
    "require_upper": True,
    "require_special": True,
}
forbidden_passwords = {   #set cause is performed like O(1), not O(n) is slower
    "basic", "client", "general", "generic", "standard123", "guest"
}


def evaluate_password(pwd: str, all_passwords: list) -> str:  
    min_len = criteria["min_length"]    # new function for check password quality

    if pwd.lower() in forbidden_passwords or len(pwd) < min_len:
        return "Заборонений"

    has_digit = any(c.isdigit() for c in pwd)
    has_upper = any(c.isupper() for c in pwd)
    has_lower = any(c.islower() for c in pwd)
    has_special = any(not c.isalnum() for c in pwd)

    meets_all = (
        len(pwd) >= min_len
        and has_digit
        and has_upper
        and has_lower
        and has_special
    )

    if meets_all:
        is_unique = all_passwords.count(pwd) == 1
        if len(pwd) >= min_len + 4 and is_unique:
            return "Дуже сильний"
        return "Сильний"

    types_count = sum([has_digit, has_upper, has_lower, has_special])
    if types_count >= 2:
        return "Середній"

    return "Слабкий" 


def run_task1():    #general module for start task
    print(
        f"--- Завдання 1 | Студент: {STUDENT_NAME} ({GROUP_NAME}), Варіант: {VARIANT_NUMBER} ---"
    )

    work_passwords = passwords.copy()
    random_indices = [random.randint(0, len(passwords) - 1) for _ in range(3)]
    for idx in random_indices:        #for saw same passwords
        work_passwords.append(work_passwords[idx])

    print(f"\n{'№':<3} | {'Пароль':<20} | {'Категорія':<20}")  #for decorating
    print("-" * 48)
    for index, pwd in enumerate(work_passwords, 1):  
        category = evaluate_password(pwd, work_passwords)  
        print(f"{index:<3} | {pwd:<20} | {category:<20}")       


if __name__ == "__main__":
    run_task1()