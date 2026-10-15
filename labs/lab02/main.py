import argparse
import logging

from labs.lab02.task1 import Admin, UserAccount
from labs.lab02.task2 import run_analyzer

logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")


def demo_task1():
    print("=== ДЕМОНСТРАЦІЯ ЗАВДАННЯ 1 (ООП) ===")
    admin_user = Admin("admin_user", "admin@corp.com", permissions={"read", "write"})
    admin_user.set_password("SecurePass123!")
    account = UserAccount(user=admin_user)

    print(f"Створено об'єкт: {account['user']}")

    print("\n1. Спроба входу з неправильним паролем:")
    account.login("admin_user", "WrongPass", "192.168.1.10")
    print(f"Статус авторизації: {account.is_authenticated()}")

    print("\n2. Спроба входу з правильним паролем:")
    account.login("admin_user", "SecurePass123!", "192.168.1.10")
    print(f"Статус авторизації: {account.is_authenticated()}")

    print("\n3. Тест валідації email (@property):")
    try:
        account["user"].email = "invalid_email_str"
    except ValueError as e:
        print(f"Отримано очікувану помилку: {e}")

    print("\n4. Історія AuditLog:")
    for log in account["audit_log"].show_all():
        print(f"[{log.timestamp.strftime('%H:%M:%S')}] {log.username}: {log.action}")

    account.logout()
    print("\n5. Після виходу (logout):")
    print(f"Статус авторизації: {account.is_authenticated()}")


def main():
    parser = argparse.ArgumentParser(
        description="Lab 02 CLI Toolkit - Variant 10 (SSL/TLS Expiry Monitor)"
    )
    subparsers = parser.add_subparsers(dest="command")

    subparsers.add_parser("demo", help="Демонстрація Завдання 1 (ООП)")

    analyze_parser = subparsers.add_parser("analyze", help="Аналіз SSL-сертифікатів (Завдання 2)")
    analyze_parser.add_argument(
        "--certs-data",
        type=str,
        default="labs/lab02/data/data_v10/certificates.json",
        help="Шлях до файлу certificates.json",
    )
    analyze_parser.add_argument(
        "--days-warning",
        type=int,
        default=30,
        help="Поріг днів для тривоги (дефолт: 30)",
    )
    analyze_parser.add_argument(
        "--output-report",
        type=str,
        default="labs/lab02/data/ssl_expiry_report.csv",
        help="Шлях для вихідного звіту",
    )
    analyze_parser.add_argument(
        "--format",
        type=str,
        choices=["csv", "json"],
        default="csv",
        help="Формат звіту (csv або json)",
    )

    args = parser.parse_args()

    if args.command == "demo":
        demo_task1()
    elif args.command == "analyze":
        run_analyzer(
            certs_data_path=args.certs_data,
            days_warning=args.days_warning,
            output_report=args.output_report,
            fmt=args.format,
        )
    else:
        parser.print_help()


if __name__ == "__main__":
    main()