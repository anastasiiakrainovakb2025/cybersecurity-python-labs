import csv
import json
import logging
import re
from collections import Counter
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger(__name__)


@dataclass
class CertAuditResult:
    domain: str
    issuer: str
    days_left: int
    status: str
    signature_alg: str


def load_certificates(file_path: Path) -> list[dict]:
    with open(file_path, "r", encoding="utf-8") as f:
        return json.load(f)


def analyze_certificates(
    certs_data: list[dict], days_warning: int = 30
) -> tuple[list[CertAuditResult], Counter, int, int]:
    results = []
    issuer_counter = Counter()
    expired_count = 0
    warning_count = 0

    now = datetime.now(timezone.utc)

    for item in certs_data:
        domain = item.get("domain", item.get("Domain", "unknown"))
        issuer = item.get("issuer", item.get("Issuer", "Unknown"))
        valid_to_str = item.get("valid_to", item.get("ValidTo", ""))
        sig_alg = item.get("signature_algorithm", item.get("SignatureAlg", "Unknown"))

        try:
            valid_to_dt = datetime.fromisoformat(valid_to_str.replace("Z", "+00:00"))
            if valid_to_dt.tzinfo is None:
                valid_to_dt = valid_to_dt.replace(tzinfo=timezone.utc)
        except ValueError:
            valid_to_dt = now

        days_left = (valid_to_dt - now).days

        is_weak_alg = bool(re.search(r"sha1|md5", sig_alg, re.IGNORECASE))

        if days_left < 0:
            status = "EXPIRED"
            expired_count += 1
        elif days_left <= days_warning:
            status = "WARNING"
            warning_count += 1
        else:
            status = "OK"

        if is_weak_alg:
            sig_alg += " (WEAK)"

        issuer_counter[issuer] += 1
        results.append(
            CertAuditResult(
                domain=domain,
                issuer=issuer,
                days_left=days_left,
                status=status,
                signature_alg=sig_alg,
            )
        )

    return results, issuer_counter, expired_count, warning_count


def export_report(results: list[CertAuditResult], output_path: Path, fmt: str) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    if fmt.lower() == "csv":
        with open(output_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(
                f,
                fieldnames=["domain", "issuer", "days_left", "status", "signature_alg"],
            )
            writer.writeheader()
            for r in results:
                writer.writerow(asdict(r))
    else:
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump([asdict(r) for r in results], f, indent=4, ensure_ascii=False)


def run_analyzer(
    certs_data_path: str,
    days_warning: int = 30,
    output_report: str = "labs/lab02/data/ssl_expiry_report.csv",
    fmt: str = "csv",
) -> None:
    path = Path(certs_data_path)
    if not path.exists():
        logger.error(f"Файл даних сертифікатів не знайдено: {certs_data_path}")
        return

    logger.info(f"Loading SSL certificates data from {certs_data_path}...")
    certs_data = load_certificates(path)
    logger.info(f"Audited {len(certs_data)} domain certificates.\n")

    results, issuer_counter, expired_count, warning_count = analyze_certificates(
        certs_data, days_warning
    )

    print("=== Certificate Expiry & Safety Status ===")
    print(f"{'Domain':<22} {'Issuer':<15} {'Days Left':<10} {'Status':<10} {'Signature Alg'}")
    print("-" * 70)
    for r in results:
        days_str = f"{r.days_left} days"
        print(f"{r.domain:<22} {r.issuer:<15} {days_str:<10} {r.status:<10} {r.signature_alg}")

    print("\n=== Issuer Statistics ===")
    for issuer, count in issuer_counter.most_common():
        print(f"{issuer:<15} : {count}")
    print()

    if expired_count > 0 or warning_count > 0:
        logger.warning(
            f"{expired_count} certificate(s) EXPIRED! {warning_count} certificate(s) expiring within {days_warning} days!"
        )

    out_p = Path(output_report)
    export_report(results, out_p, fmt)
    logger.info(f"Report saved to {output_report}")