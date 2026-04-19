"""
╔══════════════════════════════════════════════════════════════════════╗
║           ANTIGRAVITY EMAIL VALIDATOR v1.0                         ║
║           Infrastructure Layer — Lead Hygiene Engine               ║
║                                                                    ║
║  3-Layer Validation Pipeline:                                      ║
║    Layer 1 → Syntax (RFC-compliant Regex)                          ║
║    Layer 2 → DNS/MX Record Verification (dnspython)                ║
║    Layer 3 → Disposable/Temporary Domain Blacklist                 ║
║                                                                    ║
║  Security: Zero SMTP connections. DNS queries only.                ║
╚══════════════════════════════════════════════════════════════════════╝
"""

import os
import re
import sys
import time
import pandas as pd
import dns.resolver

# ─────────────────────────────────────────────────────────────────────
# CONFIGURATION
# ─────────────────────────────────────────────────────────────────────

DNS_TIMEOUT = 5          # seconds per MX lookup
DNS_LIFETIME = 10        # total resolution lifetime
OUTPUT_FILENAME = "Leads_Validados.csv"

# RFC 5322 compliant email regex (covers 99.9% of real-world addresses)
EMAIL_REGEX = re.compile(
    r"^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+"
    r"@"
    r"[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?"
    r"(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*"
    r"\.[a-zA-Z]{2,}$"
)

# ─────────────────────────────────────────────────────────────────────
# LAYER 3 — DISPOSABLE / TEMPORARY DOMAIN BLACKLIST
# ─────────────────────────────────────────────────────────────────────

DISPOSABLE_DOMAINS = {
    # Major disposable email services
    "mailinator.com",
    "guerrillamail.com",
    "guerrillamail.net",
    "guerrillamail.org",
    "guerrillamailblock.com",
    "tempmail.com",
    "temp-mail.org",
    "temp-mail.io",
    "throwaway.email",
    "throwaway.com",
    "yopmail.com",
    "yopmail.fr",
    "sharklasers.com",
    "guerrillamail.info",
    "grr.la",
    "dispostable.com",
    "trashmail.com",
    "trashmail.me",
    "trashmail.net",
    "fakeinbox.com",
    "mailnesia.com",
    "maildrop.cc",
    "discard.email",
    "discardmail.com",
    "discardmail.de",
    "10minutemail.com",
    "10minute.email",
    "minutemail.com",
    "tempail.com",
    "tempr.email",
    "tempmailaddress.com",
    "burnermail.io",
    "mailcatch.com",
    "inboxbear.com",
    "spamgourmet.com",
    "mytemp.email",
    "mohmal.com",
    "emailondeck.com",
    "getnada.com",
    "nada.email",
    "tmpmail.net",
    "tmpmail.org",
    "binkmail.com",
    "bobmail.info",
    "chammy.info",
    "devnullmail.com",
    "letthemeatspam.com",
    "mailexpire.com",
    "mailforspam.com",
    "safetymail.info",
    "spam4.me",
    "spamfree24.org",
    "trashymail.com",
    "wegwerfmail.de",
    "wegwerfmail.net",
    "wh4f.org",
    "meltmail.com",
    "harakirimail.com",
    "mailnull.com",
    "jetable.org",
    "trash-mail.com",
    "getairmail.com",
    "filzmail.com",
    "crazymailing.com",
    "tmail.ws",
    "mailsac.com",
    "luxusjacht.de",
}


# ─────────────────────────────────────────────────────────────────────
# CORE VALIDATION ENGINE
# ─────────────────────────────────────────────────────────────────────

class EmailValidator:
    """Three-layer email validation pipeline. Zero SMTP connections."""

    def __init__(self):
        self.mx_cache: dict[str, bool] = {}
        self.stats = {
            "total": 0,
            "valid": 0,
            "invalid_syntax": 0,
            "invalid_dns": 0,
            "invalid_disposable": 0,
            "dns_errors": 0,
        }

    # ── Layer 1: Syntax ──────────────────────────────────────────────

    @staticmethod
    def _validate_syntax(email: str) -> bool:
        """RFC 5322 regex validation."""
        if not isinstance(email, str):
            return False
        return bool(EMAIL_REGEX.match(email.strip().lower()))

    # ── Layer 2: DNS / MX ────────────────────────────────────────────

    def _validate_mx(self, domain: str) -> bool:
        """
        Query DNS for MX records. Results are cached per domain
        to avoid redundant lookups across duplicate domains.
        """
        if domain in self.mx_cache:
            return self.mx_cache[domain]

        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = DNS_TIMEOUT
            resolver.lifetime = DNS_LIFETIME
            answers = resolver.resolve(domain, "MX")
            has_mx = len(answers) > 0
            self.mx_cache[domain] = has_mx
            return has_mx

        except dns.resolver.NXDOMAIN:
            # Domain does not exist at all
            self.mx_cache[domain] = False
            return False

        except dns.resolver.NoAnswer:
            # Domain exists but has no MX records
            self.mx_cache[domain] = False
            return False

        except dns.resolver.NoNameservers:
            # No nameservers available for domain
            self.mx_cache[domain] = False
            return False

        except dns.resolver.LifetimeTimeout:
            # DNS query timed out
            self.stats["dns_errors"] += 1
            self.mx_cache[domain] = False
            return False

        except Exception:
            # Catch-all for unexpected DNS errors
            self.stats["dns_errors"] += 1
            self.mx_cache[domain] = False
            return False

    # ── Layer 3: Disposable Check ────────────────────────────────────

    @staticmethod
    def _is_disposable(domain: str) -> bool:
        """Check domain against internal disposable blacklist."""
        return domain in DISPOSABLE_DOMAINS

    # ── Pipeline Orchestrator ────────────────────────────────────────

    def validate(self, email: str) -> str:
        """
        Run email through all 3 validation layers.
        Returns 'Valid' or 'Invalid'.
        """
        self.stats["total"] += 1

        # Normalize
        if not isinstance(email, str) or not email.strip():
            self.stats["invalid_syntax"] += 1
            return "Invalid"

        email_clean = email.strip().lower()

        # Layer 1 — Syntax
        if not self._validate_syntax(email_clean):
            self.stats["invalid_syntax"] += 1
            return "Invalid"

        # Extract domain
        domain = email_clean.split("@")[1]

        # Layer 3 — Disposable (check before DNS to save time)
        if self._is_disposable(domain):
            self.stats["invalid_disposable"] += 1
            return "Invalid"

        # Layer 2 — DNS/MX
        if not self._validate_mx(domain):
            self.stats["invalid_dns"] += 1
            return "Invalid"

        self.stats["valid"] += 1
        return "Valid"

    def get_stats_report(self) -> str:
        """Return formatted statistics report."""
        s = self.stats
        valid_pct = (s["valid"] / s["total"] * 100) if s["total"] > 0 else 0
        return (
            "\n"
            "╔══════════════════════════════════════════════════════════╗\n"
            "║              VALIDATION REPORT                         ║\n"
            "╠══════════════════════════════════════════════════════════╣\n"
            f"║  Total Processed     : {s['total']:>8}                        ║\n"
            f"║  ✅ Valid             : {s['valid']:>8}  ({valid_pct:.1f}%)               ║\n"
            f"║  ❌ Invalid (Syntax)  : {s['invalid_syntax']:>8}                        ║\n"
            f"║  ❌ Invalid (DNS/MX)  : {s['invalid_dns']:>8}                        ║\n"
            f"║  ❌ Invalid (Dispos.) : {s['invalid_disposable']:>8}                        ║\n"
            f"║  ⚠️  DNS Errors       : {s['dns_errors']:>8}                        ║\n"
            "╚══════════════════════════════════════════════════════════╝\n"
        )


# ─────────────────────────────────────────────────────────────────────
# TERMINAL UI — INTERACTIVE CSV SELECTOR
# ─────────────────────────────────────────────────────────────────────

def _print_banner():
    """Display startup banner."""
    print(
        "\n"
        "╔══════════════════════════════════════════════════════════╗\n"
        "║       ⚡ ANTIGRAVITY EMAIL VALIDATOR v1.0 ⚡            ║\n"
        "║       Infrastructure Layer — Lead Hygiene Engine        ║\n"
        "╠══════════════════════════════════════════════════════════╣\n"
        "║  Layers: Syntax → DNS/MX → Disposable Filter           ║\n"
        "║  Policy: Zero SMTP — DNS queries only                   ║\n"
        "╚══════════════════════════════════════════════════════════╝\n"
    )


def _discover_csv_files() -> list[str]:
    """Scan current working directory for CSV files."""
    cwd = os.getcwd()
    csv_files = sorted(
        [f for f in os.listdir(cwd) if f.lower().endswith(".csv")],
        key=str.lower,
    )
    return csv_files


def _select_csv() -> str:
    """Interactive menu for CSV file selection."""
    csv_files = _discover_csv_files()

    if not csv_files:
        print("  ❌ No CSV files found in the current directory.")
        print(f"     Directory: {os.getcwd()}")
        print("     Please place your CSV files here and try again.\n")
        sys.exit(1)

    print("  📂 CSV files detected in current directory:\n")
    for idx, filename in enumerate(csv_files, start=1):
        size_kb = os.path.getsize(filename) / 1024
        print(f"     [{idx}] {filename}  ({size_kb:.1f} KB)")

    print()
    while True:
        try:
            choice = input("  ➜  Select file number: ").strip()
            index = int(choice) - 1
            if 0 <= index < len(csv_files):
                selected = csv_files[index]
                print(f"\n  ✅ Selected: {selected}\n")
                return selected
            else:
                print(f"     ⚠️  Enter a number between 1 and {len(csv_files)}.")
        except ValueError:
            print("     ⚠️  Please enter a valid number.")
        except KeyboardInterrupt:
            print("\n\n  ❌ Operation cancelled by user.\n")
            sys.exit(0)


def _detect_email_column(df: pd.DataFrame) -> str:
    """
    Detect the email column. Supports 'EMAIL' and 'CORREO'
    (case-insensitive).
    """
    columns_upper = {col.upper().strip(): col for col in df.columns}

    for candidate in ["EMAIL", "CORREO"]:
        if candidate in columns_upper:
            return columns_upper[candidate]

    # If not found, display available columns
    print("  ❌ Could not find 'EMAIL' or 'CORREO' column.")
    print(f"     Available columns: {list(df.columns)}\n")
    sys.exit(1)


# ─────────────────────────────────────────────────────────────────────
# MAIN EXECUTION
# ─────────────────────────────────────────────────────────────────────

def main():
    _print_banner()

    # Step 1 — Select CSV
    csv_file = _select_csv()

    # Step 2 — Load DataFrame
    print("  ⏳ Loading CSV...")
    try:
        # Try common separators
        try:
            df = pd.read_csv(csv_file, sep=",", dtype=str, encoding="utf-8", on_bad_lines='skip', engine='python')
            if len(df.columns) <= 1:
                df = pd.read_csv(csv_file, sep=";", dtype=str, encoding="utf-8", on_bad_lines='skip', engine='python')
        except UnicodeDecodeError:
            df = pd.read_csv(csv_file, sep=",", dtype=str, encoding="latin-1", on_bad_lines='skip', engine='python')
            if len(df.columns) <= 1:
                df = pd.read_csv(csv_file, sep=";", dtype=str, encoding="latin-1", on_bad_lines='skip', engine='python')
    except Exception as e:
        print(f"  ❌ Failed to read CSV: {e}\n")
        sys.exit(1)

    print(f"     Rows loaded: {len(df):,}")
    print(f"     Columns: {list(df.columns)}\n")

    # Step 3 — Detect email column
    email_col = _detect_email_column(df)
    print(f"  📧 Email column detected: '{email_col}'\n")

    # Step 4 — Validate
    validator = EmailValidator()
    total = len(df)

    print("  🔄 Running 3-layer validation pipeline...\n")
    start_time = time.time()

    results = []
    for idx, email in enumerate(df[email_col], start=1):
        status = validator.validate(email if pd.notna(email) else "")
        results.append(status)

        # Progress indicator every 50 rows or at the end
        if idx % 50 == 0 or idx == total:
            pct = idx / total * 100
            bar_filled = int(pct / 2)
            bar = "█" * bar_filled + "░" * (50 - bar_filled)
            print(f"\r     [{bar}] {pct:5.1f}%  ({idx:,}/{total:,})", end="", flush=True)

    elapsed = time.time() - start_time
    print(f"\n\n  ✅ Validation complete in {elapsed:.2f}s")

    # Step 5 — Append results
    df["Email_Status"] = results

    # Step 6 — Export
    output_path = os.path.join(os.getcwd(), OUTPUT_FILENAME)
    df.to_csv(output_path, index=False, encoding="utf-8-sig")
    print(f"  💾 Output saved: {output_path}")

    # Step 7 — Stats
    print(validator.get_stats_report())

    # Quick summary
    valid_count = results.count("Valid")
    invalid_count = results.count("Invalid")
    print(f"  📊 Quick Summary: {valid_count:,} Valid | {invalid_count:,} Invalid")
    print(f"     Unique domains cached: {len(validator.mx_cache):,}")
    print(f"\n  ✅ File ready: {OUTPUT_FILENAME}\n")


if __name__ == "__main__":
    main()
