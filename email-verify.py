#!/usr/bin/env python3
"""
Email Verifier v3.0 — Free SMTP-Based Email Verification

Verifies emails using SMTP RCPT TO handshake (no sending, no external APIs).
Layers: syntax → DNS/MX → SMTP → catch-all detection → scoring.

Zero cost. Run locally. Output piped directly into pipeline.
"""

import smtplib
import socket
import sys
import re
import csv
import time
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Optional

try:
    import dns.resolver
except ImportError:
    print("ERROR: dnspython required. Install: pip install dnspython")
    sys.exit(1)


# ── Disposable Email Domains ──────────────────────────────────
DISPOSABLE_DOMAINS = {
    "mailinator.com", "yopmail.com", "guerrillamail.com", "10minutemail.com",
    "temp-mail.org", "throwaway.email", "sharklasers.com", "trashmail.com",
    "maildrop.cc", "getairmail.com", "tempmail.com", "dispostable.com",
    "fakeinbox.com", "emailondeck.com", "spamgourmet.com", " guerrillamail.org",
    "mintemail.com", "mailnesia.com", "spambox.us", "telegmail.com",
    "getnada.com", "dropmail.me", "0wnd.net", "0wnd.org", "ownd.net",
    "spambog.com", "spambog.de", "spambog.ru", "discard.email",
    "discardmail.com", "discardmail.de", "mailforspam.com", "mailexpire.com",
    "mailnull.com", "mypacks.net", "mytrashmail.com", "nwytg.com",
    "objectmail.com", "obobbo.com", "pookmail.com", "safetymail.info",
    "sendspamhere.com", "spamspot.com", "trash2009.com", "trashdevil.com",
    "trashmail.net", "tyldd.com", "wegwerfmail.de", "wegwerfmail.net",
    "wegwerfmail.org", "wh4f.org", "willselfdestruct.com", "winemaven.info",
    "wronghead.com", "xagloo.com", "yogamaven.com", "ypmail.webarnak.fr.eu.org",
}

ROLE_BASED_PREFIXES = {
    "admin", "info", "support", "sales", "contact", "hello", "help",
    "billing", "team", "office", "mail", "webmaster", "postmaster",
    "abuse", "noc", "security", "hostmaster", "marketing", "enquiries",
    "jobs", "careers", "hr", "service", "customerservice", "accounts",
    "noreply", "no-reply", "donotreply", "do-not-reply",
}


@dataclass
class VerificationResult:
    """Single email verification result."""
    email: str
    is_valid: bool = False
    score: int = 0  # 0-100 confidence
    reason: str = ""
    mx_host: str = ""
    catch_all_domain: bool = False
    is_disposable: bool = False
    is_role_based: bool = False
    smtp_code: int = 0
    smtp_message: str = ""
    error: str = ""


# ── Layer 1: Syntax Validation ────────────────────────────────

def validate_syntax(email: str) -> tuple[bool, str]:
    """
    RFC 5322 simplified validation.
    Returns (is_valid, reason).
    """
    if not email or "@" not in email:
        return False, "No @ symbol"

    local_part, domain = email.rsplit("@", 1)

    if not local_part or not domain:
        return False, "Empty local or domain"

    if len(email) > 254:
        return False, "Email too long (>254 chars)"

    if len(local_part) > 64:
        return False, "Local part too long (>64 chars)"

    if ".." in email:
        return False, "Consecutive dots"

    # Basic regex — permissive enough to not reject valid addresses
    pattern = r'^[a-zA-Z0-9.!#$%&\'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$'
    if not re.match(pattern, email):
        return False, "Invalid format"

    return True, "Syntax valid"


# ── Layer 2: Domain Checks ────────────────────────────────────

def is_disposable(email: str) -> bool:
    """Check if email domain is a known disposable provider."""
    domain = email.rsplit("@", 1)[-1].lower()
    return domain in DISPOSABLE_DOMAINS


def is_role_based(email: str) -> bool:
    """Check if email is a role-based address (admin@, info@, etc)."""
    local = email.rsplit("@", 1)[0].lower().replace(".", "")
    return local in ROLE_BASED_PREFIXES


# ── Layer 3: DNS MX Resolution ────────────────────────────────

def resolve_mx(domain: str, timeout: float = 10.0) -> list[tuple[int, str]]:
    """
    Resolve MX records, return sorted by preference (lowest first).
    Returns list of (preference, hostname).
    """
    try:
        answers = dns.resolver.resolve(domain, "MX", lifetime=timeout)
        records = [(r.preference, str(r.exchange).rstrip(".")) for r in answers]
        records.sort(key=lambda x: x[0])
        return records
    except dns.resolver.NoAnswer:
        return []
    except dns.resolver.NXDOMAIN:
        return []
    except dns.resolver.Timeout:
        return []
    except Exception:
        return []


# ── Layer 4: SMTP RCPT TO Verification ────────────────────────

def verify_smtp(
    email: str,
    mx_records: list[tuple[int, str]],
    from_email: str = "verify@socialpatter.com",
    timeout: float = 15.0,
) -> tuple[Optional[bool], int, str, str, bool]:
    """
    Verify email via SMTP RCPT TO handshake. Never sends DATA.
    
    Returns: (is_valid_or_none, smtp_code, message, mx_used, is_catch_all)
    - True: address accepted
    - False: address rejected
    - None: uncertain (server unreachable or ambiguous)
    
    Uses raw SMTP commands via docmd() — no sendmail, no DATA phase.
    """
    for _, mx_host in mx_records:
        smtp = None
        try:
            smtp = smtplib.SMTP(timeout=timeout)
            smtp.connect(mx_host, 25)
            smtp.helo("socialpatter.com")

            # Use raw SMTP commands: MAIL FROM then RCPT TO
            # smtplib.mail() wraps MAIL FROM, but docmd is more explicit
            smtp.docmd("MAIL FROM:<%s>" % from_email)
            code, message = smtp.docmd("RCPT TO:<%s>" % email)

            smtp.quit()

            if code == 250:
                return True, code, message.decode(errors="replace"), mx_host, False
            elif code in (550, 551, 552, 553, 554):
                return False, code, message.decode(errors="replace"), mx_host, False
            else:
                # 4xx = temporary, 252 = VRFY not supported
                return None, code, message.decode(errors="replace"), mx_host, False

        except smtplib.SMTPConnectError:
            continue
        except smtplib.SMTPServerDisconnected:
            continue
        except smtplib.SMTPResponseException as e:
            smtp_code_val = e.smtp_code if hasattr(e, "smtp_code") else 0
            return None, smtp_code_val, str(e), mx_host, False
        except socket.timeout:
            continue
        except OSError:
            continue
        except Exception:
            continue
        finally:
            if smtp:
                try:
                    smtp.close()
                except Exception:
                    pass

    return None, 0, "No MX servers reachable", "", False


# ── Layer 5: Catch-All Detection ──────────────────────────────

def detect_catch_all(
    mx_records: list[tuple[int, str]],
    from_email: str = "verify@socialpatter.com",
    timeout: float = 10.0,
) -> bool:
    """
    Test if domain is a catch-all by attempting a clearly fake address.
    If the server accepts 'thisshouldnotexist923847@domain.com', it's a catch-all.
    """
    if not mx_records:
        return False

    domain = mx_records[0][1] if mx_records[0][1].count(".") >= 1 else mx_records[0][1]
    fake_email = f"thisshouldnotexist{mx_records[0][0]}@unknown.invalid"

    for _, mx_host in mx_records:
        smtp = None
        try:
            # Extract domain from MX for the fake test
            parts = mx_host.split(".")
            if len(parts) >= 2:
                test_domain = ".".join(parts[-2:])
            else:
                test_domain = mx_host

            test_email = f"nonexistent928374@{test_domain}"

            smtp = smtplib.SMTP(timeout=timeout)
            smtp.connect(mx_host, 25)
            smtp.helo("socialpatter.com")
            smtp.docmd("MAIL FROM:<%s>" % from_email)
            code, _ = smtp.docmd("RCPT TO:<%s>" % test_email)
            smtp.quit()
            return code == 250  # Accepts fake = catch-all
        except Exception:
            continue
        finally:
            if smtp:
                try:
                    smtp.close()
                except Exception:
                    pass
    return False


# ── Full Verification Pipeline ────────────────────────────────

def verify_email(
    email: str,
    from_email: str = "verify@socialpatter.com",
    timeout: float = 15.0,
    check_catch_all: bool = True,
) -> VerificationResult:
    """Run full verification pipeline on a single email address."""
    result = VerificationResult(email=email.strip().lower())

    # Layer 1: Syntax
    valid, reason = validate_syntax(result.email)
    if not valid:
        result.reason = f"Syntax: {reason}"
        result.score = 0
        return result
    result.score += 20

    # Layer 2: Domain checks
    result.is_disposable = is_disposable(result.email)
    if result.is_disposable:
        result.reason = "Disposable email"
        result.score = 0
        return result

    result.is_role_based = is_role_based(result.email)
    if result.is_role_based:
        result.score += 5  # Role-based is valid but lower quality for outreach
    else:
        result.score += 15

    # Layer 3: DNS MX
    domain = result.email.rsplit("@", 1)[-1]
    mx_records = resolve_mx(domain, timeout=timeout)
    if not mx_records:
        result.reason = "No MX records found"
        result.score = 0
        return result
    result.mx_host = mx_records[0][1]
    result.score += 25

    # Layer 4: Catch-all detection (on first verification per domain)
    if check_catch_all:
        result.catch_all_domain = detect_catch_all(mx_records, from_email, timeout)
        if result.catch_all_domain:
            result.score += 10  # Domain exists but can't verify individual address
            result.reason = "Catch-all domain — cannot verify individual address"
            result.is_valid = True  # Domain is real, address may exist
            return result

    # Layer 5: SMTP verification
    is_valid, code, msg, mx_used, _ = verify_smtp(
        result.email, mx_records, from_email, timeout
    )
    result.smtp_code = code
    result.smtp_message = msg
    result.mx_host = mx_used or result.mx_host

    if is_valid is True:
        result.is_valid = True
        result.score += 40
        result.reason = "SMTP verified"
    elif is_valid is False:
        result.is_valid = False
        result.score = 0
        result.reason = f"SMTP rejected: {code} {msg}"
    else:
        # Uncertain — all MX servers unreachable or ambiguous response
        result.is_valid = False
        result.score = max(0, result.score - 10)
        result.reason = f"SMTP ambiguous: {code} {msg}" if code else "No MX reachable"

    return result


# ── Bulk Verification ─────────────────────────────────────────

def verify_bulk(
    emails: list[str],
    max_workers: int = 10,
    from_email: str = "verify@socialpatter.com",
    timeout: float = 15.0,
    progress: bool = True,
) -> list[VerificationResult]:
    """Verify multiple emails concurrently with a thread pool."""
    results = []
    domain_catch_all_cache: dict[str, bool] = {}

    def verify_one(email: str) -> VerificationResult:
        domain = email.rsplit("@", 1)[-1].lower() if "@" in email else ""

        # Use cached catch-all result
        if domain in domain_catch_all_cache:
            check = False
        else:
            check = True

        result = verify_email(email, from_email, timeout, check_catch_all=check)

        # Cache catch-all result
        if domain and result.catch_all_domain:
            domain_catch_all_cache[domain] = True
        elif domain and check:
            domain_catch_all_cache[domain] = False

        return result

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(verify_one, e): e for e in emails}
        total = len(futures)

        for i, future in enumerate(as_completed(futures), 1):
            result = future.result()
            results.append(result)

            if progress and i % 10 == 0:
                valid_count = sum(1 for r in results if r.is_valid)
                print(f"  [{i}/{total}] {valid_count} valid, {i - valid_count} invalid", file=sys.stderr)

    # Sort by original order
    email_order = {e: i for i, e in enumerate(emails)}
    results.sort(key=lambda r: email_order.get(r.email, 999999))

    return results


# ── Output ────────────────────────────────────────────────────

def output_csv(results: list[VerificationResult], output_file: Optional[str] = None):
    """Write results to CSV."""
    fieldnames = [
        "email", "is_valid", "score", "reason", "mx_host",
        "catch_all_domain", "is_disposable", "is_role_based",
        "smtp_code", "smtp_message",
    ]

    if output_file:
        with open(output_file, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for r in results:
                writer.writerow({
                    "email": r.email,
                    "is_valid": r.is_valid,
                    "score": r.score,
                    "reason": r.reason,
                    "mx_host": r.mx_host,
                    "catch_all_domain": r.catch_all_domain,
                    "is_disposable": r.is_disposable,
                    "is_role_based": r.is_role_based,
                    "smtp_code": r.smtp_code,
                    "smtp_message": r.smtp_message,
                })
        print(f"Results written to {output_file}", file=sys.stderr)
    else:
        writer = csv.DictWriter(sys.stdout, fieldnames=fieldnames)
        writer.writeheader()
        for r in results:
            writer.writerow({
                "email": r.email,
                "is_valid": r.is_valid,
                "score": r.score,
                "reason": r.reason,
                "mx_host": r.mx_host,
                "catch_all_domain": r.catch_all_domain,
                "is_disposable": r.is_disposable,
                "is_role_based": r.is_role_based,
                "smtp_code": r.smtp_code,
                "smtp_message": r.smtp_message,
            })


def print_summary(results: list[VerificationResult]):
    """Print human-readable summary."""
    total = len(results)
    valid = sum(1 for r in results if r.is_valid)
    invalid = total - valid
    catch_all = sum(1 for r in results if r.catch_all_domain)
    disposable = sum(1 for r in results if r.is_disposable)
    role_based = sum(1 for r in results if r.is_role_based)
    high_confidence = sum(1 for r in results if r.score >= 90)

    print(f"\n{'='*60}")
    print(f"VERIFICATION SUMMARY")
    print(f"{'='*60}")
    print(f"  Total:            {total}")
    print(f"  Valid:            {valid} ({valid/total*100:.1f}%)" if total else "  Valid: 0")
    print(f"  Invalid:          {invalid}")
    print(f"  Catch-all domains:{catch_all} (domain exists, can't verify individual)")
    print(f"  Disposable:       {disposable} (rejected)")
    print(f"  Role-based:       {role_based} (valid but lower outreach quality)")
    print(f"  High confidence:  {high_confidence} (score 90+)")
    print(f"{'='*60}")

    if role_based:
        print(f"\n  ⚠ {role_based} role-based emails (info@, admin@, etc).")
        print(f"    These deliver but rarely get read by decision makers.")
        print(f"    Prioritize personal-name emails for outreach.")


# ── Main ──────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Email Verifier v3.0 — Free SMTP-Based Verification",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -e test@example.com
  %(prog)s -f leads.csv --email-column 3
  %(prog)s -f emails.txt --output verified.csv
  %(prog)s -f emails.txt --workers 20 --timeout 10
        """,
    )
    parser.add_argument("-e", "--email", help="Single email to verify")
    parser.add_argument("-f", "--file", help="File with emails (one per line, or CSV)")
    parser.add_argument(
        "--email-column",
        type=int,
        default=1,
        help="Column number for email in CSV file (1-based, default: 1)",
    )
    parser.add_argument(
        "-o", "--output", help="Output CSV file (default: stdout)"
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=10,
        help="Concurrent workers (default: 10, max safe: 20)",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=15.0,
        help="SMTP timeout in seconds (default: 15)",
    )
    parser.add_argument(
        "--from-email",
        default="verify@socialpatter.com",
        help="MAIL FROM address (default: verify@socialpatter.com)",
    )
    parser.add_argument(
        "-q", "--quiet", action="store_true", help="Suppress progress output"
    )
    parser.add_argument(
        "--summary-only", action="store_true", help="Only print summary, no CSV"
    )
    args = parser.parse_args()

    if not args.email and not args.file:
        parser.print_help()
        sys.exit(1)

    # Collect emails
    emails = []
    if args.email:
        emails = [args.email]
    elif args.file:
        try:
            with open(args.file, "r") as f:
                # Detect CSV vs plain text
                first_line = f.readline().strip()
                f.seek(0)

                if "," in first_line and args.email_column:
                    # CSV mode
                    reader = csv.reader(f)
                    # Skip header if it looks like one
                    header = next(reader, None)
                    col_idx = args.email_column - 1
                    for row in reader:
                        if len(row) > col_idx:
                            email = row[col_idx].strip()
                            if email and "@" in email:
                                emails.append(email)
                else:
                    # Plain text mode (one per line)
                    for line in f:
                        email = line.strip()
                        if email and "@" in email:
                            emails.append(email)
        except FileNotFoundError:
            print(f"ERROR: File not found: {args.file}", file=sys.stderr)
            sys.exit(1)

    if not emails:
        print("ERROR: No emails found to verify", file=sys.stderr)
        sys.exit(1)

    print(f"Verifying {len(emails)} email(s)...", file=sys.stderr)

    # Run verification
    start = time.time()
    results = verify_bulk(
        emails,
        max_workers=args.workers,
        from_email=args.from_email,
        timeout=args.timeout,
        progress=not args.quiet,
    )
    elapsed = time.time() - start

    # Output
    if not args.summary_only:
        output_csv(results, args.output)

    print_summary(results)
    print(f"\nVerified {len(emails)} emails in {elapsed:.1f}s "
          f"({len(emails)/elapsed:.1f} emails/sec)", file=sys.stderr)


if __name__ == "__main__":
    main()
