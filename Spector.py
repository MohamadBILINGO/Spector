#!/usr/bin/env python3
"""
Spector — Security Header, TLS, Cookie & CORS Scanner
Created by Mohamad
------------------------------------------------------------
Checks a domain's HTTP security headers, TLS/SSL configuration, cookie
flags, and CORS policy, then produces a single risk-prioritized report
(Critical / High / Medium / Low / Info) as text, JSON, and/or HTML.
Supports scanning a single target or a batch of targets from a file.

Usage:
    python3 header_scanner.py example.com
    python3 header_scanner.py https://example.com --json report.json
    python3 header_scanner.py example.com --html report.html
    python3 header_scanner.py example.com --lang fa
    python3 header_scanner.py example.com --no-tls
    python3 header_scanner.py --batch domains.txt --html batch_report.html --json batch.json
"""

import argparse
import json
import socket
import ssl
import sys
import warnings
from dataclasses import dataclass
from datetime import datetime, timezone
from urllib.parse import urlparse

import requests

warnings.filterwarnings("ignore", category=DeprecationWarning)

# ---------------------------------------------------------------------------
# Translated UI strings
# ---------------------------------------------------------------------------

STRINGS = {
    "en": {
        "report_title": "Spector — Security Scan Report",
        "target": "Target", "scanned_at": "Scanned at", "scan_error": "Scan error",
        "tls_error": "TLS check error", "status_code": "HTTP status code",
        "final_url": "Final URL (after redirects)", "summary": "Summary of findings",
        "no_issues": "No issues found. \u2714", "details": "Findings detail",
        "status": "status", "description": "Description", "remediation": "Remediation",
        "current_value": "Current value", "json_saved": "JSON output saved to",
        "html_saved": "HTML report saved to", "batch_summary": "Spector — Batch Scan Summary",
    },
    "fa": {
        "report_title": "Spector — گزارش اسکن امنیتی",
        "target": "هدف", "scanned_at": "زمان", "scan_error": "خطا در اسکن",
        "tls_error": "خطا در بررسی TLS", "status_code": "کد وضعیت HTTP",
        "final_url": "URL نهایی (پس از ریدایرکت)", "summary": "خلاصه یافته‌ها",
        "no_issues": "هیچ مشکلی یافت نشد. \u2714", "details": "جزئیات یافته‌ها",
        "status": "وضعیت", "description": "توضیح", "remediation": "راه‌حل",
        "current_value": "مقدار فعلی", "json_saved": "خروجی JSON ذخیره شد در",
        "html_saved": "گزارش HTML ذخیره شد در", "batch_summary": "Spector — خلاصه اسکن گروهی",
    },
}

STATUS_LABELS = {
    "en": {"missing": "missing", "misconfigured": "misconfigured", "present": "present",
           "weak": "weak", "expiring": "expiring", "permissive": "overly permissive"},
    "fa": {"missing": "مفقود", "misconfigured": "پیکربندی نادرست", "present": "موجود",
           "weak": "ضعیف", "expiring": "نزدیک انقضا", "permissive": "بیش‌ازحد باز"},
}

RISK_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
RISK_COLORS = {"Critical": "#7f1d1d", "High": "#b91c1c", "Medium": "#b45309",
               "Low": "#0369a1", "Info": "#4b5563"}

# ---------------------------------------------------------------------------
# HTTP header rules
# ---------------------------------------------------------------------------


@dataclass
class HeaderRule:
    name: str
    risk_if_missing: str
    description: dict
    remediation: dict
    validator: "callable" = None


def validate_hsts(value, lang):
    if "max-age=" not in value:
        return False, {"en": "HSTS header is set without a max-age directive.",
                        "fa": "هدر HSTS بدون max-age تنظیم شده است."}[lang]
    try:
        max_age = int(value.split("max-age=")[1].split(";")[0].strip())
    except (IndexError, ValueError):
        return False, {"en": "The max-age value in HSTS could not be parsed.",
                        "fa": "مقدار max-age در HSTS قابل خواندن نیست."}[lang]
    if max_age < 15552000:
        return False, {"en": f"max-age={max_age} is below the recommended minimum (6 months).",
                        "fa": f"max-age={max_age} کمتر از حداقل توصیه‌شده (۶ ماه) است."}[lang]
    return True, None


def validate_csp(value, lang):
    found = [p for p in ["unsafe-inline", "unsafe-eval", "*"] if p in value]
    if found:
        return False, {"en": f"CSP contains risky patterns: {', '.join(found)}",
                        "fa": f"CSP شامل الگوهای پرخطر است: {', '.join(found)}"}[lang]
    return True, None


def validate_xcto(value, lang):
    if value.strip().lower() != "nosniff":
        return False, {"en": "X-Content-Type-Options value must be exactly 'nosniff'.",
                        "fa": "مقدار X-Content-Type-Options باید دقیقاً 'nosniff' باشد."}[lang]
    return True, None


HEADER_RULES = [
    HeaderRule("Strict-Transport-Security", "High",
        {"en": "Without HSTS, browsers aren't forced to use HTTPS, enabling downgrade/SSL-stripping attacks.",
         "fa": "بدون HSTS، مرورگر مجبور به استفاده از HTTPS نمی‌شود و امکان حملات downgrade وجود دارد."},
        {"en": "Set 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload'.",
         "fa": "هدر 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload' را تنظیم کنید."},
        validate_hsts),
    HeaderRule("Content-Security-Policy", "High",
        {"en": "Without CSP, the site is more vulnerable to XSS and data-injection attacks.",
         "fa": "بدون CSP، سایت در برابر حملات XSS آسیب‌پذیرتر است."},
        {"en": "Define a restrictive CSP and avoid 'unsafe-inline', 'unsafe-eval', and wildcard (*).",
         "fa": "یک CSP محدود تعریف کنید و از الگوهای پرخطر پرهیز کنید."},
        validate_csp),
    HeaderRule("X-Content-Type-Options", "Medium",
        {"en": "Without this header, browsers may MIME-sniff content types.",
         "fa": "بدون این هدر، مرورگر ممکن است نوع فایل را حدس بزند (MIME sniffing)."},
        {"en": "Add 'X-Content-Type-Options: nosniff'.",
         "fa": "هدر 'X-Content-Type-Options: nosniff' را اضافه کنید."},
        validate_xcto),
    HeaderRule("X-Frame-Options", "Medium",
        {"en": "Without this header, the site is vulnerable to clickjacking attacks.",
         "fa": "بدون این هدر، سایت در برابر Clickjacking آسیب‌پذیر است."},
        {"en": "Set 'X-Frame-Options: DENY' or 'SAMEORIGIN'.",
         "fa": "هدر 'X-Frame-Options: DENY' یا 'SAMEORIGIN' تنظیم شود."}),
    HeaderRule("Referrer-Policy", "Low",
        {"en": "Without this header, sensitive info may leak via the Referrer header.",
         "fa": "بدون این هدر، اطلاعات حساس ممکن است از طریق Referrer نشت کند."},
        {"en": "Set 'Referrer-Policy: strict-origin-when-cross-origin'.",
         "fa": "هدر 'Referrer-Policy: strict-origin-when-cross-origin' تنظیم شود."}),
    HeaderRule("Permissions-Policy", "Low",
        {"en": "Without this header, browser feature access remains uncontrolled.",
         "fa": "بدون این هدر، دسترسی به قابلیت‌های مرورگر کنترل‌نشده باقی می‌ماند."},
        {"en": "Set a 'Permissions-Policy' header to restrict unnecessary features.",
         "fa": "هدر 'Permissions-Policy' را تنظیم کنید."}),
]

INFO_LEAK_HEADERS = {
    "Server": {"en": "Reveals server software/version, aiding vulnerability identification.",
               "fa": "نسخه‌ی سرور را فاش می‌کند."},
    "X-Powered-By": {"en": "Reveals the backend technology/framework in use.",
                      "fa": "فناوری backend را فاش می‌کند."},
    "X-AspNet-Version": {"en": "Reveals the ASP.NET version in use.",
                          "fa": "نسخه‌ی ASP.NET را فاش می‌کند."},
}

WEAK_CIPHER_KEYWORDS = ["RC4", "DES", "3DES", "NULL", "EXPORT", "MD5", "ANON"]
DEPRECATED_PROTOCOLS = [("TLSv1", "PROTOCOL_TLSv1"), ("TLSv1.1", "PROTOCOL_TLSv1_1")]

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def normalize_url(target: str) -> str:
    if not target.startswith(("http://", "https://")):
        target = "https://" + target
    return target


def get_hostname(url: str) -> str:
    return urlparse(url).hostname


def fetch(url, lang, timeout=10, headers=None):
    try:
        return requests.get(url, timeout=timeout, allow_redirects=True, headers=headers or {}), None
    except requests.exceptions.SSLError as e:
        return None, {"en": f"SSL error: {e}", "fa": f"خطای SSL: {e}"}[lang]
    except requests.exceptions.ConnectionError as e:
        return None, {"en": f"Connection error: {e}", "fa": f"خطای اتصال: {e}"}[lang]
    except requests.exceptions.Timeout:
        return None, {"en": "The request timed out.", "fa": "درخواست timeout شد."}[lang]
    except requests.exceptions.RequestException as e:
        return None, {"en": f"Unexpected request error: {e}", "fa": f"خطای ناشناخته: {e}"}[lang]


# ---------------------------------------------------------------------------
# HTTP header + cookie scanning
# ---------------------------------------------------------------------------


def parse_set_cookie(raw: str):
    parts = raw.split(";")
    name = parts[0].split("=")[0].strip()
    attrs = {}
    for p in parts[1:]:
        p = p.strip()
        if not p:
            continue
        if "=" in p:
            k, v = p.split("=", 1)
            attrs[k.strip().lower()] = v.strip()
        else:
            attrs[p.lower()] = True
    return name, attrs


def scan_cookies(url: str, resp, lang: str):
    findings = []
    is_https = url.startswith("https://")
    try:
        raw_cookies = resp.raw.headers.getlist("Set-Cookie")
    except AttributeError:
        single = resp.headers.get("Set-Cookie")
        raw_cookies = [single] if single else []

    for raw in raw_cookies:
        name, attrs = parse_set_cookie(raw)
        if is_https and "secure" not in attrs:
            findings.append({
                "category": "cookie", "header": f"Cookie: {name}", "status": "misconfigured", "risk": "High",
                "description": {"en": f"Cookie '{name}' is missing the Secure flag; it can be sent over unencrypted HTTP.",
                                 "fa": f"کوکی '{name}' فاقد فلگ Secure است و ممکن است روی HTTP رمزنگاری‌نشده ارسال شود."}[lang],
                "remediation": {"en": "Add the 'Secure' attribute to the cookie.",
                                 "fa": "ویژگی 'Secure' را به کوکی اضافه کنید."}[lang],
            })
        if "httponly" not in attrs:
            findings.append({
                "category": "cookie", "header": f"Cookie: {name}", "status": "misconfigured", "risk": "Medium",
                "description": {"en": f"Cookie '{name}' is missing HttpOnly; JavaScript can read it, aiding XSS-based theft.",
                                 "fa": f"کوکی '{name}' فاقد HttpOnly است و جاوااسکریپت می‌تواند آن را بخواند (خطر سرقت از طریق XSS)."}[lang],
                "remediation": {"en": "Add the 'HttpOnly' attribute to the cookie.",
                                 "fa": "ویژگی 'HttpOnly' را به کوکی اضافه کنید."}[lang],
            })
        samesite = attrs.get("samesite")
        if samesite is None:
            findings.append({
                "category": "cookie", "header": f"Cookie: {name}", "status": "missing", "risk": "Low",
                "description": {"en": f"Cookie '{name}' has no SameSite attribute set explicitly.",
                                 "fa": f"کوکی '{name}' مقدار SameSite را به‌صراحت تنظیم نکرده است."}[lang],
                "remediation": {"en": "Set 'SameSite=Lax' or 'Strict' explicitly to reduce CSRF risk.",
                                 "fa": "مقدار 'SameSite=Lax' یا 'Strict' را به‌صراحت تنظیم کنید تا ریسک CSRF کم شود."}[lang],
            })
        elif str(samesite).lower() == "none" and "secure" not in attrs:
            findings.append({
                "category": "cookie", "header": f"Cookie: {name}", "status": "misconfigured", "risk": "High",
                "description": {"en": f"Cookie '{name}' uses SameSite=None without Secure, which browsers reject/flag.",
                                 "fa": f"کوکی '{name}' از SameSite=None بدون Secure استفاده می‌کند که مرورگرها آن را رد می‌کنند."}[lang],
                "remediation": {"en": "Add 'Secure' whenever SameSite=None is used.",
                                 "fa": "هرجا از SameSite=None استفاده می‌شود، 'Secure' را هم اضافه کنید."}[lang],
            })
    return findings


def scan_headers(url, lang):
    resp, error = fetch(url, lang)
    if error:
        return [], {}, error, None

    headers = resp.headers
    findings = []

    for rule in HEADER_RULES:
        value = headers.get(rule.name)
        if value is None:
            findings.append({"category": "header", "header": rule.name, "status": "missing",
                              "risk": rule.risk_if_missing, "description": rule.description[lang],
                              "remediation": rule.remediation[lang]})
        elif rule.validator:
            ok, reason = rule.validator(value, lang)
            if not ok:
                findings.append({"category": "header", "header": rule.name, "status": "misconfigured",
                                  "risk": rule.risk_if_missing, "description": reason,
                                  "remediation": rule.remediation[lang], "current_value": value})

    for header_name, desc in INFO_LEAK_HEADERS.items():
        value = headers.get(header_name)
        if value:
            cur = STRINGS[lang]["current_value"]
            findings.append({"category": "header", "header": header_name, "status": "present", "risk": "Info",
                              "description": f"{desc[lang]} ({cur}: {value})",
                              "remediation": {"en": f"Remove or generalize the '{header_name}' header.",
                                              "fa": f"هدر '{header_name}' را حذف یا مقدارش را عمومی‌تر کنید."}[lang]})

    findings.extend(scan_cookies(url, resp, lang))

    meta = {"final_url": resp.url, "status_code": resp.status_code}
    return findings, meta, None, resp


# ---------------------------------------------------------------------------
# CORS scanning
# ---------------------------------------------------------------------------


def scan_cors(url, lang):
    findings = []
    probe_origin = "https://cors-test-probe.example.org"
    resp, error = fetch(url, lang, headers={"Origin": probe_origin})
    if error or resp is None:
        return findings, error

    acao = resp.headers.get("Access-Control-Allow-Origin")
    acac = resp.headers.get("Access-Control-Allow-Credentials", "").lower() == "true"

    if not acao:
        return findings, None

    if acao == probe_origin:
        risk = "Critical" if acac else "Medium"
        cred_suffix_en = " using the victim's credentials" if acac else ""
        cred_suffix_fa = " (حتی با اعتبار قربانی)" if acac else ""
        findings.append({
            "category": "cors", "header": "Access-Control-Allow-Origin", "status": "permissive", "risk": risk,
            "description": {
                "en": f"The server reflects an arbitrary Origin back in ACAO{' with credentials allowed' if acac else ''}, "
                      f"letting any website read this API's responses{cred_suffix_en}.",
                "fa": f"سرور مقدار Origin دلخواه را در ACAO بازتاب می‌دهد{' (همراه با اجازه‌ی credentials)' if acac else ''} "
                      f"و این یعنی هر سایتی می‌تواند پاسخ‌های این API را بخواند{cred_suffix_fa}."}[lang],
            "remediation": {"en": "Validate Origin against an allow-list server-side instead of reflecting it; never combine with wildcard credentials.",
                             "fa": "Origin را در سمت سرور با یک allow-list معتبر بسنجید، نه اینکه هرچیزی را بازتاب دهید."}[lang],
            "current_value": acao,
        })
    elif acao == "*":
        risk = "Critical" if acac else "Low"
        findings.append({
            "category": "cors", "header": "Access-Control-Allow-Origin", "status": "permissive", "risk": risk,
            "description": {
                "en": "ACAO is set to '*' (any origin)" + (", combined with Allow-Credentials — an invalid and dangerous combination." if acac else ". Fine for fully public, non-authenticated APIs; risky otherwise."),
                "fa": "مقدار ACAO برابر '*' است" + ("، همراه با Allow-Credentials — ترکیبی نامعتبر و خطرناک." if acac else "؛ برای APIهای کاملاً عمومی و بدون احراز هویت مشکلی ندارد.")}[lang],
            "remediation": {"en": "If the API handles authenticated requests, replace '*' with a specific allow-list of origins.",
                             "fa": "اگر API درخواست‌های احرازهویت‌شده را مدیریت می‌کند، '*' را با یک allow-list مشخص جایگزین کنید."}[lang],
            "current_value": acao,
        })
    return findings, None


# ---------------------------------------------------------------------------
# TLS scanning
# ---------------------------------------------------------------------------


def get_certificate_info(hostname, port=443, timeout=10):
    ctx = ssl.create_default_context()
    with socket.create_connection((hostname, port), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
            return ssock.getpeercert(), ssock.cipher(), ssock.version()


def check_deprecated_protocol(hostname, port, protocol_attr, timeout=8):
    proto_const = getattr(ssl, protocol_attr, None)
    if proto_const is None:
        return False
    try:
        ctx = ssl.SSLContext(proto_const)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname):
                return True
    except Exception:
        return False


def scan_tls(hostname, lang, port=443):
    findings, meta = [], {}
    try:
        cert, cipher, version = get_certificate_info(hostname, port)
    except ssl.SSLCertVerificationError as e:
        return [], {}, {"en": f"Certificate verification failed: {e}", "fa": f"تایید گواهی ناموفق بود: {e}"}[lang]
    except (socket.timeout, socket.gaierror, ConnectionRefusedError, OSError) as e:
        return [], {}, {"en": f"Could not establish a TLS connection: {e}", "fa": f"اتصال TLS برقرار نشد: {e}"}[lang]

    meta["tls_version"] = version
    meta["cipher"] = cipher[0] if cipher else None

    not_after_str = cert.get("notAfter")
    if not_after_str:
        expires_at = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        days_left = (expires_at - datetime.now(timezone.utc)).days
        meta["cert_expires"] = expires_at.isoformat()
        if days_left < 0:
            risk, desc_en, desc_fa = "Critical", f"The TLS certificate expired {abs(days_left)} day(s) ago.", f"گواهی TLS از {abs(days_left)} روز پیش منقضی شده است."
        elif days_left < 14:
            risk, desc_en, desc_fa = "High", f"The TLS certificate expires in {days_left} day(s).", f"گواهی TLS تا {days_left} روز دیگر منقضی می‌شود."
        elif days_left < 30:
            risk, desc_en, desc_fa = "Medium", f"The TLS certificate expires in {days_left} day(s).", f"گواهی TLS تا {days_left} روز دیگر منقضی می‌شود."
        else:
            risk = None
        if risk:
            findings.append({"category": "tls", "header": "Certificate expiry", "status": "expiring", "risk": risk,
                              "description": {"en": desc_en, "fa": desc_fa}[lang],
                              "remediation": {"en": "Renew the TLS certificate.", "fa": "گواهی TLS را تمدید کنید."}[lang],
                              "current_value": not_after_str})

    issuer = dict(x[0] for x in cert.get("issuer", []))
    subject = dict(x[0] for x in cert.get("subject", []))
    if issuer == subject:
        findings.append({"category": "tls", "header": "Certificate trust", "status": "misconfigured", "risk": "High",
                          "description": {"en": "The certificate appears to be self-signed.",
                                          "fa": "گواهی به‌نظر self-signed است."}[lang],
                          "remediation": {"en": "Use a certificate from a trusted public CA.",
                                          "fa": "از یک گواهی معتبر عمومی استفاده کنید."}[lang]})

    for label, attr in DEPRECATED_PROTOCOLS:
        if check_deprecated_protocol(hostname, port, attr):
            findings.append({"category": "tls", "header": f"Protocol {label}", "status": "weak", "risk": "High",
                              "description": {"en": f"The server accepts connections using the deprecated {label} protocol.",
                                              "fa": f"سرور اتصال با پروتکل منسوخ {label} را می‌پذیرد."}[lang],
                              "remediation": {"en": f"Disable {label}; require TLS 1.2 or higher.",
                                              "fa": f"پروتکل {label} را غیرفعال کنید."}[lang]})

    if cipher and any(w in cipher[0].upper() for w in WEAK_CIPHER_KEYWORDS):
        findings.append({"category": "tls", "header": "Cipher suite", "status": "weak", "risk": "High",
                          "description": {"en": f"The negotiated cipher suite ({cipher[0]}) is considered weak.",
                                          "fa": f"سوییت رمزنگاری ({cipher[0]}) ضعیف محسوب می‌شود."}[lang],
                          "remediation": {"en": "Disable weak ciphers; prefer AES-GCM/ChaCha20.",
                                          "fa": "سوییت‌های ضعیف را غیرفعال و از AES-GCM/ChaCha20 استفاده کنید."}[lang]})

    if version in ("TLSv1", "TLSv1.1"):
        findings.append({"category": "tls", "header": "Negotiated protocol", "status": "weak", "risk": "High",
                          "description": {"en": f"The connection negotiated {version}, which is deprecated.",
                                          "fa": f"اتصال با نسخه منسوخ {version} انجام شد."}[lang],
                          "remediation": {"en": "Configure the server to prefer TLS 1.2 or 1.3.",
                                          "fa": "سرور را برای اولویت TLS 1.2/1.3 پیکربندی کنید."}[lang]})

    return findings, meta, None


# ---------------------------------------------------------------------------
# Combined scan for one target
# ---------------------------------------------------------------------------


def scan(url, lang="en", include_tls=True, include_cors=True):
    hostname = get_hostname(url)
    header_findings, header_meta, header_error, resp = scan_headers(url, lang)

    cors_findings, cors_error = [], None
    if include_cors and resp is not None:
        cors_findings, cors_error = scan_cors(url, lang)

    tls_findings, tls_meta, tls_error = [], {}, None
    if include_tls and hostname:
        tls_findings, tls_meta, tls_error = scan_tls(hostname, lang)

    all_findings = header_findings + cors_findings + tls_findings
    all_findings.sort(key=lambda f: RISK_ORDER.get(f["risk"], 99))

    return {
        "target": url, "hostname": hostname, "scanned_at": datetime.now(timezone.utc).isoformat(),
        "header_error": header_error, "tls_error": tls_error, "cors_error": cors_error,
        "final_url": header_meta.get("final_url"), "status_code": header_meta.get("status_code"),
        "tls_version": tls_meta.get("tls_version"), "cipher": tls_meta.get("cipher"),
        "cert_expires": tls_meta.get("cert_expires"), "findings": all_findings,
        "summary": {level: sum(1 for f in all_findings if f["risk"] == level)
                    for level in ["Critical", "High", "Medium", "Low", "Info"]},
    }


# ---------------------------------------------------------------------------
# Text report
# ---------------------------------------------------------------------------


def print_report(result, lang="en"):
    t = STRINGS[lang]
    status_labels = STATUS_LABELS[lang]

    print("=" * 70)
    print(f"  {t['report_title']}")
    print(f"  {t['target']}: {result['target']}")
    print(f"  {t['scanned_at']}: {result['scanned_at']}")
    print("=" * 70)

    if result.get("header_error"):
        print(f"\n[!] {t['scan_error']}: {result['header_error']}")
    else:
        print(f"  {t['status_code']}: {result['status_code']}")
        if result.get("final_url") and result.get("final_url") != result["target"]:
            print(f"  {t['final_url']}: {result['final_url']}")

    if result.get("tls_error"):
        print(f"[!] {t['tls_error']}: {result['tls_error']}")
    elif result.get("tls_version"):
        print(f"  TLS: {result['tls_version']} | Cipher: {result.get('cipher')}")

    print(f"\n  {t['summary']}:")
    for level, count in result["summary"].items():
        if count:
            print(f"    {level:10s}: {count}")

    if not result["findings"]:
        print(f"\n  {t['no_issues']}")
        return

    print(f"\n  {t['details']}:")
    print("-" * 70)
    for f in result["findings"]:
        status_label = status_labels.get(f["status"], f["status"])
        tag = {"tls": "[TLS]", "cors": "[CORS]", "cookie": "[COOKIE]"}.get(f.get("category"), "[HDR]")
        print(f"{tag} [{f['risk'].upper()}] {f['header']} — {t['status']}: {status_label}")
        print(f"    {t['description']}: {f['description']}")
        print(f"    {t['remediation']}: {f['remediation']}")
        if "current_value" in f:
            print(f"    {t['current_value']}: {f['current_value']}")
        print("-" * 70)


# ---------------------------------------------------------------------------
# HTML report
# ---------------------------------------------------------------------------

def _esc(s):
    if s is None:
        return ""
    return (str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))


def generate_html_report(results, lang="en"):
    t = STRINGS[lang]
    status_labels = STATUS_LABELS[lang]
    dir_attr = ' dir="rtl"' if lang == "fa" else ""

    sections = []
    for result in results:
        rows = []
        for f in result["findings"]:
            color = RISK_COLORS.get(f["risk"], "#4b5563")
            status_label = status_labels.get(f["status"], f["status"])
            tag = f.get("category", "header").upper()
            cur = f'<div class="cur">{t["current_value"]}: {_esc(f.get("current_value"))}</div>' if "current_value" in f else ""
            rows.append(f'''
            <div class="finding" style="border-left-color:{color}">
              <div class="finding-head">
                <span class="badge" style="background:{color}">{_esc(f["risk"].upper())}</span>
                <span class="tag">{_esc(tag)}</span>
                <span class="hname">{_esc(f["header"])}</span>
                <span class="status">{_esc(status_label)}</span>
              </div>
              <div class="desc">{_esc(f["description"])}</div>
              <div class="rem"><strong>{_esc(t["remediation"])}:</strong> {_esc(f["remediation"])}</div>
              {cur}
            </div>''')

        summary_chips = "".join(
            f'<span class="chip" style="background:{RISK_COLORS[lvl]}">{lvl}: {cnt}</span>'
            for lvl, cnt in result["summary"].items() if cnt
        )

        errors_html = ""
        if result.get("header_error"):
            errors_html += f'<div class="error">{_esc(t["scan_error"])}: {_esc(result["header_error"])}</div>'
        if result.get("tls_error"):
            errors_html += f'<div class="error">{_esc(t["tls_error"])}: {_esc(result["tls_error"])}</div>'

        meta_html = ""
        if result.get("status_code"):
            meta_html += f'<div class="meta-item">{t["status_code"]}: {result["status_code"]}</div>'
        if result.get("tls_version"):
            meta_html += f'<div class="meta-item">TLS: {_esc(result["tls_version"])} | {_esc(result.get("cipher"))}</div>'

        body = f'<div class="no-issues">{t["no_issues"]}</div>' if not result["findings"] else "".join(rows)

        sections.append(f'''
        <section class="target-section">
          <h2>{_esc(result["target"])}</h2>
          <div class="meta">{meta_html}</div>
          {errors_html}
          <div class="chips">{summary_chips}</div>
          {body}
        </section>''')

    title = t["batch_summary"] if len(results) > 1 else t["report_title"]

    return f'''<!DOCTYPE html>
<html lang="{lang}"{dir_attr}>
<head>
<meta charset="UTF-8">
<title>{_esc(title)}</title>
<style>
  body {{ font-family: -apple-system, Segoe UI, Tahoma, sans-serif; background:#0f172a; color:#e2e8f0; margin:0; padding:32px; }}
  h1 {{ font-size: 22px; margin-bottom: 4px; }}
  .subtitle {{ color:#94a3b8; margin-bottom:28px; font-size:13px; }}
  .target-section {{ background:#1e293b; border-radius:12px; padding:20px 24px; margin-bottom:24px; }}
  .target-section h2 {{ margin-top:0; font-size:17px; color:#f1f5f9; word-break:break-all; }}
  .meta {{ display:flex; gap:16px; flex-wrap:wrap; font-size:12px; color:#94a3b8; margin-bottom:8px; }}
  .chips {{ display:flex; gap:8px; flex-wrap:wrap; margin-bottom:16px; }}
  .chip {{ color:white; font-size:11px; padding:3px 10px; border-radius:999px; font-weight:600; }}
  .finding {{ border-left:4px solid; background:#0f172a; border-radius:6px; padding:12px 14px; margin-bottom:10px; }}
  .finding-head {{ display:flex; gap:8px; align-items:center; margin-bottom:6px; flex-wrap:wrap; }}
  .badge {{ color:white; font-size:10px; font-weight:700; padding:2px 8px; border-radius:4px; }}
  .tag {{ font-size:10px; color:#64748b; border:1px solid #334155; padding:1px 6px; border-radius:4px; }}
  .hname {{ font-weight:600; font-size:13px; }}
  .status {{ font-size:11px; color:#94a3b8; margin-inline-start:auto; }}
  .desc {{ font-size:13px; color:#cbd5e1; margin-bottom:4px; }}
  .rem {{ font-size:12px; color:#86efac; }}
  .cur {{ font-size:11px; color:#64748b; margin-top:4px; }}
  .no-issues {{ color:#86efac; font-size:14px; }}
  .error {{ color:#fca5a5; font-size:13px; margin-bottom:10px; }}
</style>
</head>
<body>
  <h1>{_esc(title)}</h1>
  <div class="subtitle">{_esc(t["scanned_at"])}: {_esc(datetime.now(timezone.utc).isoformat())}</div>
  {''.join(sections)}
</body>
</html>'''


# ---------------------------------------------------------------------------
# Batch mode
# ---------------------------------------------------------------------------


def read_batch_file(path):
    targets = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                targets.append(line)
    return targets


def main():
    parser = argparse.ArgumentParser(
        description="Spector — Check HTTP security headers, TLS/SSL, cookies, and CORS policy for a domain, and generate a risk report."
    )
    parser.add_argument("target", nargs="?", help="Domain or URL to scan (e.g. example.com)")
    parser.add_argument("--batch", metavar="FILE", help="File with one domain/URL per line to scan in batch")
    parser.add_argument("--json", metavar="FILE", help="Save output as JSON")
    parser.add_argument("--html", metavar="FILE", help="Save output as an HTML report")
    parser.add_argument("--lang", choices=["en", "fa"], default="en", help="Report language: en (default) or fa")
    parser.add_argument("--no-tls", action="store_true", help="Skip TLS/SSL checks")
    parser.add_argument("--no-cors", action="store_true", help="Skip CORS checks")
    args = parser.parse_args()

    if not args.target and not args.batch:
        parser.error("Provide a target domain, or use --batch FILE for multiple targets.")

    targets = read_batch_file(args.batch) if args.batch else [args.target]
    results = []

    for raw_target in targets:
        url = normalize_url(raw_target)
        print(f"\n[*] Scanning {url} ...")
        result = scan(url, lang=args.lang, include_tls=not args.no_tls, include_cors=not args.no_cors)
        results.append(result)
        print_report(result, lang=args.lang)

    if len(results) > 1:
        print("\n" + "=" * 70)
        print(f"  {STRINGS[args.lang]['batch_summary']}")
        print("=" * 70)
        for r in results:
            crit = r["summary"].get("Critical", 0)
            high = r["summary"].get("High", 0)
            print(f"  {r['target']:<40} Critical:{crit}  High:{high}")

    if args.json:
        payload = results if len(results) > 1 else results[0]
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump(payload, f, ensure_ascii=False, indent=2)
        print(f"\n[+] {STRINGS[args.lang]['json_saved']}: {args.json}")

    if args.html:
        html = generate_html_report(results, lang=args.lang)
        with open(args.html, "w", encoding="utf-8") as f:
            f.write(html)
        print(f"[+] {STRINGS[args.lang]['html_saved']}: {args.html}")

    worst_high_or_critical = any(r["summary"].get("Critical") or r["summary"].get("High") for r in results)
    all_errored = all(r.get("header_error") and r.get("tls_error") for r in results)
    if all_errored:
        sys.exit(2)
    if worst_high_or_critical:
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
