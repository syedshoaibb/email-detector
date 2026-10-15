"""
Lightweight forensic analysis of a single .eml file.

Fills the Authentication / Routing / URLs / Attachments / Timeline /
Findings sections of the page. Used automatically when the separate
`m2_forensics` package is not present.
"""

import hashlib
import re

from email import policy
from email.parser import BytesParser
from email.utils import parseaddr, parsedate_to_datetime
from html.parser import HTMLParser

URL_RE = re.compile(r"https?://[^\s<>\"']+|www\.[^\s<>\"']+", re.IGNORECASE)
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

RISKY_EXTENSIONS = {
    ".exe", ".scr", ".bat", ".cmd", ".com", ".js", ".jse", ".vbs", ".vbe",
    ".ps1", ".msi", ".jar", ".lnk", ".iso", ".img", ".hta", ".html",
    ".htm", ".docm", ".xlsm", ".pptm", ".zip", ".rar", ".7z",
}

# brand -> domains that legitimately send for it
BRANDS = {
    "microsoft": ["microsoft.com", "office.com", "outlook.com", "live.com",
                  "microsoftonline.com", "office365.com"],
    "google": ["google.com", "gmail.com", "youtube.com"],
    "paypal": ["paypal.com"],
    "amazon": ["amazon.com", "amazon.in", "amazonses.com"],
    "apple": ["apple.com", "icloud.com"],
    "netflix": ["netflix.com"],
    "facebook": ["facebook.com", "facebookmail.com", "meta.com"],
    "linkedin": ["linkedin.com"],
    "dhl": ["dhl.com"],
    "fedex": ["fedex.com"],
}

LOOKALIKE = str.maketrans({"0": "o", "1": "l", "3": "e", "5": "s", "@": "a", "$": "s"})


class _LinkParser(HTMLParser):
    """Collects (href, visible text) pairs from HTML."""

    def __init__(self):
        super().__init__()
        self.links = []
        self._href = None
        self._text = []

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            self._href = dict(attrs).get("href")
            self._text = []

    def handle_data(self, data):
        if self._href is not None:
            self._text.append(data)

    def handle_endtag(self, tag):
        if tag == "a" and self._href is not None:
            self.links.append((self._href, " ".join("".join(self._text).split())))
            self._href = None


def _domain_of_url(url):
    url = url.strip()
    url = re.sub(r"^https?://", "", url, flags=re.IGNORECASE)
    return url.split("/")[0].split("@")[-1].split(":")[0].lower().rstrip(".")


def _auth_value(text, protocol):
    match = re.search(rf"\b{protocol}\s*=\s*([a-z]+)", text.lower())
    return match.group(1) if match else None


def _is_public_ip(ip):
    try:
        a, b, _, _ = (int(x) for x in ip.split("."))
    except ValueError:
        return False
    if any(int(x) > 255 for x in ip.split(".")):
        return False
    if a in (10, 127, 0) or (a == 172 and 16 <= b <= 31):
        return False
    if (a == 192 and b == 168) or (a == 169 and b == 254):
        return False
    return True


def analyze_email_lite(file_bytes):
    msg = BytesParser(policy=policy.default).parsebytes(file_bytes)

    findings = []

    def add(severity, description, source=None):
        findings.append({
            "finding_id": f"F{len(findings) + 1:03d}",
            "severity": severity,
            "description": description,
            "source": source,
        })

    # ---------------- addresses ----------------
    display_name, from_addr = parseaddr(str(msg.get("From", "")))
    from_domain = from_addr.split("@")[-1].lower() if "@" in from_addr else ""

    def domain_header(name):
        _, addr = parseaddr(str(msg.get(name, "")))
        return addr.split("@")[-1].lower() if "@" in addr else ""

    reply_domain = domain_header("Reply-To")
    return_domain = domain_header("Return-Path")

    # ---------------- authentication ----------------
    auth_text = " ".join(str(v) for v in msg.get_all("Authentication-Results", []))
    spf_header = str(msg.get("Received-SPF", ""))

    authentication = {
        "SPF": _auth_value(auth_text, "spf")
        or (spf_header.split()[0].lower() if spf_header else "not present"),
        "DKIM": _auth_value(auth_text, "dkim") or "not present",
        "DMARC": _auth_value(auth_text, "dmarc") or "not present",
    }

    for name, value in authentication.items():
        if value in ("fail", "softfail", "permerror", "temperror"):
            add("high", f"{name} check result: {value}", "Authentication-Results")

    # ---------------- routing ----------------
    received = [str(v) for v in msg.get_all("Received", [])]
    ips = []
    for hop in received:
        for ip in IP_RE.findall(hop):
            if ip not in ips:
                ips.append(ip)

    public_ips = [ip for ip in ips if _is_public_ip(ip)]

    routing = {
        "hop_count": len(received),
        "origin_ip (earliest hop)": public_ips[-1] if public_ips else "not found",
        "all_ips": ", ".join(ips) or "none",
        "from_domain": from_domain or "not present",
        "reply_to_domain": reply_domain or "not present",
        "return_path_domain": return_domain or "not present",
    }

    if not received:
        add("medium", "No Received headers found - message path cannot be verified", "Received")

    if reply_domain and from_domain and reply_domain != from_domain:
        add("medium",
            f"Reply-To domain ({reply_domain}) differs from sender domain ({from_domain})",
            "Reply-To")

    if return_domain and from_domain and return_domain != from_domain:
        add("medium",
            f"Return-Path domain ({return_domain}) differs from sender domain ({from_domain})",
            "Return-Path")

    # ---------------- brand look-alike ----------------
    name_lower = display_name.lower()
    domain_normalised = from_domain.translate(LOOKALIKE)

    for brand, official in BRANDS.items():
        is_official = any(
            from_domain == d or from_domain.endswith("." + d) for d in official
        )
        if is_official:
            continue
        if brand in name_lower or brand in domain_normalised:
            add("high",
                f"Sender presents as '{brand}' but the domain is '{from_domain}', "
                f"which is not an official {brand} domain",
                "From")
            break

    # ---------------- date ----------------
    timeline = []
    date_header = msg.get("Date")

    if not date_header:
        add("low", "Date header is missing", "Date")
    else:
        try:
            parsedate_to_datetime(str(date_header))
        except Exception:
            add("low", "Date header could not be parsed", "Date")

    # ---------------- bodies, URLs, attachments ----------------
    html_bodies, text_bodies, attachments = [], [], []

    for part in msg.walk():
        if part.is_multipart():
            continue

        filename = part.get_filename()
        disposition = part.get_content_disposition()
        content_type = part.get_content_type()

        if filename or disposition == "attachment":
            payload = part.get_payload(decode=True) or b""
            attachments.append({
                "filename": filename or "(unnamed)",
                "content_type": content_type,
                "size": len(payload),
                "sha256": hashlib.sha256(payload).hexdigest(),
            })
            continue

        try:
            content = part.get_content()
        except Exception:
            continue

        if content_type == "text/html":
            html_bodies.append(str(content))
        elif content_type == "text/plain":
            text_bodies.append(str(content))

    for item in attachments:
        lower = item["filename"].lower()
        ext = "." + lower.rsplit(".", 1)[-1] if "." in lower else ""
        if ext in RISKY_EXTENSIONS:
            add("high", f"Attachment '{item['filename']}' has a risky file type ({ext})", "Attachment")
        if re.search(r"\.(pdf|docx?|xlsx?|jpg|png|txt)\.(exe|scr|js|vbs|bat|cmd|lnk|html?)$", lower):
            add("high", f"Attachment '{item['filename']}' uses a double extension", "Attachment")

    urls = []
    link_pairs = []

    for body in html_bodies:
        parser = _LinkParser()
        try:
            parser.feed(body)
        except Exception:
            pass
        link_pairs.extend(parser.links)

    for body in html_bodies + text_bodies:
        for url in URL_RE.findall(body):
            clean = url.rstrip(".,);]>\"'")
            if clean not in urls:
                urls.append(clean)

    for href, _ in link_pairs:
        if href and href.lower().startswith(("http", "www")) and href not in urls:
            urls.append(href)

    for href, text in link_pairs:
        shown = URL_RE.search(text or "")
        if shown and href:
            if _domain_of_url(shown.group(0)) != _domain_of_url(href):
                add("high",
                    f"Link text shows '{_domain_of_url(shown.group(0))}' but points to "
                    f"'{_domain_of_url(href)}'",
                    "HTML link")

    for url in urls:
        domain = _domain_of_url(url)
        if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", domain):
            add("high", f"URL uses a raw IP address: {url[:80]}", "URL")
        elif domain and from_domain and domain != from_domain and not domain.endswith("." + from_domain):
            pass  # different domains are common (CDNs, trackers); not flagged alone

    # ---------------- timeline ----------------
    def add_event(timestamp_text, event, details):
        try:
            when = parsedate_to_datetime(timestamp_text)
            timeline.append({"timestamp": when.isoformat(), "event": event, "details": details, "_t": when})
        except Exception:
            timeline.append({"timestamp": timestamp_text or "unknown", "event": event, "details": details, "_t": None})

    for index, hop in enumerate(received, start=1):
        stamp = hop.rsplit(";", 1)[-1].strip() if ";" in hop else ""
        short = " ".join(hop.split())[:140]
        add_event(stamp, f"Received hop {index}", short)

    if date_header:
        add_event(str(date_header), "Date header (claimed by sender)", f"From: {from_addr}")

    timeline.sort(key=lambda e: (e["_t"] is None, e["_t"].timestamp() if e["_t"] else 0))

    for event in timeline:
        event.pop("_t", None)

    return {
        "authentication": authentication,
        "routing": routing,
        "urls": urls,
        "attachments": attachments,
        "timeline": timeline,
        "forensic_findings": findings,
        "engine": "forensics_lite",
    }
