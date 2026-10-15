"""
Email header feature extraction.

This is the EXACT feature code used when the XGBoost model was trained
(sliced out of train_model.py). The model only works correctly if serving
uses the same feature logic as training.
"""

import re

import pandas as pd

from email import policy
from email.parser import Parser
from email.utils import parseaddr, parsedate_to_datetime


# ============================================================
# SUSPICIOUS HEADER KEYWORDS
# ============================================================

SUSPICIOUS_KEYWORDS = [
    "forged",
    "spoof",
    "x-spam",
    "x-spam-status",
    "x-spam-flag",
    "authentication-failure",
    "authentication failed",
]


# ============================================================
# DOMAIN EXTRACTION
# ============================================================

def extract_domain(value):
    """
    Extract a domain from an email/header value.

    Examples:

    person@example.com
        -> example.com

    <person@example.com>
        -> example.com

    Empty value
        -> ""
    """

    if value is None:
        return ""

    try:
        value = str(value).strip().lower()
    except Exception:
        return ""

    if not value:
        return ""

    # Normal email address
    _, address = parseaddr(value)

    if "@" in address:

        domain = address.rsplit(
            "@",
            1
        )[1]

        domain = domain.strip()
        domain = domain.strip("<>")
        domain = domain.rstrip(".")

        return domain

    # If it isn't a normal email address,
    # remove brackets if present.
    value = value.strip("<>")
    value = value.rstrip(".")

    return value


# ============================================================
# IP ADDRESS CHECK
# ============================================================

def is_ip_address(value):
    """
    Check whether a value is an IPv4 address.
    """

    if not value:
        return 0

    pattern = (
        r"^(?:"
        r"(?:25[0-5]|2[0-4][0-9]|"
        r"1[0-9][0-9]|"
        r"[1-9]?[0-9])\."
        r"){3}"
        r"(?:25[0-5]|2[0-4][0-9]|"
        r"1[0-9][0-9]|"
        r"[1-9]?[0-9])$"
    )

    return int(
        re.match(
            pattern,
            str(value)
        )
        is not None
    )


# ============================================================
# PUBLIC IPv4 CHECK
# ============================================================

def is_public_ipv4(ip):
    """
    Check whether an IPv4 address is public.

    Private, loopback and link-local
    addresses are not considered public.
    """

    if not ip:
        return False

    try:

        parts = ip.split(".")

        if len(parts) != 4:
            return False

        numbers = [
            int(part)
            for part in parts
        ]

        if any(
            number < 0 or number > 255
            for number in numbers
        ):
            return False

        a, b, c, d = numbers

        # Private: 10.0.0.0/8
        if a == 10:
            return False

        # Private: 172.16.0.0/12
        if (
            a == 172
            and 16 <= b <= 31
        ):
            return False

        # Private: 192.168.0.0/16
        if (
            a == 192
            and b == 168
        ):
            return False

        # Loopback: 127.0.0.0/8
        if a == 127:
            return False

        # Link-local: 169.254.0.0/16
        if (
            a == 169
            and b == 254
        ):
            return False

        return True

    except Exception:
        return False


# ============================================================
# RECEIVED IP EXTRACTION
# ============================================================

def extract_received_ips(
    received_headers
):
    """
    Extract IPv4 addresses from
    Received headers.
    """

    ips = []

    ip_pattern = (
        r"\b(?:"
        r"(?:25[0-5]|2[0-4][0-9]|"
        r"1[0-9][0-9]|"
        r"[1-9]?[0-9])\."
        r"){3}"
        r"(?:25[0-5]|2[0-4][0-9]|"
        r"1[0-9][0-9]|"
        r"[1-9]?[0-9])\b"
    )

    for header in received_headers:

        if not header:
            continue

        matches = re.findall(
            ip_pattern,
            str(header)
        )

        for ip in matches:

            if ip not in ips:
                ips.append(ip)

    return ips


# ============================================================
# AUTHENTICATION STATUS
# ============================================================

def extract_authentication_status(
    authentication_results
):
    """
    Extract SPF, DKIM and DMARC results.
    """

    text = " ".join(
        str(value)
        for value in authentication_results
    ).lower()

    spf_status = "unknown"
    dkim_status = "unknown"
    dmarc_status = "unknown"

    # --------------------------------------------------------
    # SPF
    # --------------------------------------------------------

    spf_match = re.search(
        r"\bspf\s*=\s*"
        r"(pass|fail|softfail|neutral|"
        r"none|temperror|permerror)",
        text
    )

    if spf_match:
        spf_status = (
            spf_match.group(1)
        )

    # --------------------------------------------------------
    # DKIM
    # --------------------------------------------------------

    dkim_match = re.search(
        r"\bdkim\s*=\s*"
        r"(pass|fail|neutral|"
        r"none|temperror|permerror)",
        text
    )

    if dkim_match:
        dkim_status = (
            dkim_match.group(1)
        )

    # --------------------------------------------------------
    # DMARC
    # --------------------------------------------------------

    dmarc_match = re.search(
        r"\bdmarc\s*=\s*"
        r"(pass|fail|"
        r"bestguesspass|"
        r"none|temperror|permerror)",
        text
    )

    if dmarc_match:
        dmarc_status = (
            dmarc_match.group(1)
        )

    return (
        spf_status,
        dkim_status,
        dmarc_status
    )


# ============================================================
# FEATURE EXTRACTION
# ============================================================

def extract_features(
    raw_email
):
    """
    Extract machine-learning features
    from a complete raw email.
    """

    # --------------------------------------------------------
    # Clean input
    # --------------------------------------------------------

    if raw_email is None:
        raw_email = ""

    if pd.isna(raw_email):
        raw_email = ""

    raw_email = str(
        raw_email
    )

    # --------------------------------------------------------
    # Parse raw email
    # --------------------------------------------------------

    try:

        message = Parser(
            policy=policy.default
        ).parsestr(
            raw_email
        )

    except Exception:

        message = None

    # --------------------------------------------------------
    # Read headers
    # --------------------------------------------------------

    if message is not None:

        from_value = message.get(
            "From",
            ""
        )

        reply_to_value = message.get(
            "Reply-To",
            ""
        )

        return_path_value = message.get(
            "Return-Path",
            ""
        )

        message_id_value = message.get(
            "Message-ID",
            ""
        )

        date_value = message.get(
            "Date",
            ""
        )

        authentication_results = (
            message.get_all(
                "Authentication-Results",
                []
            )
        )

        received_headers = (
            message.get_all(
                "Received",
                []
            )
        )

    else:

        from_value = ""
        reply_to_value = ""
        return_path_value = ""
        message_id_value = ""
        date_value = ""

        authentication_results = []
        received_headers = []

    # --------------------------------------------------------
    # Extract domains
    # --------------------------------------------------------

    sender_domain = extract_domain(
        from_value
    )

    reply_to_domain = extract_domain(
        reply_to_value
    )

    return_path_domain = extract_domain(
        return_path_value
    )

    message_id_domain = extract_domain(
        message_id_value
    )

    # --------------------------------------------------------
    # Header existence
    # --------------------------------------------------------

    has_from = int(
        bool(from_value)
    )

    has_reply_to = int(
        bool(reply_to_value)
    )

    has_return_path = int(
        bool(return_path_value)
    )

    has_message_id = int(
        bool(message_id_value)
    )

    has_date = int(
        bool(date_value)
    )

    has_authentication_results = int(
        bool(authentication_results)
    )

    # --------------------------------------------------------
    # Domain mismatch checks
    # --------------------------------------------------------

    sender_replyto_mismatch = int(
        bool(
            sender_domain
            and reply_to_domain
            and sender_domain
            != reply_to_domain
        )
    )

    sender_returnpath_mismatch = int(
        bool(
            sender_domain
            and return_path_domain
            and sender_domain
            != return_path_domain
        )
    )

    message_id_sender_mismatch = int(
        bool(
            sender_domain
            and message_id_domain
            and sender_domain
            != message_id_domain
        )
    )

    # --------------------------------------------------------
    # SPF / DKIM / DMARC
    # --------------------------------------------------------

    (
        spf_status,
        dkim_status,
        dmarc_status
    ) = extract_authentication_status(
        authentication_results
    )

    # --------------------------------------------------------
    # Count authentication failures
    # --------------------------------------------------------

    authentication_failures = 0

    authentication_statuses = [
        spf_status,
        dkim_status,
        dmarc_status
    ]

    for status in authentication_statuses:

        if status in [
            "fail",
            "softfail",
            "permerror",
            "temperror"
        ]:

            authentication_failures += 1

    # --------------------------------------------------------
    # Received headers
    # --------------------------------------------------------

    received_count = len(
        received_headers
    )

    received_ips = (
        extract_received_ips(
            received_headers
        )
    )

    received_ip_count = len(
        received_ips
    )

    received_public_ip_count = sum(
        1
        for ip in received_ips
        if is_public_ipv4(ip)
    )

    # --------------------------------------------------------
    # Validate date
    # --------------------------------------------------------

    date_valid = 0

    if date_value:

        try:

            parsedate_to_datetime(
                str(date_value)
            )

            date_valid = 1

        except Exception:

            date_valid = 0

    # --------------------------------------------------------
    # Header statistics
    # --------------------------------------------------------

    header_lines = []

    for line in raw_email.splitlines():

        # Header line
        if ":" in line:

            header_lines.append(
                line
            )

        # First non-header line means body started
        elif header_lines:

            break

    header_line_count = len(
        header_lines
    )

    header_length = len(
        "\n".join(
            header_lines
        )
    )

    # --------------------------------------------------------
    # Suspicious keywords
    # --------------------------------------------------------

    raw_lower = raw_email.lower()

    suspicious_keyword_count = 0

    for keyword in SUSPICIOUS_KEYWORDS:

        suspicious_keyword_count += (
            raw_lower.count(
                keyword
            )
        )

    # --------------------------------------------------------
    # Domain lengths
    # --------------------------------------------------------

    sender_domain_length = len(
        sender_domain
    )

    reply_to_domain_length = len(
        reply_to_domain
    )

    return_path_domain_length = len(
        return_path_domain
    )

    # --------------------------------------------------------
    # Domain IP checks
    # --------------------------------------------------------

    sender_domain_is_ip = (
        is_ip_address(
            sender_domain
        )
    )

    reply_to_domain_is_ip = (
        is_ip_address(
            reply_to_domain
        )
    )

    return_path_domain_is_ip = (
        is_ip_address(
            return_path_domain
        )
    )

    # --------------------------------------------------------
    # Return complete feature dictionary
    # --------------------------------------------------------

    return {

        # Categorical
        "sender_domain": sender_domain,

        "reply_to_domain": reply_to_domain,

        "return_path_domain": (
            return_path_domain
        ),

        "message_id_domain": (
            message_id_domain
        ),

        "spf_status": spf_status,

        "dkim_status": dkim_status,

        "dmarc_status": dmarc_status,

        # Header existence
        "has_from": has_from,

        "has_reply_to": has_reply_to,

        "has_return_path": (
            has_return_path
        ),

        "has_message_id": (
            has_message_id
        ),

        "has_date": has_date,

        "has_authentication_results": (
            has_authentication_results
        ),

        # Mismatch
        "sender_replyto_mismatch": (
            sender_replyto_mismatch
        ),

        "sender_returnpath_mismatch": (
            sender_returnpath_mismatch
        ),

        "message_id_sender_mismatch": (
            message_id_sender_mismatch
        ),

        # Authentication
        "authentication_failures": (
            authentication_failures
        ),

        # Received
        "received_count": (
            received_count
        ),

        "received_ip_count": (
            received_ip_count
        ),

        "received_public_ip_count": (
            received_public_ip_count
        ),

        # Date
        "date_valid": date_valid,

        # Header statistics
        "header_line_count": (
            header_line_count
        ),

        "header_length": (
            header_length
        ),

        # Suspicious
        "suspicious_keyword_count": (
            suspicious_keyword_count
        ),

        # Domain lengths
        "sender_domain_length": (
            sender_domain_length
        ),

        "reply_to_domain_length": (
            reply_to_domain_length
        ),

        "return_path_domain_length": (
            return_path_domain_length
        ),

        # Domain IP
        "sender_domain_is_ip": (
            sender_domain_is_ip
        ),

        "reply_to_domain_is_ip": (
            reply_to_domain_is_ip
        ),

        "return_path_domain_is_ip": (
            return_path_domain_is_ip
        ),
    }


