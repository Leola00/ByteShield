"""Extract the 66 URL features used by phishing_dl_model.h5.

Matches the GregaVrbancic / lucasayres url-feature-extractor pipeline:
- URL body = host + path + params + query + fragment (no scheme)
- Missing path/query sections use -1
- Failed network/WHOIS lookups use -1
- qty_tld_url counts known TLD matches in the URL body
"""

from __future__ import annotations

import ipaddress
import posixpath
import re
import socket
import ssl
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import dns.resolver
import requests
import whois

MISSING = -1.0
TLD_FILE = Path(__file__).resolve().parent / "tlds.txt"
EMAIL_RE = re.compile(r"[\w\.-]+@[\w\.-]+")
SHORTENER_HOSTS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "rb.gy", "ow.ly",
    "is.gd", "buff.ly", "cutt.ly", "shorturl.at", "www.bit.ly",
}

FEATURE_NAMES = [
    "qty_dot_url", "qty_hyphen_url", "qty_underline_url", "qty_slash_url",
    "qty_questionmark_url", "qty_equal_url", "qty_at_url", "qty_and_url",
    "qty_exclamation_url", "qty_space_url", "qty_tilde_url", "qty_comma_url",
    "qty_plus_url", "qty_asterisk_url", "qty_hashtag_url", "qty_dollar_url",
    "qty_percent_url", "qty_tld_url", "length_url", "qty_dot_domain",
    "qty_hyphen_domain", "qty_underline_domain", "qty_at_domain",
    "qty_vowels_domain", "domain_length", "domain_in_ip", "server_client_domain",
    "qty_dot_directory", "qty_hyphen_directory", "qty_underline_directory",
    "qty_questionmark_directory", "qty_at_directory", "qty_asterisk_directory",
    "qty_percent_directory", "directory_length", "qty_dot_file", "qty_hyphen_file",
    "qty_underline_file", "qty_asterisk_file", "qty_percent_file", "file_length",
    "qty_dot_params", "qty_hyphen_params", "qty_underline_params", "qty_slash_params",
    "qty_questionmark_params", "qty_at_params", "qty_and_params",
    "qty_exclamation_params", "qty_percent_params", "params_length", "email_in_url",
    "time_response", "domain_spf", "asn_ip", "time_domain_activation",
    "time_domain_expiration", "qty_ip_resolved", "qty_nameservers", "qty_mx_servers",
    "ttl_hostname", "tls_ssl_certificate", "qty_redirects", "url_google_index",
    "domain_google_index", "url_shortened",
]


@lru_cache(maxsize=1)
def _load_tlds() -> tuple[str, ...]:
    if not TLD_FILE.exists():
        return (".com", ".org", ".net", ".gov", ".edu", ".sa", ".gov.sa")
    return tuple(line.strip().lower() for line in TLD_FILE.read_text(encoding="utf-8").splitlines() if line.strip())


def _count_tld(text: str) -> float:
    lowered = text.lower()
    pattern = re.compile(r"[a-zA-Z0-9.]")
    count = 0
    for tld in _load_tlds():
        start = lowered.find(tld)
        while start > -1:
            after = start + len(tld)
            if after >= len(lowered) or not pattern.match(lowered[after]):
                count += 1
            start = lowered.find(tld, start + 1)
    return float(count)


def _count_vowels(value: str) -> int:
    return sum(1 for ch in value.lower() if ch in "aeiou")


def _normalize_url(url: str) -> str:
    cleaned = url.strip()
    if not cleaned:
        raise ValueError("Empty URL")
    if not urlparse(cleaned).scheme:
        cleaned = f"http://{cleaned}"
    return cleaned


def _parse_url(url: str) -> dict[str, str]:
    """Match lucasayres start_url() structure."""
    parsed = urlparse(url.strip())
    host = parsed.netloc.split("@")[-1]
    if ":" in host and not host.startswith("["):
        host = host.rsplit(":", 1)[0]
    path = parsed.path or ""
    params = parsed.params or ""
    query = parsed.query or ""
    fragment = parsed.fragment or ""
    body = host + path + params + query + fragment
    return {
        "body": body,
        "scheme": parsed.scheme or "http",
        "host": host,
        "path": path,
        "params": params,
        "query": query,
        "fragment": fragment,
        "full": url,
    }


def _count_chars(value: str, char: str) -> float:
    return float(value.count(char))


def _section_counts(value: str, chars: str) -> dict[str, float]:
    return {char: _count_chars(value, char) for char in chars}


def _missing_section(length: int = 9) -> list[float]:
    return [MISSING] * length


def _domain_is_ip(host: str) -> float:
    try:
        ipaddress.ip_address(host.strip("[]"))
        return 1.0
    except ValueError:
        return 0.0


def _server_client_domain(host: str) -> float:
    lowered = host.lower()
    return 1.0 if "server" in lowered or "client" in lowered else 0.0


def _email_in_url(text: str) -> float:
    return 1.0 if EMAIL_RE.search(text) else 0.0


def _url_shortened(host: str) -> float:
    return 1.0 if host.lower() in SHORTENER_HOSTS or host.lower().replace("www.", "") in SHORTENER_HOSTS else 0.0


def _dns_count(host: str, record_type: str) -> float:
    try:
        answers = dns.resolver.resolve(host, record_type, lifetime=4)
        return float(len(list(answers)))
    except Exception:
        return MISSING


def _dns_ttl(host: str) -> float:
    try:
        answers = dns.resolver.resolve(host, "A", lifetime=4)
        return float(answers.rrset.ttl)
    except Exception:
        return MISSING


def _domain_spf(host: str) -> float:
    try:
        answers = dns.resolver.resolve(host, "TXT", lifetime=4)
        for answer in answers:
            if "v=spf1" in str(answer).lower():
                return 1.0
    except Exception:
        pass
    return 0.0


def _time_response(url: str) -> float:
    try:
        start = datetime.now(timezone.utc)
        requests.head(url, allow_redirects=False, timeout=5)
        return round((datetime.now(timezone.utc) - start).total_seconds(), 6)
    except Exception:
        return MISSING


def _asn_ip(host: str) -> float:
    try:
        socket.gethostbyname(host)
        return MISSING
    except Exception:
        return MISSING


def _domain_age_features(host: str) -> tuple[float, float]:
    try:
        record = whois.whois(host)
        created = record.creation_date
        expires = record.expiration_date
        if isinstance(created, list):
            created = created[0]
        if isinstance(expires, list):
            expires = expires[0]
        now = datetime.now(timezone.utc)
        activation = MISSING
        expiration = MISSING
        if created:
            if created.tzinfo is None:
                created = created.replace(tzinfo=timezone.utc)
            activation = round(max(0.0, (now - created).total_seconds() / 86400), 2)
        if expires:
            if expires.tzinfo is None:
                expires = expires.replace(tzinfo=timezone.utc)
            expiration = round(max(0.0, (expires - now).total_seconds() / 86400), 2)
        if activation == MISSING and expiration == MISSING:
            return MISSING, MISSING
        return activation, expiration
    except Exception:
        return MISSING, MISSING


def _tls_ssl_certificate(url: str) -> float:
    try:
        parsed = urlparse(url)
        if parsed.scheme != "https":
            return 0.0
        host = parsed.netloc.split(":")[0]
        context = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=host) as secure:
                return 1.0 if secure.getpeercert() else 0.0
    except Exception:
        return 0.0


def _count_redirects(url: str) -> float:
    try:
        response = requests.get(url, allow_redirects=True, timeout=8)
        return float(max(0, len(response.history)))
    except Exception:
        return MISSING


def extract_features(url: str) -> dict[str, float]:
    normalized = _normalize_url(url)
    parts = _parse_url(normalized)
    body = parts["body"]
    host = parts["host"]
    path = parts["path"]
    query = parts["query"]
    file_name = posixpath.basename(path) if path else ""

    url_chars = _section_counts(body, ".-_/?=&@! ~,+*#$%")
    domain_chars = _section_counts(host, ".-_@")

    features: dict[str, Any] = {
        "qty_dot_url": url_chars["."],
        "qty_hyphen_url": url_chars["-"],
        "qty_underline_url": url_chars["_"],
        "qty_slash_url": url_chars["/"],
        "qty_questionmark_url": url_chars["?"],
        "qty_equal_url": url_chars["="],
        "qty_at_url": url_chars["@"],
        "qty_and_url": url_chars["&"],
        "qty_exclamation_url": url_chars["!"],
        "qty_space_url": url_chars[" "],
        "qty_tilde_url": url_chars["~"],
        "qty_comma_url": url_chars[","],
        "qty_plus_url": url_chars["+"],
        "qty_asterisk_url": url_chars["*"],
        "qty_hashtag_url": url_chars["#"],
        "qty_dollar_url": url_chars["$"],
        "qty_percent_url": url_chars["%"],
        "qty_tld_url": _count_tld(body),
        "length_url": float(len(body)),
        "qty_dot_domain": domain_chars["."],
        "qty_hyphen_domain": domain_chars["-"],
        "qty_underline_domain": domain_chars["_"],
        "qty_at_domain": domain_chars["@"],
        "qty_vowels_domain": float(_count_vowels(host)),
        "domain_length": float(len(host)),
        "domain_in_ip": _domain_is_ip(host),
        "server_client_domain": _server_client_domain(host),
        "email_in_url": _email_in_url(body),
        "url_google_index": 0.0,
        "domain_google_index": 0.0,
        "url_shortened": _url_shortened(host),
        "domain_spf": _domain_spf(host),
        "tls_ssl_certificate": _tls_ssl_certificate(normalized),
    }

    if path:
        directory_chars = _section_counts(path, ".-_?@*%")
        features.update({
            "qty_dot_directory": directory_chars["."],
            "qty_hyphen_directory": directory_chars["-"],
            "qty_underline_directory": directory_chars["_"],
            "qty_questionmark_directory": directory_chars["?"],
            "qty_at_directory": directory_chars["@"],
            "qty_asterisk_directory": directory_chars["*"],
            "qty_percent_directory": directory_chars["%"],
            "directory_length": float(len(path)),
        })
        file_chars = _section_counts(file_name, ".-_?@*%")
        features.update({
            "qty_dot_file": file_chars["."],
            "qty_hyphen_file": file_chars["-"],
            "qty_underline_file": file_chars["_"],
            "qty_asterisk_file": file_chars["*"],
            "qty_percent_file": file_chars["%"],
            "file_length": float(len(file_name)),
        })
    else:
        keys = [
            "qty_dot_directory", "qty_hyphen_directory", "qty_underline_directory",
            "qty_questionmark_directory", "qty_at_directory", "qty_asterisk_directory",
            "qty_percent_directory", "directory_length",
            "qty_dot_file", "qty_hyphen_file", "qty_underline_file",
            "qty_asterisk_file", "qty_percent_file", "file_length",
        ]
        for key in keys:
            features[key] = MISSING

    if query:
        params_chars = _section_counts(query, ".-_/?=&@!%")
        features.update({
            "qty_dot_params": params_chars["."],
            "qty_hyphen_params": params_chars["-"],
            "qty_underline_params": params_chars["_"],
            "qty_slash_params": params_chars["/"],
            "qty_questionmark_params": params_chars["?"],
            "qty_at_params": params_chars["@"],
            "qty_and_params": params_chars["&"],
            "qty_exclamation_params": params_chars["!"],
            "qty_percent_params": params_chars["%"],
            "params_length": float(len(query)),
        })
    else:
        for key in [
            "qty_dot_params", "qty_hyphen_params", "qty_underline_params",
            "qty_slash_params", "qty_questionmark_params", "qty_at_params",
            "qty_and_params", "qty_exclamation_params", "qty_percent_params",
            "params_length",
        ]:
            features[key] = MISSING

    activation, expiration = _domain_age_features(host)
    features.update({
        "time_response": _time_response(f"{parts['scheme']}://{host}"),
        "asn_ip": _asn_ip(host),
        "time_domain_activation": activation,
        "time_domain_expiration": expiration,
        "qty_ip_resolved": _dns_count(host, "A"),
        "qty_nameservers": _dns_count(host, "NS"),
        "qty_mx_servers": _dns_count(host, "MX"),
        "ttl_hostname": _dns_ttl(host),
        "qty_redirects": _count_redirects(normalized),
    })

    return {name: float(features[name]) for name in FEATURE_NAMES}
