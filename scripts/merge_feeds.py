import csv, io, os, re, requests, sys

# AWS Access Key IDs and Secret Access Keys (common patterns)
AWS_AKID_RE   = re.compile(r'(?:AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA)[0-9A-Z]{16}')
AWS_SAK_RE    = re.compile(r'(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])')

def looks_like_secret(s: str) -> bool:
    return bool(AWS_AKID_RE.search(s) or AWS_SAK_RE.search(s))

#!/usr/bin/env python3
import csv, io, re, requests, sys
from urllib.parse import urlparse

# ---- SOURCE LISTS ----
FEEDS = {
    "ips": [
        "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt",
        "http://cinsscore.com/list/ci-badguys.txt",
        "https://lists.blocklist.de/lists/all.txt",
    ],
    "domains": [
        "https://urlhaus.abuse.ch/downloads/hostfile/",
        "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
    ],
    "urls": [
        "https://urlhaus.abuse.ch/downloads/text/",
        "https://data.phishtank.com/data/online-valid.csv",
    ],
}

TIMEOUT = 40
IPV4_RE = re.compile(r"^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)$")
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?!-)(?:[a-z0-9-]{1,63}(?<!-)\.)+[a-z]{2,63}$", re.I)

# ---------- helpers ----------

def fetch(url: str) -> str:
    r = requests.get(url, timeout=TIMEOUT)
    r.raise_for_status()
    return r.text.replace("\r", "")

def fetch_threatfox() -> tuple[set[str], set[str], set[str]]:
    auth_key = os.environ.get("THREATFOX_AUTH_KEY")

    if not auth_key:
        raise RuntimeError("THREATFOX_AUTH_KEY is not configured")

    headers = {
        "Auth-Key": auth_key,
        "Content-Type": "application/json",
    }

    payload = {
        "query": "get_iocs",
        "days": 7,
    }

    r = requests.post(
        "https://threatfox-api.abuse.ch/api/v1/",
        headers=headers,
        json=payload,
        timeout=TIMEOUT,
    )

    r.raise_for_status()
    data = r.json()

    if data.get("query_status") != "ok":
        raise RuntimeError(
            f"ThreatFox API returned status: {data.get('query_status')}"
        )

    tf_ips = set()
    tf_domains = set()
    tf_urls = set()

    for item in data.get("data", []):
        ioc = str(item.get("ioc", "")).strip()
        ioc_type = str(item.get("ioc_type", "")).lower()

        if not ioc:
            continue

        if ioc_type == "domain":
            domain = normalize_domain(ioc)
            if domain:
                tf_domains.add(domain)

        elif ioc_type == "url":
            if ioc.startswith(("http://", "https://")):
                tf_urls.add(ioc)

        elif ioc_type == "ip:port":
            ip = ioc.rsplit(":", 1)[0]
            if IPV4_RE.match(ip):
                tf_ips.add(ip)

    return tf_ips, tf_domains, tf_urls

def suffix_match(domain: str, wl: set[str]) -> bool:
    """Return True if domain equals or is a subdomain of any whitelist entry."""
    d = domain.lower()
    for w in wl:
        w = w.lower()
        if d == w or d.endswith("." + w):
            return True
    return False

def load_whitelist(path: str = "whitelist.txt") -> set[str]:
    try:
        raw = open(path, "r", encoding="utf-8").read().splitlines()
    except FileNotFoundError:
        return set()
    out = set()
    for line in raw:
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        # strip possible leading "*."
        if s.startswith("*."):
            s = s[2:]
        # drop trailing dot
        s = s.rstrip(".")
        if DOMAIN_RE.match(s):
            out.add(s.lower())
    return out

def domain_from_url(u: str) -> str | None:
    try:
        p = urlparse(u)
        host = p.netloc.lower()
        if not host:
            return None
        # strip port if present
        if ":" in host:
            host = host.split(":")[0]
        # strip leading wildcard/dots
        host = host.lstrip(".")
        return host if DOMAIN_RE.match(host) else None
    except Exception:
        return None

# ---------- cleaners ----------

def clean_ips(text: str) -> set[str]:
    out = set()
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith(("#",";")):
            continue
        token = line.split()[0]
        if IPV4_RE.match(token):
            out.add(token)
    return out

def normalize_domain(token: str) -> str | None:
    token = token.strip().lower()
    if token.startswith(("http://","https://")):
        return None  # domains file must NOT contain URLs
    token = token.lstrip(".")
    token = token.replace("*.", "")
    token = token.split("/")[0]
    token = token.split("#")[0]
    token = token.split()[0]
    if token.startswith("0.0.0.0 ") or token.startswith("127.0.0.1 "):
        token = token.split()[-1]
    if ":" in token:
        return None
    return token if DOMAIN_RE.match(token) else None

def clean_domains(text: str) -> set[str]:
    out = set()

    for raw in text.splitlines():
        raw = raw.strip()

        if not raw or raw.startswith(("#", ";")):
            continue

        parts = raw.split()

        # Hosts-file format:
        # 127.0.0.1 example.com
        # 0.0.0.0 example.com
        if len(parts) >= 2 and parts[0] in ("0.0.0.0", "127.0.0.1"):
            raw = parts[1]

        dom = normalize_domain(raw)

        if dom:
            out.add(dom)

    return out

def clean_urls(text: str, source: str) -> set[str]:
    out = set()
    if urlparse(source).hostname == "data.phishtank.com":
        reader = csv.reader(io.StringIO(text))
        next(reader, None)
        for row in reader:
            if len(row) >= 2:
                url = row[1].strip().strip('"')
                if url.startswith(("http://","https://")):
                    out.add(url)
        return out

    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith(("#",";")):
            continue
        if line.startswith(("http://","https://")):
            out.add(line)
            continue
        # malc0de BOOT sometimes lists bare domains; make them URLs
        maybe_dom = normalize_domain(line)
        if maybe_dom:
            out.add("http://" + maybe_dom)
    return out

# ---------- main ----------

def main():
    wl = load_whitelist()
    print(f"WHITELIST DOMAINS LOADED: {len(wl)}", file=sys.stderr)

    ips, domains, urls = set(), set(), set()

    total_sources = (
        len(FEEDS["ips"])
        + len(FEEDS["domains"])
        + len(FEEDS["urls"])
    )
    successful_sources = 0
    failed_sources = 0

    print("\n=== SOURCE STATUS ===")


        # ---- ThreatFox ----
    try:
        tf_ips, tf_domains, tf_urls = fetch_threatfox()

        ips |= tf_ips
        domains |= tf_domains
        urls |= tf_urls

        successful_sources += 1
        total_sources += 1

        print(
            f"[OK]   THREATFOX "
            f"IPs:{len(tf_ips)} "
            f"Domains:{len(tf_domains)} "
            f"URLs:{len(tf_urls)}"
        )

    except Exception as e:
        failed_sources += 1
        total_sources += 1

        print(
            f"[FAIL] THREATFOX {e}",
            file=sys.stderr,
        )

    # ---- IP feeds ----
    for u in FEEDS["ips"]:
        try:
            parsed = clean_ips(fetch(u))
            ips |= parsed
            successful_sources += 1
            print(
                f"[OK]   IP      {urlparse(u).hostname:<35} "
                f"{len(parsed):>8} indicators"
            )
        except Exception as e:
            failed_sources += 1
            print(
                f"[FAIL] IP      {urlparse(u).hostname:<35} {e}",
                file=sys.stderr,
            )

    # ---- Domain feeds ----
    for u in FEEDS["domains"]:
        try:
            parsed = clean_domains(fetch(u))
            domains |= parsed
            successful_sources += 1
            print(
                f"[OK]   DOMAIN  {urlparse(u).hostname:<35} "
                f"{len(parsed):>8} indicators"
            )
        except Exception as e:
            failed_sources += 1
            print(
                f"[FAIL] DOMAIN  {urlparse(u).hostname:<35} {e}",
                file=sys.stderr,
            )

    # ---- URL feeds ----
    for u in FEEDS["urls"]:
        try:
            parsed = clean_urls(fetch(u), u)
            urls |= parsed
            successful_sources += 1
            print(
                f"[OK]   URL     {urlparse(u).hostname:<35} "
                f"{len(parsed):>8} indicators"
            )
        except Exception as e:
            failed_sources += 1
            print(
                f"[FAIL] URL     {urlparse(u).hostname:<35} {e}",
                file=sys.stderr,
            )

    # ---- apply whitelist ----
    domains_before = len(domains)
    domains = {d for d in domains if not suffix_match(d, wl)}
    domains_removed = domains_before - len(domains)

    urls_before = len(urls)
    filtered_urls = set()

    for u in urls:
        host = domain_from_url(u)
        if host and suffix_match(host, wl):
            continue
        filtered_urls.add(u)

    urls_removed = urls_before - len(filtered_urls)
    urls = filtered_urls

    # ---- safety checks ----
    MIN_IPS = 1000
    MIN_DOMAINS = 5000
    MIN_URLS = 5000

    print("\n=== SOURCE SUMMARY ===")
    print(
        f"Successful sources: {successful_sources}/{total_sources}"
    )
    print(f"Failed sources:     {failed_sources}/{total_sources}")

    print("\n=== FINAL COUNTS ===")
    print(f"IPs:     {len(ips)}")
    print(
        f"Domains: {len(domains)} "
        f"(-{domains_removed} whitelisted)"
    )
    print(
        f"URLs:    {len(urls)} "
        f"(-{urls_removed} whitelisted)"
    )

    if len(ips) < MIN_IPS:
        raise RuntimeError(
            f"Safety check failed: only {len(ips)} IP indicators generated"
        )

    if len(domains) < MIN_DOMAINS:
        raise RuntimeError(
            f"Safety check failed: only {len(domains)} domain indicators generated"
        )

    if len(urls) < MIN_URLS:
        raise RuntimeError(
            f"Safety check failed: only {len(urls)} URL indicators generated"
        )

    # ---- write outputs ----
    with open("docs/ips.txt", "w", encoding="utf-8", newline="\n") as f:
        for x in sorted(ips):
            f.write(x + "\n")

    with open("docs/domains.txt", "w", encoding="utf-8", newline="\n") as f:
        for x in sorted(domains):
            f.write(x + "\n")

    with open("docs/urls.txt", "w", encoding="utf-8", newline="\n") as f:
        for x in sorted(urls):
            f.write(x + "\n")

    print("\nSAFETY CHECKS: PASSED")
    print("Feed files written successfully.")


if __name__ == "__main__":
    main()
