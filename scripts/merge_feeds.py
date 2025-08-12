#!/usr/bin/env python3
import csv, io, re, requests, sys
from urllib.parse import urlparse

# ---- SOURCE LISTS ----
FEEDS = {
    "ips": [
        "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt",
        "http://cinsscore.com/list/ci-badguys.txt",
        "https://lists.blocklist.de/lists/all.txt",
        "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset",
    ],
    "domains": [
        "https://urlhaus.abuse.ch/downloads/hostfile/",
        "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
        "https://mirror1.malwaredomains.com/files/justdomains",
    ],
    "urls": [
        "https://urlhaus.abuse.ch/downloads/text/",
        "http://data.phishtank.com/data/online-valid.csv",
        "http://malc0de.com/bl/BOOT",
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
        if not raw or raw.startswith(("#",";")):
            continue
        if raw.startswith(("0.0.0.0 ", "127.0.0.1 ")):
            raw = raw.split(maxsplit=1)[1]
        dom = normalize_domain(raw)
        if dom:
            out.add(dom)
    return out

def clean_urls(text: str, source: str) -> set[str]:
    out = set()
    if "phishtank.com" in source:
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

    for u in FEEDS["ips"]:
        try:
            ips |= clean_ips(fetch(u))
        except Exception as e:
            print(f"[IP] {u} -> {e}", file=sys.stderr)

    for u in FEEDS["domains"]:
        try:
            domains |= clean_domains(fetch(u))
        except Exception as e:
            print(f"[DOMAIN] {u} -> {e}", file=sys.stderr)

    for u in FEEDS["urls"]:
        try:
            urls |= clean_urls(fetch(u), u)
        except Exception as e:
            print(f"[URL] {u} -> {e}", file=sys.stderr)

    # ---- apply whitelist (suffix match) ----
    domains_before = len(domains)
    domains = {d for d in domains if not suffix_match(d, wl)}
    domains_removed = domains_before - len(domains)

    urls_before = len(urls)
    filtered_urls = set()
    for u in urls:
        host = domain_from_url(u)
        if host and suffix_match(host, wl):
            continue  # skip this URL (whitelisted)
        filtered_urls.add(u)
    urls_removed = urls_before - len(filtered_urls)
    urls = filtered_urls

    # ---- write outputs in docs/ ----
    with open("docs/ips.txt", "w", encoding="utf-8", newline="\n") as f:
        for x in sorted(ips):
            f.write(x + "\n")

    with open("docs/domains.txt", "w", encoding="utf-8", newline="\n") as f:
        for x in sorted(domains):
            f.write(x + "\n")

    with open("docs/urls.txt", "w", encoding="utf-8", newline="\n") as f:
        for x in sorted(urls):
            f.write(x + "\n")

    print(f"FINAL COUNTS → IPs:{len(ips)}  Domains:{len(domains)} (-{domains_removed})  URLs:{len(urls)} (-{urls_removed})")

if __name__ == "__main__":
    main()
