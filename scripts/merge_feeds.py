#!/usr/bin/env python3
import csv, io, re, requests, sys

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

# IPv4 only (Sophos is pickier with v6 in some builds)
IPV4_RE = re.compile(r"^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)$")
DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)(?:[a-z0-9-]{1,63}(?<!-)\.)+[a-z]{2,63}$",
    re.I,
)

def fetch(url: str) -> str:
    r = requests.get(url, timeout=TIMEOUT)
    r.raise_for_status()
    # normalize newlines
    return r.text.replace("\r", "")

# ---------- CLEANERS ----------

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
    token = token.lstrip(".")       # .example.com -> example.com
    token = token.replace("*.", "") # *.example.com -> example.com
    token = token.split("/")[0]     # drop any accidental path
    token = token.split("#")[0]     # drop comments
    token = token.split()[0]        # first field only
    # strip hosts file prefixes
    if token.startswith("0.0.0.0 ") or token.startswith("127.0.0.1 "):
        token = token.split()[-1]
    # discard anything with spaces/ports
    if ":" in token:
        return None
    if DOMAIN_RE.match(token):
        return token
    return None

def clean_domains(text: str) -> set[str]:
    out = set()
    for raw in text.splitlines():
        raw = raw.strip()
        if not raw or raw.startswith(("#",";")):
            continue
        # hosts file formats: "0.0.0.0 domain" / "127.0.0.1 domain"
        if raw.startswith(("0.0.0.0 ", "127.0.0.1 ")):
            raw = raw.split(maxsplit=1)[1]
        dom = normalize_domain(raw)
        if dom:
            out.add(dom)
    return out

def clean_urls(text: str, source: str) -> set[str]:
    out = set()
    if "phishtank.com" in source:
        # CSV: url in second column
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
        # malc0de BOOT sometimes lists domains only -> convert to http
        maybe_dom = normalize_domain(line)
        if maybe_dom:
            out.add("http://" + maybe_dom)
    return out

# ---------- MAIN ----------

def main():
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

    # Write to docs/ exactly as Sophos expects
    with open("docs/ips.txt", "w", encoding="utf-8", newline="\n") as f:
        for x in sorted(ips): f.write(x + "\n")

    with open("docs/domains.txt", "w", encoding="utf-8", newline="\n") as f:
        for x in sorted(domains): f.write(x + "\n")

    with open("docs/urls.txt", "w", encoding="utf-8", newline="\n") as f:
        for x in sorted(urls): f.write(x + "\n")

    print(f"FINAL COUNTS → IPs:{len(ips)}  Domains:{len(domains)}  URLs:{len(urls)}")

if __name__ == "__main__":
    main()
