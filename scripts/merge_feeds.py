#!/usr/bin/env python3
import csv, io, re, requests, sys

# --- source lists to merge ---
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

TIMEOUT = 30
IPV4_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?!-)(?:[a-z0-9-]{1,63}\.)+[a-z]{2,63}$", re.I)

def fetch(url):
    r = requests.get(url, timeout=TIMEOUT)
    r.raise_for_status()
    return r.text

def clean_ips(text):
    out = set()
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith(("#",";")): continue
        token = line.split()[0]
        if IPV4_RE.match(token):
            octets = token.split(".")
            if all(o.isdigit() and 0 <= int(o) <= 255 for o in octets):
                out.add(token)
    return out

def clean_domains(text):
    out = set()
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith(("#",";")): continue
        for pref in ("0.0.0.0 ", "127.0.0.1 "):
            if line.startswith(pref):
                line = line[len(pref):].strip()
        line = line.split("#")[0].strip()
        domain = line.split()[0]
        if DOMAIN_RE.match(domain):
            out.add(domain.lower())
    return out

def clean_urls(text, source):
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
        if not line or line.startswith(("#",";")): continue
        if line.startswith(("http://","https://")):
            out.add(line)
        else:
            if DOMAIN_RE.match(line):
                out.add("http://" + line)
    return out

def main():
    ips, domains, urls = set(), set(), set()
    for u in FEEDS["ips"]:
        try: ips |= clean_ips(fetch(u))
        except Exception as e: print(f"[IP] {u} -> {e}", file=sys.stderr)
    for u in FEEDS["domains"]:
        try: domains |= clean_domains(fetch(u))
        except Exception as e: print(f"[DOMAIN] {u} -> {e}", file=sys.stderr)
    for u in FEEDS["urls"]:
        try: urls |= clean_urls(fetch(u), u)
        except Exception as e: print(f"[URL] {u} -> {e}", file=sys.stderr)

    with open("docs/ips.txt", "w") as f:
        for x in sorted(ips): f.write(x+"\n")
    with open("docs/domains.txt", "w") as f:
        for x in sorted(domains): f.write(x+"\n")
    with open("docs/urls.txt", "w") as f:
        for x in sorted(urls): f.write(x+"\n")

    print(f"IPs: {len(ips)}  Domains: {len(domains)}  URLs: {len(urls)}")

if __name__ == "__main__":
    main()
