# Threat Feeds for Sophos Firewall

Public, merged, and regularly updated **Indicators of Compromise (IoCs)** ready for **Sophos Firewall** (and any product that accepts plain‑text IP / domain / URL feeds).

## 📌 Live Feeds (GitHub Pages)
| Feed | URL | Notes |
|---|---|---|
| **IPs** | https://shadeco92.github.io/threat-feeds/ips.txt | IPv4 addresses only |
| **Domains** | https://shadeco92.github.io/threat-feeds/domains.txt | FQDNs only (no scheme) |
| **URLs** | https://shadeco92.github.io/threat-feeds/urls.txt | http/https URLs only |

> Feeds are auto‑built by GitHub Actions every 6 hours and after manual runs.

---

## 🛠 How it works
- `scripts/merge_feeds.py` downloads from free OSINT sources, deduplicates, normalizes types, and applies a domain **whitelist** from `whitelist.txt`.
- Outputs are written as plain text and published to GitHub Pages by the workflow in `.github/workflows/build-feeds.yml`.
- Large URLs lists may contain strings that look like secrets; Push Protection is handled via Pages deploy and light redaction in the build step.

## 🔧 Using with Sophos Firewall
1. Go to **System → Profiles → Threat Feeds**.
2. Add a feed for each list above and choose the correct **type**:
   - `ips.txt` → **IP address**
   - `domains.txt` → **Domain**
   - `urls.txt` → **URL**
3. Attach the feeds to your firewall rules / web policies.

## ✅ Whitelist
Put safe/business‑critical domains (one per line) in `whitelist.txt` (e.g., security tools, monitoring, analytics you use). The build excludes those domains and any URLs under them.

## 🧪 Local test (optional)
```bash
python scripts/merge_feeds.py
wc -l docs/*.txt  # quick counts
```

## 📣 Contributing
- Found a false positive? Open an **Issue** using the “False positive” template.
- Want to add a source? Open a **Pull Request** with details and a link.

## 📜 License & Conduct
- Code: [MIT](LICENSE)
- Community: [Code of Conduct](CODE_OF_CONDUCT.md)
- Security & reporting: [SECURITY.md](SECURITY.md)

---
**Disclaimer:** These indicators are provided *as‑is*. Use at your own risk. Always test in a staging environment before production.
