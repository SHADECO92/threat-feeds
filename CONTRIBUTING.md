# Contributing

Thanks for considering a contribution!

## Issues
Use the provided templates—especially for false positives. Include:
- The indicator (IP / domain / URL)
- Why it’s safe / evidence (vendor docs, screenshots, etc.)

## Pull Requests
- Keep changes small and focused.
- Explain *why* the change is needed.
- If adding a new source, link the provider’s ToS and rate limits.

## Local run
```bash
python scripts/merge_feeds.py
wc -l docs/*.txt
```
