# Email OSINT Pro

A public-source email intelligence checker.

## Checks
- Email syntax normalization
- Domain resolution and MX
- SPF / DMARC / TXT / A / AAAA records
- Disposable-domain detection
- Common mail-provider classification
- RDAP domain registration metadata
- Public Gravatar presence
- Public GitHub search
- Username-based public search shortcuts
- Google/Bing exact-email search shortcuts
- Simple risk/reputation signal

## Deploy
Build: `pip install -r requirements.txt`
Start: `gunicorn app:app --bind 0.0.0.0:$PORT`

## Safety
Results are public-source leads, not proof of identity. The app does not request passwords, private account access, credential stuffing, login bypasses, or private breach records.
