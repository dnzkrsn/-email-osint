# Email OSINT

A privacy-conscious email OSINT checker for publicly available information.

## Features
- Email syntax validation
- Domain resolution and MX records
- Disposable-email detection
- Local-part name/username heuristics
- Public Gravatar check
- Public GitHub search
- Browser UI + JSON API

## Run
```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python app.py
```

Open http://127.0.0.1:5000

API:
`/api/check?email=person@example.com`

## Safety
This tool does not collect passwords, authentication tokens, private account data, or attempt credential stuffing, login bypasses, or access to breach databases. Results are leads, not proof of identity.
