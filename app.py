from flask import Flask, request, jsonify, render_template
from email_validator import validate_email, EmailNotValidError
import hashlib
import re
import socket
import urllib.request
import urllib.parse
import urllib.error
import json

app = Flask(__name__)

DISPOSABLE_DOMAINS = {
    "10minutemail.com", "guerrillamail.com", "mailinator.com",
    "tempmail.com", "temp-mail.org", "yopmail.com", "sharklasers.com",
    "getnada.com", "trashmail.com", "maildrop.cc", "dispostable.com"
}

def name_hints(local):
    cleaned = re.sub(r'[^a-zA-Z0-9._-]+', ' ', local)
    parts = [p for p in re.split(r'[._-]+|\s+', cleaned) if p]
    parts = [p for p in parts if not p.isdigit() and len(p) > 1]
    hints = []
    if len(parts) >= 2:
        hints.append({
            "first": parts[0].capitalize(),
            "last": parts[1].capitalize(),
            "source": "email local-part heuristic",
            "verified": False
        })
    elif len(parts) == 1:
        hints.append({
            "username": parts[0],
            "source": "email local-part heuristic",
            "verified": False
        })
    return hints

def github_lookup(email):
    # GitHub's public user API does not support arbitrary email search.
    # We therefore avoid scraping or authentication bypasses and only
    # query the public search endpoint when GitHub exposes a matching result.
    url = "https://api.github.com/search/users?q=" + urllib.parse.quote(f'"{email}"')
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "email-osint-safe-checker/1.0", "Accept": "application/vnd.github+json"}
    )
    try:
        with urllib.request.urlopen(req, timeout=8) as r:
            data = json.loads(r.read().decode("utf-8"))
            return {
                "available": True,
                "total_count": data.get("total_count", 0),
                "users": [
                    {
                        "login": u.get("login"),
                        "profile": u.get("html_url"),
                        "avatar": u.get("avatar_url")
                    }
                    for u in data.get("items", [])[:10]
                ]
            }
    except Exception as e:
        return {"available": False, "error": str(e)}

def public_gravatar(email):
    digest = hashlib.md5(email.strip().lower().encode()).hexdigest()
    url = f"https://www.gravatar.com/avatar/{digest}?d=404"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "email-osint-safe-checker/1.0"})
        with urllib.request.urlopen(req, timeout=6) as r:
            return {"found": r.status == 200, "url": url}
    except urllib.error.HTTPError as e:
        return {"found": False, "url": url, "status": e.code}
    except Exception:
        return {"found": False, "url": url}

def check_domain(domain):
    result = {"domain": domain, "resolves": False, "mx": [], "disposable": domain.lower() in DISPOSABLE_DOMAINS}
    try:
        socket.gethostbyname(domain)
        result["resolves"] = True
    except socket.gaierror:
        pass

    # Lightweight MX lookup without requiring a DNS package.
    try:
        import dns.resolver
        answers = dns.resolver.resolve(domain, "MX", lifetime=5)
        result["mx"] = sorted(
            [{"priority": int(a.preference), "host": str(a.exchange).rstrip(".")} for a in answers],
            key=lambda x: x["priority"]
        )
    except Exception:
        result["mx_lookup_note"] = "Install dnspython for MX records."

    return result

@app.route("/")
def index():
    return render_template("index.html")

@app.get("/api/check")
def api_check():
    raw = (request.args.get("email") or "").strip()
    if not raw:
        return jsonify({"error": "Missing email parameter. Use /api/check?email=person@example.com"}), 400

    try:
        info = validate_email(raw, check_deliverability=False)
        email = info.normalized
    except EmailNotValidError as e:
        return jsonify({
            "email": raw,
            "valid": False,
            "error": str(e)
        }), 400

    local, domain = email.rsplit("@", 1)
    domain_info = check_domain(domain)

    return jsonify({
        "email": email,
        "valid": True,
        "local_part": local,
        "domain": domain_info,
        "name_hints": name_hints(local),
        "gravatar": public_gravatar(email),
        "github_public_search": github_lookup(email),
        "notes": [
            "Name hints are heuristics, not verified identity.",
            "Only public information is checked.",
            "No passwords, private account data, credential stuffing, or breach databases are queried."
        ]
    })

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
