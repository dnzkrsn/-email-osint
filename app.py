from flask import Flask, request, jsonify, render_template
from email_validator import validate_email, EmailNotValidError
import hashlib, re, socket, urllib.request, urllib.parse, urllib.error, json

app = Flask(__name__)

DISPOSABLE_DOMAINS = {
    "10minutemail.com","guerrillamail.com","mailinator.com","tempmail.com",
    "temp-mail.org","yopmail.com","sharklasers.com","getnada.com",
    "trashmail.com","maildrop.cc","dispostable.com"
}
FREE_PROVIDERS = {
    "gmail.com":"Google Gmail","outlook.com":"Microsoft Outlook",
    "hotmail.com":"Microsoft Hotmail","live.com":"Microsoft Outlook",
    "icloud.com":"Apple iCloud","yahoo.com":"Yahoo Mail",
    "proton.me":"Proton Mail","protonmail.com":"Proton Mail",
    "gmx.com":"GMX","gmx.de":"GMX","web.de":"WEB.DE"
}
SOCIAL_TEMPLATES = {
    "GitHub":"https://github.com/{u}","GitLab":"https://gitlab.com/{u}",
    "Reddit":"https://www.reddit.com/user/{u}/","X":"https://x.com/{u}",
    "Instagram":"https://www.instagram.com/{u}/","TikTok":"https://www.tiktok.com/@{u}",
    "Pinterest":"https://www.pinterest.com/{u}/","Keybase":"https://keybase.io/{u}"
}

def dns_records(domain, record_type):
    try:
        import dns.resolver
        return [str(a).strip('"') for a in dns.resolver.resolve(domain, record_type, lifetime=5)]
    except Exception:
        return []

def name_hints(local):
    cleaned=re.sub(r"[^a-zA-Z0-9._-]+"," ",local)
    parts=[p for p in re.split(r"[._-]+|\s+",cleaned) if p and len(p)>1 and not p.isdigit()]
    if len(parts)>=2:
        return [{"first":parts[0].capitalize(),"last":parts[1].capitalize(),
                 "source":"email local-part heuristic","verified":False}]
    if len(parts)==1:
        return [{"username":parts[0],"source":"email local-part heuristic","verified":False}]
    return []

def github_lookup(email, username):
    queries=[f'"{email}"'] + ([username] if username else [])
    results=[]; seen=set()
    for query in queries:
        url="https://api.github.com/search/users?q="+urllib.parse.quote(query)
        req=urllib.request.Request(url,headers={
            "User-Agent":"email-osint-safe-checker/2.0",
            "Accept":"application/vnd.github+json"
        })
        try:
            with urllib.request.urlopen(req,timeout=8) as r:
                data=json.loads(r.read().decode())
            for u in data.get("items",[])[:10]:
                login=u.get("login")
                if login and login not in seen:
                    seen.add(login)
                    results.append({"login":login,"profile":u.get("html_url"),"avatar":u.get("avatar_url")})
        except Exception:
            pass
    return {"available":True,"total_count":len(results),"users":results[:15]}

def public_gravatar(email):
    digest=hashlib.md5(email.strip().lower().encode()).hexdigest()
    url=f"https://www.gravatar.com/avatar/{digest}?d=404"
    try:
        req=urllib.request.Request(url,headers={"User-Agent":"email-osint-safe-checker/2.0"})
        with urllib.request.urlopen(req,timeout=6) as r:
            return {"found":r.status==200,"url":url}
    except urllib.error.HTTPError as e:
        return {"found":False,"url":url,"status":e.code}
    except Exception:
        return {"found":False,"url":url}

def rdap_domain(domain):
    url="https://rdap.org/domain/"+urllib.parse.quote(domain)
    req=urllib.request.Request(url,headers={"User-Agent":"email-osint-safe-checker/2.0","Accept":"application/rdap+json"})
    try:
        with urllib.request.urlopen(req,timeout=8) as r:
            data=json.loads(r.read().decode())
        events={}
        for ev in data.get("events",[]):
            if ev.get("eventAction") in {"registration","expiration","last changed"}:
                events[ev.get("eventAction")]=ev.get("eventDate")
        registrars=[]
        for ent in data.get("entities",[]):
            if "registrar" in ent.get("roles",[]):
                for item in ent.get("vcardArray",[None,[]])[1]:
                    if item and item[0]=="fn": registrars.append(item[3])
        return {"available":True,"handle":data.get("handle"),"status":data.get("status",[]),
                "events":events,"registrar":registrars[:3]}
    except Exception as e:
        return {"available":False,"error":str(e)}

def check_domain(domain):
    out={"domain":domain,"resolves":False,"disposable":domain.lower() in DISPOSABLE_DOMAINS,
         "provider":FREE_PROVIDERS.get(domain.lower(),"Custom / business domain"),
         "mx":[],"a":[],"aaaa":[],"txt":[],"spf":[],"dmarc":[]}
    try:
        socket.gethostbyname(domain); out["resolves"]=True
    except socket.gaierror: pass
    try:
        import dns.resolver
        ans=dns.resolver.resolve(domain,"MX",lifetime=5)
        out["mx"]=sorted([{"priority":int(a.preference),"host":str(a.exchange).rstrip(".")} for a in ans],
                         key=lambda x:x["priority"])
    except Exception: pass
    out["a"]=dns_records(domain,"A")[:10]
    out["aaaa"]=dns_records(domain,"AAAA")[:10]
    out["txt"]=dns_records(domain,"TXT")[:20]
    out["spf"]=[x for x in out["txt"] if x.lower().startswith("v=spf1")]
    out["dmarc"]=dns_records("_dmarc."+domain,"TXT")[:10]
    return out

def public_searches(email,username,domain):
    qe=urllib.parse.quote('"'+email+'"')
    qu=urllib.parse.quote('"'+username+'"') if username else ""
    qd=urllib.parse.quote("site:"+domain)
    return {
        "exact_email_google":f"https://www.google.com/search?q={qe}",
        "exact_email_bing":f"https://www.bing.com/search?q={qe}",
        "username_google":f"https://www.google.com/search?q={qu}" if qu else None,
        "domain_google":f"https://www.google.com/search?q={qd}",
        "social_username":{n:u.format(u=urllib.parse.quote(username)) for n,u in SOCIAL_TEMPLATES.items()} if username else {}
    }

def risk_score(d,g,gh):
    score=0; reasons=[]
    if d["disposable"]: score+=35; reasons.append("Disposable-email domain detected")
    if not d["resolves"]: score+=25; reasons.append("Domain does not resolve")
    if not d["mx"]: score+=20; reasons.append("No MX records returned")
    if d["dmarc"]: score=max(0,score-5)
    if d["spf"]: score=max(0,score-5)
    if g.get("found"): reasons.append("Public Gravatar profile exists")
    if gh.get("total_count",0): reasons.append("Public GitHub results found")
    label="Low" if score<20 else "Medium" if score<50 else "High"
    return {"score":min(100,score),"label":label,"reasons":reasons}

@app.route("/")
def index(): return render_template("index.html")

@app.get("/api/check")
def api_check():
    raw=(request.args.get("email") or "").strip()
    if not raw: return jsonify({"error":"Missing email parameter"}),400
    try:
        info=validate_email(raw,check_deliverability=False); email=info.normalized
    except EmailNotValidError as e:
        return jsonify({"email":raw,"valid":False,"error":str(e)}),400
    local,domain=email.rsplit("@",1)
    hints=name_hints(local)
    username=(hints[0].get("username") if hints and "username" in hints[0]
              else (hints[0].get("first","")+"."+hints[0].get("last","")).strip(".") if hints else local)
    d=check_domain(domain); g=public_gravatar(email); gh=github_lookup(email,username)
    return jsonify({
        "email":email,"valid":True,"local_part":local,"domain":d,
        "rdap":rdap_domain(domain),"name_hints":hints,"gravatar":g,
        "github_public_search":gh,"public_search_links":public_searches(email,username,domain),
        "risk":risk_score(d,g,gh),
        "notes":["Identity/name hints are unverified leads, not proof of identity.",
                 "Only public information and public APIs are checked.",
                 "No passwords, private account data, credential stuffing, login bypasses, or private breach records are queried."]
    })

# ==============================
# AI INTELLIGENCE ANALYSIS
# ==============================

@app.post("/api/ai-analyze")
def ai_analyze():
    import os

    try:
        from openai import OpenAI
    except ImportError:
        return jsonify({
            "error": "OpenAI package is not installed. Add openai to requirements.txt."
        }), 500

    api_key = os.environ.get("OPENAI_API_KEY")

    if not api_key:
        return jsonify({
            "error": "OPENAI_API_KEY is not configured on the server."
        }), 500

    data = request.get_json(silent=True) or {}

    if not data:
        return jsonify({"error": "No investigation data supplied."}), 400

    # Only analyze information already collected by this application.
    allowed_data = {
        "email": data.get("email"),
        "valid": data.get("valid"),
        "local_part": data.get("local_part"),
        "domain": data.get("domain"),
        "rdap": data.get("rdap"),
        "name_hints": data.get("name_hints"),
        "gravatar": data.get("gravatar"),
        "github_public_search": data.get("github_public_search"),
        "risk": data.get("risk"),
        "public_search_links": data.get("public_search_links")
    }

    prompt = f"""
You are an email-intelligence analysis assistant.

Analyze ONLY the public-source investigation data supplied below.

Your job is to:
1. Summarize the strongest findings.
2. Explain what each finding actually means.
3. Separate verified technical facts from unverified heuristics.
4. Identify potentially interesting signals.
5. Give an overall confidence level.
6. Suggest reasonable next PUBLIC-source checks.
7. Never claim that a person has been identified unless the supplied evidence
   actually proves that.
8. Never invent names, phone numbers, addresses, passwords, private accounts,
   credentials, IP addresses, or other information not present in the data.

Return a concise professional investigation report.

Structure your response with these sections:

OVERALL ASSESSMENT
KEY FINDINGS
TECHNICAL ANALYSIS
IDENTITY SIGNALS
CONFIDENCE
RECOMMENDED PUBLIC CHECKS
IMPORTANT LIMITATIONS

Investigation data:

{json.dumps(allowed_data, indent=2, default=str)}
"""

    try:
        client = OpenAI(api_key=api_key)

        response = client.responses.create(
            model="gpt-5-mini",
            input=prompt
        )

        return jsonify({
            "success": True,
            "analysis": response.output_text
        })

    except Exception as e:
        return jsonify({
            "success": False,
            "error": "AI analysis failed.",
            "details": str(e)
        }), 500

if __name__=="__main__":
    app.run(host="0.0.0.0",port=5000,debug=False)
