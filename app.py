from flask import Flask, request, jsonify, send_file
import io
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from flask_cors import CORS
import requests
from bs4 import BeautifulSoup
from google import genai
import whois
from datetime import datetime
import re
import json

app = Flask(__name__)
CORS(app)


GEMINI_API_KEY = "AIzaSyAaTD84vec-0WaToKPSEKJ0SU35LxYWsVk"
client = genai.Client(api_key=GEMINI_API_KEY)

def check_https(url):
    return url.startswith("https://")

def get_domain(url):
    match = re.search(r'https?://([^/]+)', url)
    return match.group(1) if match else url

def check_domain_age(domain):
    try:
        w = whois.whois(domain)
        creation = w.creation_date
        if isinstance(creation, list):
            creation = creation[0]
        age = (datetime.now() - creation).days
        return age
    except:
        return -1

def fetch_page_content(url):
    try:
        headers = {"User-Agent": "Mozilla/5.0"}
        response = requests.get(url, headers=headers, timeout=8)
        soup = BeautifulSoup(response.text, "html.parser")
        text = soup.get_text(separator=" ", strip=True)[:3000]
        forms = soup.find_all("form")
        links = [a.get("href", "") for a in soup.find_all("a", href=True)]
        return {
            "content": text,
            "forms": len(forms),
            "links": links[:20],
            "title": soup.title.string if soup.title else "No title"
        }
    except:
        return {"content": "", "forms": 0, "links": [], "title": "Could not fetch"}

def analyse_with_gemini(url, page_data, domain_age, has_https):
    score = 0
    checks = []
    vulnerabilities = []

    if not has_https:
        score += 30
        checks.append({"label": "HTTPS Not Used", "status": "danger", "detail": "Site uses HTTP — data is not encrypted."})
        vulnerabilities.append("No encryption")
    else:
        checks.append({"label": "HTTPS Enabled", "status": "safe", "detail": "Site uses HTTPS encryption."})

    if domain_age == -1:
        score += 20
        checks.append({"label": "Domain Age Unknown", "status": "warn", "detail": "Could not determine domain age."})
    elif domain_age < 30:
        score += 25
        checks.append({"label": f"New Domain: {domain_age} days old", "status": "danger", "detail": "Very new domains are commonly used for phishing."})
        vulnerabilities.append("Newly registered domain")
    else:
        checks.append({"label": f"Domain Age: {domain_age} days", "status": "safe", "detail": "Domain has been registered for a reasonable time."})

    if page_data['forms'] > 0:
        score += 20
        checks.append({"label": f"{page_data['forms']} Form(s) Detected", "status": "warn", "detail": "Page contains forms that could harvest credentials."})
        vulnerabilities.append("Credential harvesting form")
    else:
        checks.append({"label": "No Suspicious Forms", "status": "safe", "detail": "No login forms detected."})

    suspicious_words = ["login", "verify", "account", "secure", "banking", "password", "confirm", "update"]
    found_words = [w for w in suspicious_words if w in url.lower() or w in page_data['content'].lower()[:500]]
    if found_words:
        score += 15
        checks.append({"label": "Suspicious Keywords Found", "status": "warn", "detail": f"Found: {', '.join(found_words[:3])}"})
        vulnerabilities.append("Suspicious keywords")
    else:
        checks.append({"label": "No Suspicious Keywords", "status": "safe", "detail": "No phishing keywords detected."})

    if page_data['title'] in ["Could not fetch", "No title"]:
        score += 10
        checks.append({"label": "Page Not Accessible", "status": "warn", "detail": "Could not access the page content."})
    else:
        checks.append({"label": "Page Accessible", "status": "safe", "detail": f"Title: {page_data['title']}"})

    try:
        prompt = f"""
You are a cybersecurity expert. Analyse this URL for phishing:
URL: {url}
HTTPS: {has_https}
Domain Age: {domain_age} days
Page Title: {page_data['title']}
Forms: {page_data['forms']}
Content: {page_data['content'][:1000]}

Return ONLY a JSON object with no extra text:
{{
  "risk_score": <0-100>,
  "risk_level": "<SAFE|SUSPICIOUS|HIGH RISK>",
  "summary": "<2 sentence explanation>",
  "checks": <list of check objects>,
  "vulnerabilities": <list of strings>
}}
"""
        response = client.models.generate_content(model="gemini-2.0-flash", contents=prompt)
        text = response.text.strip()
        text = re.sub(r'```json|```', '', text).strip()
        return json.loads(text)
    except:
        score = min(score, 100)
        if score >= 75:
            risk_level = "HIGH RISK"
            summary = "Multiple high-risk indicators detected. This URL shows strong signs of being a phishing site."
        elif score >= 40:
            risk_level = "SUSPICIOUS"
            summary = "Some suspicious indicators found. Exercise caution with this URL."
        else:
            risk_level = "SAFE"
            summary = "No major threats detected. This URL appears to be safe."

        return {
            "risk_score": score,
            "risk_level": risk_level,
            "summary": summary,
            "checks": checks,
            "vulnerabilities": vulnerabilities
        }

def generate_pdf(result):
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter)
    styles = getSampleStyleSheet()
    story = []

    title_style = ParagraphStyle('title', fontSize=24, fontName='Helvetica-Bold', textColor=colors.HexColor('#ff3b57'), spaceAfter=10)
    story.append(Paragraph("PhishGuard AI — Scan Report", title_style))
    story.append(Paragraph("Generated by osho", styles['Normal']))
    story.append(Spacer(1, 20))

    story.append(Paragraph(f"<b>URL Scanned:</b> {result.get('url','')}", styles['Normal']))
    story.append(Paragraph(f"<b>Risk Score:</b> {result.get('risk_score', 0)}/100", styles['Normal']))
    story.append(Paragraph(f"<b>Risk Level:</b> {result.get('risk_level','')}", styles['Normal']))
    story.append(Paragraph(f"<b>Summary:</b> {result.get('summary','')}", styles['Normal']))
    story.append(Spacer(1, 20))

    story.append(Paragraph("<b>Security Checks:</b>", styles['Heading2']))
    checks = result.get('checks', [])
    table_data = [['Check', 'Status', 'Detail']]
    for check in checks:
        table_data.append([check.get('label',''), check.get('status','').upper(), check.get('detail','')])

    table = Table(table_data, colWidths=[150, 70, 280])
    table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#ff3b57')),
        ('TEXTCOLOR', (0,0), (-1,0), colors.white),
        ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
        ('FONTSIZE', (0,0), (-1,-1), 9),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.HexColor('#f9f9f9'), colors.white]),
        ('GRID', (0,0), (-1,-1), 0.5, colors.grey),
        ('VALIGN', (0,0), (-1,-1), 'TOP'),
    ]))
    story.append(table)
    story.append(Spacer(1, 20))

    story.append(Paragraph("<b>Detected Threats:</b>", styles['Heading2']))
    for v in result.get('vulnerabilities', []):
        story.append(Paragraph(f"• {v}", styles['Normal']))

    doc.build(story)
    buffer.seek(0)
    return buffer

@app.route("/scan", methods=["POST"])
def scan():
    data = request.get_json()
    url = data.get("url", "").strip()
    if not url:
        return jsonify({"error": "URL is required"}), 400
    if not url.startswith("http"):
        url = "https://" + url
    has_https = check_https(url)
    domain = get_domain(url)
    domain_age = check_domain_age(domain)
    page_data = fetch_page_content(url)
    result = analyse_with_gemini(url, page_data, domain_age, has_https)
    result["url"] = url
    result["domain_age"] = domain_age
    result["has_https"] = has_https
    return jsonify(result)

@app.route("/report", methods=["POST"])
def report():
    data = request.get_json()
    buffer = generate_pdf(data)
    return send_file(buffer, as_attachment=True, download_name="phishguard_report.pdf", mimetype="application/pdf")

@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"})

if __name__ == "__main__":
    app.run(debug=False, host="0.0.0.0", port=5000)
