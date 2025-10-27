from flask import Flask, render_template, jsonify, request, redirect, url_for, flash, session
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_sqlalchemy import SQLAlchemy
from flask_ngrok import run_with_ngrok
from werkzeug.security import generate_password_hash, check_password_hash
import requests
import json
from config import Config
import logging
import os
import re
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import csv
from io import StringIO
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import SimpleDocTemplate, Paragraph, Table, TableStyle
from reportlab.lib import colors
import datetime

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here'  # Change in production
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///threats.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

config = Config()

logging.basicConfig(level=config.LOG_LEEL)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)

class Threat(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    type = db.Column(db.String(50), nullable=False)
    value = db.Column(db.String(500), nullable=False)
    source = db.Column(db.String(100), nullable=False)
    alert_folder = db.Column(db.Boolean, default=False)
    timestamp = db.Column(db.DateTime, default=datetime.datetime.utcnow)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def fetch_virustotal():
    # Placeholder: Fetch recent threats from VirusTotal
    # In real implementation, use VT API to get recent malware hashes or URLs
    return [{"type": "malware", "value": "example_hash", "source": "VirusTotal"}]

def fetch_alienvault():
    # Placeholder: Fetch OTX pulses
    return [{"type": "ip", "value": "192.168.1.1", "source": "AlienVault"}]

def fetch_shodan():
    # Placeholder: Fetch vulnerable devices
    return [{"type": "device", "value": "example_ip", "source": "Shodan"}]

def fetch_abuseipdb():
    # Placeholder: Fetch abused IPs
    return [{"type": "ip", "value": "10.0.0.1", "source": "AbuseIPDB"}]

def mock_gmail_scan(email):
    # Mock Gmail scan: simulate scanning user's Gmail for vulnerabilities
    # In real implementation, use Gmail API to fetch emails and scan for threats
    mock_threats = []
    # Simulate finding phishing in emails
    if "gmail.com" in email:
        mock_threats.append({"type": "Phishing", "value": f"Phishing email in {email}", "source": "Gmail Scan"})
        mock_threats.append({"type": "SQL Injection", "value": f"SQL injection attempt in {email}", "source": "Gmail Scan"})
    return mock_threats

def scan_local_vulnerabilities():
    vulnerabilities = []
    # Get the base directory of the app
    base_dir = os.path.dirname(os.path.abspath(__file__))
    # Scan files in the app's directory for common vulnerabilities
    for root, dirs, files in os.walk(base_dir):
        for file in files:
            filepath = os.path.join(root, file)
            try:
                if file.endswith('.py'):
                    with open(filepath, 'r', encoding='utf-8') as f:
                        content = f.read()
                        # Check for SQL injection patterns (simplified: look for SELECT and string formatting)
                        if 'SELECT' in content and ('f"' in content or '+' in content):
                            vulnerabilities.append({"type": "SQL Injection", "value": filepath, "source": "Local Scan"})
                        # Check for insecure eval
                        if 'eval(' in content:
                            vulnerabilities.append({"type": "Insecure Eval", "value": filepath, "source": "Local Scan"})
                        # Check for hardcoded secrets
                        if re.search(r"(password|secret|key)\s*=\s*['\"][^'\"]*['\"]", content, re.IGNORECASE):
                            vulnerabilities.append({"type": "Hardcoded Secret", "value": filepath, "source": "Local Scan"})
                elif file.endswith('.txt') or file.endswith('.html'):
                    with open(filepath, 'r', encoding='utf-8') as f:
                        content = f.read()
                        # Check for phishing keywords
                        if any(keyword in content.lower() for keyword in ['urgent', 'click here', 'verify', 'account suspended']):
                            vulnerabilities.append({"type": "Phishing", "value": filepath, "source": "Local Scan"})
                        # Check for XSS patterns (simplified: look for <script>)
                        if '<script' in content.lower():
                            vulnerabilities.append({"type": "XSS", "value": filepath, "source": "Local Scan"})
                elif file.endswith('.exe'):
                    # Simulate malware detection
                    vulnerabilities.append({"type": "Malware", "value": filepath, "source": "Local Scan"})
            except Exception as e:
                logging.error(f"Error scanning {filepath}: {e}")
    return vulnerabilities

def scan_file(filepath):
    threats = []
    try:
        if filepath.endswith('.py'):
            with open(filepath, 'r', encoding='utf-8') as f:
                content = f.read()
                if re.search(r"cursor\.execute\(.*\+.*\)", content) or re.search(r"f\".*SELECT.*\{.*\}.*\"", content):
                    threats.append({"type": "SQL Injection", "value": filepath, "source": "File Upload"})
                if re.search(r"\beval\b", content):
                    threats.append({"type": "Insecure Eval", "value": filepath, "source": "File Upload"})
                if re.search(r"(password|secret|key)\s*=\s*['\"][^'\"]*['\"]", content, re.IGNORECASE):
                    threats.append({"type": "Hardcoded Secret", "value": filepath, "source": "File Upload"})
        elif filepath.endswith('.txt') or filepath.endswith('.html'):
            with open(filepath, 'r', encoding='utf-8') as f:
                content = f.read()
                if re.search(r'\b(urgent|click here|verify|account suspended)\b', content, re.IGNORECASE):
                    threats.append({"type": "Phishing", "value": filepath, "source": "File Upload"})
                if re.search(r'<script.*?>.*?</script>', content, re.IGNORECASE):
                    threats.append({"type": "XSS", "value": filepath, "source": "File Upload"})
        elif filepath.endswith('.exe'):
            threats.append({"type": "Malware", "value": filepath, "source": "File Upload"})
    except Exception as e:
        logging.error(f"Error scanning uploaded file {filepath}: {e}")
    return threats

def scan_url(url):
    threats = []
    # Mock URL scanning
    if "phishing" in url.lower() or "malicious" in url.lower():
        threats.append({"type": "Malicious URL", "value": url, "source": "URL Scan"})
    return threats

@app.route('/')
@login_required
def dashboard():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('dashboard'))
        flash('Invalid credentials')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload():
    if request.method == 'POST':
        file = request.files.get('file')
        url = request.form.get('url')
        if file:
            filename = file.filename
            filepath = os.path.join('uploads', filename)
            os.makedirs('uploads', exist_ok=True)
            file.save(filepath)
            # Scan the uploaded file
            threats = scan_file(filepath)
            for threat in threats:
                existing = Threat.query.filter_by(type=threat['type'], value=threat['value'], source=threat['source']).first()
                if not existing:
                    new_threat = Threat(type=threat['type'], value=threat['value'], source=threat['source'])
                    db.session.add(new_threat)
                    db.session.commit()
                    send_alert_email([threat])
            flash('File uploaded and scanned successfully.')
        elif url:
            # Scan the URL
            threats = scan_url(url)
            for threat in threats:
                existing = Threat.query.filter_by(type=threat['type'], value=threat['value'], source=threat['source']).first()
                if not existing:
                    new_threat = Threat(type=threat['type'], value=threat['value'], source=threat['source'])
                    db.session.add(new_threat)
                    db.session.commit()
                    send_alert_email([threat])
            flash('URL scanned successfully.')
        return redirect(url_for('dashboard'))
    return render_template('upload.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']
        # Check if username or email already exists
        existing_user = User.query.filter((User.username == username) | (User.email == email)).first()
        if existing_user:
            if existing_user.username == username:
                flash('Username already exists')
            else:
                flash('Email already exists')
            return redirect(url_for('register'))
        # Hash the password
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(username=username, password=hashed_password, email=email)
        db.session.add(new_user)
        db.session.commit()
        flash('Registration successful')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/api/threats')
@login_required
def get_threats():
    threats = []
    threats.extend(fetch_virustotal())
    threats.extend(fetch_alienvault())
    threats.extend(fetch_shodan())
    threats.extend(fetch_abuseipdb())
    threats.extend(scan_local_vulnerabilities())
    # Include DB threats
    db_threats = Threat.query.all()
    for t in db_threats:
        threats.append({
            "type": t.type,
            "value": t.value,
            "source": t.source
        })
    return jsonify(threats)



@app.route('/export/csv')
@login_required
def export_csv():
    threats = get_threats().get_json()
    si = StringIO()
    writer = csv.writer(si)
    writer.writerow(['Type', 'Value', 'Source'])
    for threat in threats:
        writer.writerow([threat['type'], threat['value'], threat['source']])
    output = si.getvalue()
    return output, 200, {'Content-Type': 'text/csv', 'Content-Disposition': 'attachment; filename=threats.csv'}

@app.route('/export/pdf')
@login_required
def export_pdf():
    threats = get_threats().get_json()
    from io import BytesIO
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter)
    elements = []
    styles = getSampleStyleSheet()
    elements.append(Paragraph("Threat Report", styles['Title']))
    data = [['Type', 'Value', 'Source']] + [[t['type'], t['value'], t['source']] for t in threats]
    table = Table(data)
    table.setStyle(TableStyle([('BACKGROUND', (0,0), (-1,0), colors.grey),
                               ('TEXTCOLOR', (0,0), (-1,0), colors.whitesmoke),
                               ('ALIGN', (0,0), (-1,-1), 'CENTER'),
                               ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
                               ('BORDERS', (0,0), (-1,-1), 1, colors.black),
                               ('BACKGROUND', (0,1), (-1,-1), colors.beige)]))
    elements.append(table)
    doc.build(elements)
    pdf = buffer.getvalue()
    buffer.close()
    return pdf, 200, {'Content-Type': 'application/pdf', 'Content-Disposition': 'attachment; filename=threats.pdf'}

def send_alert_email(threats):
    # Send alert emails for new threats
    sender_email = "alerts@yourdomain.com"  # Replace with your email
    sender_password = "yourpassword"  # Replace with your password
    smtp_server = "smtp.gmail.com"
    smtp_port = 587

    for threat in threats:
        msg = MIMEMultipart()
        msg['From'] = sender_email
        msg['To'] = "admin@yourdomain.com"  # Replace with admin email
        msg['Subject'] = f"Security Alert: {threat['type']} Detected"

        body = f"A {threat['type']} has been detected.\n\nDetails:\nType: {threat['type']}\nValue: {threat['value']}\nSource: {threat['source']}\n\nThis threat has been blocked and moved to the alert folder."
        msg.attach(MIMEText(body, 'plain'))

        try:
            server = smtplib.SMTP(smtp_server, smtp_port)
            server.starttls()
            server.login(sender_email, sender_password)
            text = msg.as_string()
            server.sendmail(sender_email, "admin@yourdomain.com", text)
            server.quit()
            logging.info(f"Alert email sent for {threat['type']}")
        except Exception as e:
            logging.error(f"Failed to send alert email: {e}")



if __name__ == '__main__':
    import webbrowser
    import threading
    import time

    def open_browser():
        time.sleep(2)  # Wait for server to start
        webbrowser.open('http://127.0.0.1:5000')

    threading.Thread(target=open_browser).start()
    app.run(debug=True)
