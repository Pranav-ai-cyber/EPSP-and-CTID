import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from flask import current_app

def send_phishing_email(to_email, html_content, email_id):
    msg = MIMEMultipart('alternative')
    msg['Subject'] = "Important Security Update"
    msg['From'] = current_app.config['MAIL_DEFAULT_SENDER']
    msg['To'] = to_email

    # Replace placeholders in HTML with tracking links
    tracked_html = html_content.replace('{{email_id}}', str(email_id))
    tracked_html = tracked_html.replace('{{track_url}}', f"http://localhost:5000/track/{email_id}")

    part = MIMEText(tracked_html, 'html')
    msg.attach(part)

    try:
        server = smtplib.SMTP(current_app.config['MAIL_SERVER'], current_app.config['MAIL_PORT'])
        server.sendmail(current_app.config['MAIL_DEFAULT_SENDER'], to_email, msg.as_string())
        server.quit()
        print(f"Email sent to {to_email}")
    except Exception as e:
        print(f"Failed to send email: {e}")
