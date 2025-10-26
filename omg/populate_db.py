from app import create_app
from models import db, Campaign, Template, User, Email, Click
from datetime import datetime

app = create_app()

with app.app_context():
    # Create sample template
    template = Template(
        name="Sample Phishing Email",
        html_content="""
        <html>
        <body>
        <h1>Urgent: Account Security Alert</h1>
        <p>Dear User,</p>
        <p>Your account has been compromised. Please click <a href="{{ tracking_url }}">here</a> to reset your password.</p>
        <p>Best regards,<br>Security Team</p>
        </body>
        </html>
        """
    )
    db.session.add(template)

    # Create sample users with login keys
    user1 = User(email="test1@example.com", name="Test User 1", role="Employee", department="IT")
    user1.generate_login_key()
    user2 = User(email="test2@example.com", name="Test User 2", role="Manager", department="HR")
    user2.generate_login_key()
    db.session.add(user1)
    db.session.add(user2)

    # Create sample campaign
    campaign = Campaign(
        name="Security Awareness Campaign",
        description="Testing employee response to phishing emails",
        template_id=template.id
    )
    db.session.add(campaign)
    db.session.commit()  # Commit to get IDs

    # Create sample emails
    email1 = Email(campaign_id=campaign.id, user_id=user1.id, sent_at=datetime.utcnow(), opened=True, opened_at=datetime.utcnow())
    email2 = Email(campaign_id=campaign.id, user_id=user2.id, sent_at=datetime.utcnow(), opened=False)
    db.session.add(email1)
    db.session.add(email2)
    db.session.commit()

    # Create sample click
    click = Click(email_id=email1.id, url="http://phishing-site.com/reset", clicked_at=datetime.utcnow(), ip_address="192.168.1.1")
    db.session.add(click)
    db.session.commit()

    print("Sample data added successfully!")
    print(f"User 1 login key: {user1.login_key}")
    print(f"User 2 login key: {user2.login_key}")
