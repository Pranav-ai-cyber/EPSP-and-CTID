from flask import Blueprint, render_template, request, redirect, url_for, flash
from flask_login import login_required
from models import db, Campaign, User, Email, Template
from utils.email_sender import send_phishing_email
from datetime import datetime
from sqlalchemy import func

main_bp = Blueprint('main', __name__)

@main_bp.route('/')
@login_required
def dashboard():
    campaigns = Campaign.query.order_by(Campaign.created_at.desc()).limit(5).all()
    campaigns_count = Campaign.query.count()
    users_count = User.query.count()
    avg_progress = db.session.query(func.avg(User.progress)).scalar() or 0

    # Calculate success rate (emails clicked / emails sent)
    total_emails = Email.query.count()
    clicked_emails = db.session.query(func.count(Email.id)).filter(Email.clicks.any()).scalar()
    success_rate = (clicked_emails / total_emails * 100) if total_emails > 0 else 0

    return render_template('dashboard.html',
                         campaigns=campaigns,
                         campaigns_count=campaigns_count,
                         users_count=users_count,
                         avg_progress=avg_progress,
                         success_rate=success_rate)

@main_bp.route('/campaign/new', methods=['GET', 'POST'])
def new_campaign():
    if request.method == 'POST':
        name = request.form['name']
        description = request.form['description']
        template_id = request.form['template_id']
        user_emails = request.form['user_emails'].split('\n')

        campaign = Campaign(name=name, description=description, template_id=template_id)
        db.session.add(campaign)
        db.session.commit()

        for email in user_emails:
            email = email.strip()
            if email:
                user = User.query.filter_by(email=email).first()
                if not user:
                    user = User(email=email)
                    db.session.add(user)
                email_record = Email(campaign_id=campaign.id, user_id=user.id)
                db.session.add(email_record)
                # Send email
                send_phishing_email(email, campaign.template.html_content, email_record.id)

        db.session.commit()
        flash('Campaign created and emails sent!')
        return redirect(url_for('main.dashboard'))

    templates = Template.query.all()
    return render_template('new_campaign.html', templates=templates)

@main_bp.route('/track/<int:email_id>')
def track_click(email_id):
    email = Email.query.get_or_404(email_id)
    email.opened = True
    email.opened_at = datetime.utcnow()
    db.session.commit()
    # Redirect to education page or fake login
    return redirect(url_for('main.education'))

@main_bp.route('/education')
def education():
    return render_template('education.html')
