from flask import Blueprint, render_template
from models import Campaign, Email, Click
from sqlalchemy import func

analytics_bp = Blueprint('analytics', __name__)

@analytics_bp.route('/')
def dashboard():
    campaigns = Campaign.query.all()
    analytics = []
    for campaign in campaigns:
        total_emails = len(campaign.emails)
        opened_emails = sum(1 for email in campaign.emails if email.opened)
        total_clicks = sum(len(email.clicks) for email in campaign.emails)
        open_rate = (opened_emails / total_emails * 100) if total_emails > 0 else 0
        success_rate = (total_clicks / total_emails * 100) if total_emails > 0 else 0
        analytics.append({
            'campaign': campaign,
            'total_emails': total_emails,
            'opened_emails': opened_emails,
            'total_clicks': total_clicks,
            'open_rate': open_rate,
            'success_rate': success_rate
        })
    return render_template('analytics.html', analytics=analytics)
