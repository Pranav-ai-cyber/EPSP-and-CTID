from flask import Blueprint, render_template
from models import Campaign

campaigns_bp = Blueprint('campaigns', __name__)

@campaigns_bp.route('/')
def list_campaigns():
    campaigns = Campaign.query.all()
    return render_template('campaigns.html', campaigns=campaigns)

@campaigns_bp.route('/<int:campaign_id>')
def campaign_detail(campaign_id):
    campaign = Campaign.query.get_or_404(campaign_id)
    return render_template('campaign_detail.html', campaign=campaign)
