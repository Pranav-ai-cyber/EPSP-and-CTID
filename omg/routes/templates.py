from flask import Blueprint, render_template, request, redirect, url_for, flash
from models import db, Template

templates_bp = Blueprint('templates', __name__)

@templates_bp.route('/')
def list_templates():
    templates = Template.query.all()
    return render_template('templates.html', templates=templates)

@templates_bp.route('/new', methods=['GET', 'POST'])
def new_template():
    if request.method == 'POST':
        name = request.form['name']
        html_content = request.form['html_content']
        template = Template(name=name, html_content=html_content)
        db.session.add(template)
        db.session.commit()
        flash('Template created!')
        return redirect(url_for('templates.list_templates'))
    return render_template('new_template.html')

@templates_bp.route('/edit/<int:template_id>', methods=['GET', 'POST'])
def edit_template(template_id):
    template = Template.query.get_or_404(template_id)
    if request.method == 'POST':
        template.name = request.form['name']
        template.html_content = request.form['html_content']
        db.session.commit()
        flash('Template updated!')
        return redirect(url_for('templates.list_templates'))
    return render_template('edit_template.html', template=template)
