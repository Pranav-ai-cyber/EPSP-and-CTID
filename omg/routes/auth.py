from flask import Blueprint, render_template, redirect, url_for, flash, request
from flask_login import login_user, logout_user, login_required, current_user
from models import db, User
from werkzeug.security import generate_password_hash, check_password_hash

auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))

    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        name = request.form['name']
        department = request.form['department']

        # Check if user already exists
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash('Email already registered!')
            return redirect(url_for('auth.register'))

        # Check maximum users limit (100)
        total_users = User.query.count()
        if total_users >= 100:
            flash('Maximum user limit reached (100 users)!')
            return redirect(url_for('auth.register'))

        # Create new user
        user = User(email=email, name=name, department=department)
        user.set_password(password)
        user.generate_login_key()
        db.session.add(user)
        db.session.commit()

        flash(f'Registration successful! Your login key is: {user.login_key}')
        return redirect(url_for('auth.login'))

    return render_template('register.html')

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))

    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        login_key = request.form.get('login_key')

        if email and password:
            # Email/password login
            user = User.query.filter_by(email=email, is_active=True).first()
            if user and user.check_password(password):
                login_user(user)
                return redirect(url_for('main.dashboard'))
            else:
                flash('Invalid email or password!')
        elif login_key:
            # Login key login
            user = User.query.filter_by(login_key=login_key, is_active=True).first()
            if user:
                login_user(user)
                return redirect(url_for('main.dashboard'))
            else:
                flash('Invalid login key!')
        else:
            flash('Please provide email/password or login key!')

    return render_template('login.html')

@auth_bp.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('auth.login'))
