from flask import Flask
from flask_login import LoginManager
from config import Config
from models import db, User
from routes.main import main_bp
from routes.campaigns import campaigns_bp
from routes.templates import templates_bp
from routes.analytics import analytics_bp
from routes.auth import auth_bp
import webbrowser
import threading
import time

login_manager = LoginManager()

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    db.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = 'auth.login'

    app.register_blueprint(main_bp)
    app.register_blueprint(campaigns_bp, url_prefix='/campaigns')
    app.register_blueprint(templates_bp, url_prefix='/templates')
    app.register_blueprint(analytics_bp, url_prefix='/analytics')
    app.register_blueprint(auth_bp, url_prefix='/auth')

    with app.app_context():
        db.create_all()

    return app

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def open_browser():
    time.sleep(1.5)  # Wait for server to start
    webbrowser.open('http://127.0.0.1:5000')

if __name__ == '__main__':
    app = create_app()
    # Open browser in a separate thread
    threading.Thread(target=open_browser).start()
    app.run(debug=True)
