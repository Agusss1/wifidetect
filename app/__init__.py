import os
import logging
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_socketio import SocketIO

db = SQLAlchemy()
socketio = SocketIO()

def create_app():
    app = Flask(__name__)

    from config import Config
    app.config.from_object(Config)

    os.makedirs(app.config['DATA_DIR'], exist_ok=True)

    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
        handlers=[
            logging.FileHandler(app.config['LOG_FILE']),
            logging.StreamHandler()
        ]
    )

    db.init_app(app)
    socketio.init_app(app, cors_allowed_origins='*', async_mode='eventlet')

    from app.routes.dashboard import dashboard_bp
    from app.routes.devices import devices_bp
    from app.routes.api import api_bp

    app.register_blueprint(dashboard_bp)
    app.register_blueprint(devices_bp, url_prefix='/devices')
    app.register_blueprint(api_bp, url_prefix='/api')

    with app.app_context():
        db.create_all()

    return app
