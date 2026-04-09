"""
app.py - Flask application factory for SecureAuth.
"""

import logging
import os
import sys
from threading import Lock

from dotenv import load_dotenv
from flask import Flask, jsonify, send_from_directory
from flask_cors import CORS

_backend_dir = os.path.dirname(os.path.abspath(__file__))
_project_dir = os.path.dirname(_backend_dir)

load_dotenv(dotenv_path=os.path.join(_project_dir, 'config', '.env'))

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S',
)
logger = logging.getLogger(__name__)

if _backend_dir not in sys.path:
    sys.path.insert(0, _backend_dir)

from database import init_db, seed_demo_data
from routes.auth import auth_bp
from routes.dashboard import dash_bp
from security.protection import security_headers

_runtime_lock = Lock()
_runtime_ready = False


def initialize_runtime() -> None:
    global _runtime_ready

    if _runtime_ready:
        return

    with _runtime_lock:
        if _runtime_ready:
            return

        logger.info("Initializing database ...")
        init_db()
        seed_demo_data()

        logger.info("Loading AI ensemble ...")
        from ai.ensemble_model import get_ensemble
        get_ensemble()

        _runtime_ready = True


def create_app() -> Flask:
    initialize_runtime()

    app = Flask(__name__, static_folder=None)
    app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'change-me')
    app.config['JSON_SORT_KEYS'] = False

    CORS(
        app,
        resources={
            r'/api/*': {
                'origins': ['http://localhost:*', 'http://127.0.0.1:*', 'null', '*'],
                'methods': ['GET', 'POST', 'OPTIONS'],
                'allow_headers': ['Content-Type', 'Authorization'],
            }
        },
        supports_credentials=True,
    )

    app.register_blueprint(auth_bp)
    app.register_blueprint(dash_bp)
    app.after_request(security_headers)

    frontend_dir = os.path.join(_project_dir, 'frontend')

    @app.route('/')
    def index():
        return send_from_directory(frontend_dir, 'index.html')

    @app.route('/<path:filename>')
    def static_files(filename):
        return send_from_directory(frontend_dir, filename)

    @app.route('/health')
    def health():
        return jsonify({'status': 'ok', 'service': 'SecureAuth API'}), 200

    @app.errorhandler(404)
    def not_found(error):
        return jsonify({'error': 'Endpoint not found.'}), 404

    @app.errorhandler(405)
    def method_not_allowed(error):
        return jsonify({'error': 'Method not allowed.'}), 405

    @app.errorhandler(500)
    def internal_error(error):
        logger.exception("Internal server error")
        return jsonify({'error': 'Internal server error.'}), 500

    return app


if __name__ == '__main__':
    port = int(os.getenv('PORT', 5000))
    debug = os.getenv('FLASK_DEBUG', '1') == '1'

    app = create_app()
    logger.info("SecureAuth starting on http://localhost:%d", port)
    app.run(host='0.0.0.0', port=port, debug=debug, use_reloader=False)
