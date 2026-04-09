"""
Vercel Python entrypoint for the SecureAuth Flask app.
"""

import os
import sys

PROJECT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

if PROJECT_DIR not in sys.path:
    sys.path.insert(0, PROJECT_DIR)

from backend.app import create_app

app = create_app()
