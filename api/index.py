import os
import sys

# Ensure backend directory is in path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.main import app
