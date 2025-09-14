#!/bin/bash
set -e

echo "Starting Test Site (6 Subpages)..."

# Ensure dependencies
sudo apt update
sudo apt install -y python3-pip python3-venv --fix-missing

# Set up virtual environment
python3 -m venv venv
source venv/bin/activate

# Install Django
pip install -r requirements.txt
# Run migrations (not used but required for Django)
cd baselining_server
python manage.py migrate || true

# disable host firewall
sudo ufw allow 8000/tcp

# Run server on 0.0.0.0:8000
echo "🌐 Access the site at http://<your-ip>:8000"
python manage.py runserver 0.0.0.0:8000
