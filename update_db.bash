#! /bin/bash
cd /var/www/html/flask/git_repo/cybsec_site
source .venv/bin/activate

export FLASK_APP=run.py
flask db migrate
flask db upgrade