#! /bin/bash
cd /var/www/html/flask/git_repo/cybsec_site
source .venv/bin/activate

kill $(pgrep -f 'python test.py')

nohup python run.py