from flask import Flask, render_template, redirect, url_for, flash, session, request
from flask_bcrypt import Bcrypt
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from markupsafe import Markup
import logging
import os

from config import Config
from models import db, User
from forms import RegisterForm, LoginForm
from security import apply_security_headers

app = Flask(__name__)
app.config.from_object(Config)

db.init_app(app)
bcrypt = Bcrypt(app)
csrf = CSRFProtect(app)

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=[app.config.get('RATELIMIT_DEFAULT')]
)

apply_security_headers(app)

# Simple in-memory tracking of failed login attempts per IP
failed_logins = {}


def classify_severity(count):
    if count >= 20:
        return 'CRITICAL'
    if count >= 10:
        return 'HIGH'
    if count >= 5:
        return 'MEDIUM'
    return 'LOW'


def record_failed_login(ip, username):
    count = failed_logins.get(ip, 0) + 1
    failed_logins[ip] = count
    severity = classify_severity(count)
    logging.warning(f"{severity} - Failed login from {ip} for user '{username}' (count={count})")
    return count

# ----------------------------------------------------------------------------
# Vulnerable endpoints for demonstration; NOT used in production
# ----------------------------------------------------------------------------

@app.route('/vuln_login', methods=['GET'])
def vuln_login():
    # parameters come from query string to allow easy attack simulation
    username = request.args.get('username', '')
    password = request.args.get('password', '')
    # dangerously concatenated SQL - subject to injection
    sql = f"SELECT * FROM user WHERE username='{username}' AND password='{password}'"
    result = db.session.execute(sql).fetchone()
    if result:
        return f"(vulnerable) Authenticated as {username}"
    return "(vulnerable) Login failed"

@app.route('/vuln_login_fixed', methods=['GET'])
def vuln_login_fixed():
    username = request.args.get('username', '')
    password = request.args.get('password', '')
    # safe parameterized query using SQLAlchemy text binding
    from sqlalchemy import text
    stmt = text("SELECT * FROM user WHERE username=:u AND password=:p")
    result = db.session.execute(stmt, {'u': username, 'p': password}).fetchone()
    if result:
        return f"(fixed) Authenticated as {username}"
    return "(fixed) Login failed"

@app.route('/echo')
def echo():
    text = request.args.get('text', '')
    # Jinja autoescaping will render this safely
    return render_template('echo.html', text=text)

@app.route('/vuln_echo')
def vuln_echo():
    text = request.args.get('text', '')
    # intentionally mark as safe to demonstrate XSS vulnerability
    return render_template('echo.html', text=Markup(text))

# ----------------------------------------------------------------------------

# Logging setup (uses config LOG_FILE)
logfile = app.config.get('LOG_FILE', 'logs/security.log')
if not os.path.exists(os.path.dirname(logfile)):
    os.makedirs(os.path.dirname(logfile), exist_ok=True)

logging.basicConfig(
    filename=logfile,
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        hashed_pw = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(username=form.username.data, password=hashed_pw)
        db.session.add(user)
        db.session.commit()
        flash("Account created successfully", "success")
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        ip = request.remote_addr or 'unknown'
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            session['user'] = user.username
            flash("Login successful", "success")
            return redirect(url_for('dashboard'))
        else:
            count = record_failed_login(ip, form.username.data)
            if count > 20:
                flash("Too many failed attempts, try later", "danger")
            else:
                flash("Login failed", "danger")
    return render_template('login.html', form=form)

@app.route('/dashboard')
def dashboard():
    if 'user' in session:
        return render_template('dashboard.html', user=session['user'])
    return redirect(url_for('login'))

@app.route('/logout')
def logout():
    session.pop('user', None)
    flash("Logged out", "info")
    return redirect(url_for('login'))

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)