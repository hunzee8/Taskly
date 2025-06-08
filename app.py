from flask import Flask, render_template, redirect, url_for, flash, request, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_wtf import FlaskForm, CSRFProtect
from wtforms import StringField, PasswordField, SubmitField, SelectField, TextAreaField, DateField
from wtforms.validators import DataRequired, Length, Email, ValidationError, EqualTo, Regexp
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, date, timezone
from markupsafe import escape
from flask_talisman import Talisman
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import re

# App initialization
app = Flask(__name__)
app.config['SECRET_KEY'] = 'replace_with_a_strong_random_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///taskmanager.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Extensions
db = SQLAlchemy()
db.init_app(app)
csrf = CSRFProtect(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.session_protection = "strong"

limiter = Limiter(key_func=get_remote_address, default_limits=["200 per day", "50 per hour"])
limiter.init_app(app)

Talisman(app, content_security_policy={
    'default-src': ["'self'"],
    'style-src': ["'self'", "https://cdn.jsdelivr.net"],
    'script-src': ["'self'", "https://cdn.jsdelivr.net"]
})

# Models
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    tasks = db.relationship('Task', backref='owner', lazy=True)

class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    status = db.Column(db.String(20), default='To Do')
    priority = db.Column(db.String(10), default='Medium')
    start_date = db.Column(db.Date)
    due_date = db.Column(db.Date)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

# Forms
class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=20)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[
        DataRequired(), Length(min=8),
        EqualTo('confirm_password', message='Passwords must match'),
        Regexp(r'^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d@$!%*?&]{8,}$', message='Password must contain letters and numbers.')
    ])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired()])
    submit = SubmitField('Register')

    def validate_username(self, username):
        if not re.match(r'^\w+$', username.data):
            raise ValidationError('Username must contain only letters, numbers, and underscores')
        if User.query.filter_by(username=username.data).first():
            raise ValidationError('Username already taken!')

    def validate_email(self, email):
        if User.query.filter_by(email=email.data).first():
            raise ValidationError('Email already registered!')

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class TaskForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired(), Length(max=100)])
    description = TextAreaField('Description', validators=[Length(max=500)])
    status = SelectField('Status', choices=[('To Do', 'To Do'), ('In Progress', 'In Progress'), ('Done', 'Done')])
    priority = SelectField('Priority', choices=[('High', 'High'), ('Medium', 'Medium'), ('Low', 'Low')])
    start_date = DateField('Start Date', format='%Y-%m-%d', default=date.today, validators=[DataRequired()])
    due_date = DateField('Due Date', format='%Y-%m-%d', validators=[DataRequired()])
    submit = SubmitField('Save Task')

    def validate_due_date(self, due_date):
        if self.start_date.data and due_date.data < self.start_date.data:
            raise ValidationError('Due date cannot be before start date.')

# User loader
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Routes
@app.route('/')
def home():
    return render_template('home.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_pw = generate_password_hash(form.password.data)
        user = User(username=escape(form.username.data.strip()), email=escape(form.email.data.strip()), password=hashed_pw)
        db.session.add(user)
        db.session.commit()
        flash('Registered successfully! Please login.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=escape(form.username.data.strip())).first()
        if user and check_password_hash(user.password, form.password.data):
            login_user(user)
            next_page = request.args.get('next')
            return redirect(next_page or url_for('tasks'))
        flash('Invalid username or password.', 'danger')
    return render_template('login.html', form=form)

@app.route('/logout', methods=['POST'])
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('home'))

@app.route('/tasks', methods=['GET', 'POST'])
@login_required
def tasks():
    form = TaskForm()
    if form.validate_on_submit():
        task = Task(
            title=escape(form.title.data.strip()),
            description=escape(form.description.data.strip()) if form.description.data else '',
            status=form.status.data,
            priority=form.priority.data,
            start_date=form.start_date.data,
            due_date=form.due_date.data,
            owner=current_user
        )
        db.session.add(task)
        db.session.commit()
        flash("Task added!", "success")
        return redirect(url_for('tasks'))

    user_tasks = Task.query.filter_by(user_id=current_user.id).order_by(Task.due_date.asc()).all()
    return render_template('tasks.html', form=form, tasks=user_tasks)

@app.route('/edit/<int:task_id>', methods=['GET', 'POST'])
@login_required
def edit_task(task_id):
    task = Task.query.get_or_404(task_id)
    if task.owner != current_user:
        abort(403)
    form = TaskForm(obj=task)
    if form.validate_on_submit():
        task.title = escape(form.title.data.strip())
        task.description = escape(form.description.data.strip()) if form.description.data else ''
        task.status = form.status.data
        task.priority = form.priority.data
        task.start_date = form.start_date.data
        task.due_date = form.due_date.data
        db.session.commit()
        flash("Task updated!", "success")
        return redirect(url_for('tasks'))
    return render_template('edit_task.html', form=form, task=task)

@app.route('/delete/<int:task_id>', methods=['POST'])
@login_required
def delete_task(task_id):
    task = Task.query.get_or_404(task_id)
    if task.owner != current_user:
        abort(403)
    db.session.delete(task)
    db.session.commit()
    flash("Task deleted.", "info")
    return redirect(url_for('tasks'))

# Error handlers
@app.errorhandler(403)
def forbidden(e):
    return render_template('403.html'), 403

@app.errorhandler(404)
def not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(429)
def ratelimit_handler(e):
    return render_template('429.html'), 429

@app.errorhandler(500)
def server_error(e):
    return render_template('500.html'), 500

# Context processor
@app.context_processor
def inject_now():
    return {'current_year': datetime.now(timezone.utc).year}

# Run app
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
