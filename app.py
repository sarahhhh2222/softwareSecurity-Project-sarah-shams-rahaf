from flask import Flask, render_template, redirect, url_for, flash, request
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from cryptography.fernet import Fernet
from dotenv import load_dotenv
from database import db
import os
import bcrypt

load_dotenv()

app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "supersecretkey")
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///app.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db.init_app(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

FERNET_KEY = os.getenv("FERNET_KEY")
if not FERNET_KEY:
    raise ValueError("FERNET_KEY is missing. Please add it to .env file.")
cipher = Fernet(FERNET_KEY.encode())

from models import User, Note
from forms import RegisterForm, LoginForm, NoteForm

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route("/")
def home():
    return redirect(url_for("login"))

@app.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))

    form = RegisterForm()
    if form.validate_on_submit():
        existing_user = User.query.filter_by(email=form.email.data).first()
        if existing_user:
            flash("Email already registered.", "danger")
            return redirect(url_for("register"))

        hashed_password = bcrypt.hashpw(form.password.data.encode("utf-8"), bcrypt.gensalt())

        role = "user"
        if User.query.count() == 0:
            role = "admin"  # أول مستخدم نخليه أدمن للتجربة

        new_user = User(
            username=form.username.data,
            email=form.email.data,
            password_hash=hashed_password.decode("utf-8"),
            role=role
        )
        db.session.add(new_user)
        db.session.commit()

        flash("Registration successful. Please login.", "success")
        return redirect(url_for("login"))

    return render_template("register.html", form=form)

@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))

    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()

        if user and bcrypt.checkpw(form.password.data.encode("utf-8"), user.password_hash.encode("utf-8")):
            login_user(user)
            flash("Login successful.", "success")
            return redirect(url_for("dashboard"))
        else:
            flash("Invalid email or password.", "danger")

    return render_template("login.html", form=form)

@app.route("/dashboard")
@login_required
def dashboard():
    notes = Note.query.filter_by(user_id=current_user.id).all()
    decrypted_notes = []

    for note in notes:
        decrypted_text = cipher.decrypt(note.encrypted_content.encode()).decode()
        decrypted_notes.append({
            "id": note.id,
            "content": decrypted_text
        })

    return render_template("dashboard.html", notes=decrypted_notes)

@app.route("/add_note", methods=["GET", "POST"])
@login_required
def add_note():
    form = NoteForm()
    if form.validate_on_submit():
        encrypted_text = cipher.encrypt(form.content.data.encode()).decode()
        note = Note(user_id=current_user.id, encrypted_content=encrypted_text)
        db.session.add(note)
        db.session.commit()
        flash("Note added securely.", "success")
        return redirect(url_for("dashboard"))

    return render_template("add_note.html", form=form)

@app.route("/admin")
@login_required
def admin():
    if current_user.role != "admin":
        flash("Unauthorized access.", "danger")
        return redirect(url_for("dashboard"))

    users = User.query.all()
    return render_template("admin.html", users=users)

@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("Logged out successfully.", "info")
    return redirect(url_for("login"))

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)