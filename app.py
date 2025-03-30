from flask import Flask, render_template, request, redirect, url_for, flash, session, send_from_directory
from flask_socketio import SocketIO, join_room, leave_room, send
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_wtf import FlaskForm
from werkzeug.utils import secure_filename
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, EqualTo
import os

app = Flask(__name__)
app.config["SECRET_KEY"] = "supersecretkey"
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///chat.db"
app.config["UPLOAD_FOLDER"] = "uploads"
os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)

db = SQLAlchemy(app)
socketio = SocketIO(app)
login_manager = LoginManager()
login_manager.init_app(app)

# Allowed file extensions
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif", "mp4", "mp3", "wav"}

def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

# User Model
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(50), nullable=False)

# Chat Message Model
class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender = db.Column(db.String(50), nullable=False)
    receiver = db.Column(db.String(50), nullable=False)
    content = db.Column(db.Text, nullable=True)
    file_path = db.Column(db.String(200), nullable=True)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# User Registration Form
class RegisterForm(FlaskForm):
    username = StringField("Username", validators=[InputRequired(), Length(min=4, max=50)])
    password = PasswordField("Password", validators=[InputRequired(), Length(min=6, max=50)])
    confirm_password = PasswordField("Confirm Password", validators=[InputRequired(), EqualTo("password")])
    submit = SubmitField("Register")

# User Login Form
class LoginForm(FlaskForm):
    username = StringField("Username", validators=[InputRequired(), Length(min=4, max=50)])
    password = PasswordField("Password", validators=[InputRequired()])
    submit = SubmitField("Login")

@app.route("/", methods=["GET", "POST"])
def home():
    if current_user.is_authenticated:
        return redirect(url_for("chat"))
    
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and user.password == form.password.data:
            login_user(user)
            return redirect(url_for("chat"))
        flash("Invalid username or password", "danger")
    return render_template("login.html", form=form)

@app.route("/register", methods=["GET", "POST"])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        if User.query.filter_by(username=form.username.data).first():
            flash("Username already taken", "danger")
        else:
            new_user = User(username=form.username.data, password=form.password.data)
            db.session.add(new_user)
            db.session.commit()
            flash("Registration successful. Please login.", "success")
            return redirect(url_for("home"))
    return render_template("register.html", form=form)

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("home"))

@app.route("/chat")
@login_required
def chat():
    messages = Message.query.all()
    return render_template("chat.html", username=current_user.username, messages=messages)

@socketio.on("join")
def handle_join(data):
    join_room(data["room"])
    send(f"{data['username']} has joined the chat", room=data["room"])

@socketio.on("message")
def handle_message(data):
    send(f"{data['username']}: {data['message']}", room=data["room"])
    new_message = Message(sender=data["username"], receiver=data["room"], content=data["message"])
    db.session.add(new_message)
    db.session.commit()

@socketio.on("leave")
def handle_leave(data):
    leave_room(data["room"])
    send(f"{data['username']} has left the chat", room=data["room"])

@app.route("/upload", methods=["POST"])
@login_required
def upload_file():
    if "file" not in request.files:
        flash("No file selected", "danger")
        return redirect(url_for("chat"))

    file = request.files["file"]
    if file.filename == "":
        flash("No file selected", "danger")
        return redirect(url_for("chat"))

    if allowed_file(file.filename):
        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
        file.save(file_path)

        new_message = Message(sender=current_user.username, receiver="All", file_path=file_path)
        db.session.add(new_message)
        db.session.commit()

        flash("File uploaded successfully", "success")
    else:
        flash("Invalid file type", "danger")

    return redirect(url_for("chat"))

@app.route("/uploads/<filename>")
def uploaded_file(filename):
    return send_from_directory(app.config["UPLOAD_FOLDER"], filename)

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    socketio.run(app, debug=True)
