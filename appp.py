from flask import Flask, render_template, request, redirect, session, url_for, send_file, abort
from werkzeug.utils import secure_filename
from cryptography.fernet import Fernet, InvalidToken
from flask_mail import Mail, Message
import os
from datetime import datetime, timedelta
import secrets

app = Flask(__name__)
app.secret_key = b'_5#y2L"F4Q8z/n/xec]/'

# Mail configuration
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'yugee03@gmail.com'
app.config['MAIL_PASSWORD'] = 'xwdr szkx fvyu xeml'
app.config['MAIL_DEFAULT_SENDER'] = 'yugee03@gmail.com'

mail = Mail(app)

# File upload and storage paths
app.config['UPLOAD_FOLDER'] = r'C:/2nd year internship/recovery/flask_test1_UED zip/flask_test1_UED/upload'
ENCRYPTED_FOLDER = r'C:/2nd year internship/recovery/flask_test1_UED zip/flask_test1_UED/ensol'
DECRYPTED_FOLDER = r'C:/2nd year internship/recovery/flask_test1_UED zip/flask_test1_UED/decrypt'

# User credentials
USERNAME = 'yugesh'
PASSWORD = 'CFCYUGEE'

# Security questions and answers
SECURITY_QUESTIONS = {
    'cook': 'briyani',
    'first_flight': 'mumbai'
}

# Shared links for file sharing with passcode
shared_links = {}

# Utility functions
def load_or_generate_key():
    """Load an existing encryption key or generate a new one."""
    key_file = os.path.join(ENCRYPTED_FOLDER, 'key.key')
    if os.path.exists(key_file):
        with open(key_file, 'rb') as key_in:
            return key_in.read()
    else:
        key = Fernet.generate_key()
        with open(key_file, 'wb') as key_out:
            key_out.write(key)
        return key

def encrypt(file_path, key):
    """Encrypt a file using the given key."""
    with open(file_path, 'rb') as file_in:
        data = file_in.read()
    encrypted_data = Fernet(key).encrypt(data)
    encrypted_file_path = os.path.join(ENCRYPTED_FOLDER, secure_filename(file_path.split('/')[-1] + '.encrypted'))
    with open(encrypted_file_path, 'wb') as file_out:
        file_out.write(encrypted_data)

def decrypt(file_path, key):
    """Decrypt a file using the given key."""
    with open(file_path, 'rb') as file_in:
        encrypted_data = file_in.read()
    try:
        data = Fernet(key).decrypt(encrypted_data)
        decrypted_file_path = os.path.join(DECRYPTED_FOLDER, secure_filename(file_path.split('/')[-1].replace('.encrypted', '')))
        with open(decrypted_file_path, 'wb') as file_out:
            file_out.write(data)
    except InvalidToken:
        raise ValueError("Invalid encryption key or corrupted file.")

def remove_expired_links():
    """Remove expired links based on a 5-minute expiration."""
    current_time = datetime.now()
    expired_links = [
        link for link, metadata in shared_links.items() if metadata['expiration_time'] < current_time
    ]
    for link in expired_links:
        del shared_links[link]

def generate_token():
    return secrets.token_urlsafe(16)

def share_file_via_email(filename, shared_link, recipient_email, passcode):
    """Send an email with a shared file link and passcode."""
    msg = Message(subject='Shared Encrypted File',
                  recipients=[recipient_email])
    msg.body = f'You have received a shared encrypted file. Access it using the following link: {shared_link}\n\n' \
               f'Use this passcode to verify: {passcode}'
    mail.send(msg)

# Routes
@app.route("/", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form['username']
        password = request.form['password']
        security_answer_cook = request.form['security_answer_cook']
        if username == USERNAME and password == PASSWORD and SECURITY_QUESTIONS.get('cook') == security_answer_cook:
            session['logged_in'] = True
            return redirect(url_for('index'))
        else:
            return render_template('login.html', error='Invalid credentials or security answer')
    return render_template('login.html', error='')

@app.route("/index", methods=["GET", "POST"])
def index():
    if not session.get('logged_in'):
        return redirect(url_for('login'))

    if request.method == "POST":
        secret_key = request.form.get("secret_key")
        files = request.files.getlist("files[]")

        if secret_key not in ['e', 'd']:
            return render_template("result.html", message="Invalid secret key.")

        if not files:
            return render_template("result.html", message="No files selected.")

        for file in files:
            filename = secure_filename(file.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)

            key = load_or_generate_key()

            if secret_key == 'e':
                encrypt(file_path, key)
                message = "Files encrypted successfully."
            else:
                decrypt(file_path, key)
                message = "Files decrypted successfully."

        return render_template("result.html", message=message)

    return render_template("index.html")

@app.route("/share", methods=["GET", "POST"])
def share_file():
    remove_expired_links()
    if request.method == "POST":
        recipient_email = request.form.get('recipient_email')
        security_answer = request.form.get('security_answer_flight')

        if not recipient_email:
            return render_template("result.html", message="Recipient email is required.")
        elif not SECURITY_QUESTIONS.get('first_flight') == security_answer:
            return render_template("result.html", message="Security answer is incorrect.")

        selected_files = request.files.getlist('files[]')
        if not selected_files:
            return render_template("result.html", message="No files selected.")

        for file in selected_files:
            filename = secure_filename(file.filename)
            if filename.endswith('.encrypted'):
                passcode = generate_token()  # Generate a passcode for this file
                token = generate_token()
                shared_links[token] = {
                    "recipient_email": recipient_email,
                    "filename": filename,
                    "expiration_time": datetime.now() + timedelta(minutes=5),
                    "accessed": False,
                    "passcode": passcode  # Store the passcode for later verification
                }
                shared_link = url_for('download_shared_file', token=token, _external=True)
                share_file_via_email(filename, shared_link, recipient_email, passcode)
            else:
                return render_template("result.html", message="Invalid file format.")

        return render_template("result.html", message="Files shared successfully.")
    else:
        encrypted_files = os.listdir(ENCRYPTED_FOLDER)
        return render_template("share.html", encrypted_files=encrypted_files)

@app.route("/download/<token>", methods=["GET", "POST"])
def download_shared_file(token):
    remove_expired_links()
    link_data = shared_links.get(token)
    if link_data:
        filename = link_data['filename']
        expiration_time = link_data['expiration_time']
        passcode = link_data['passcode']

        encrypted_file_path = os.path.join(ENCRYPTED_FOLDER, filename)

        if datetime.now() > expiration_time:
            return render_template("result.html", message="Link has expired.")

        if link_data['accessed']:
            return render_template("result.html", message="This link has already been accessed.")

        if request.method == "POST":
            entered_passcode = request.form.get("passcode")
            if entered_passcode == passcode:
                link_data['accessed'] = True
                return send_file(encrypted_file_path, as_attachment=True)
            else:
                return render_template("passcode.html", message="Invalid passcode. Please try again.")
        else:
            return render_template("passcode.html", message="")
    else:
        return render_template("result.html", message="Invalid or expired link.")

@app.route("/blog")
def blog():
    return render_template("blog.html")
