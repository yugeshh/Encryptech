from flask import Flask, render_template, request, redirect, session, url_for, send_file, abort,current_app
from werkzeug.utils import secure_filename
from cryptography.fernet import Fernet, InvalidToken
from flask_mail import Mail, Message
import os
from datetime import datetime, timedelta
import secrets
import glob

app = Flask(__name__)
app.secret_key = b'_5#y2L"F4Q8z/n/xec]/'

app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'hemaa210604@gmail.com'
app.config['MAIL_PASSWORD'] = 'xwdr szkx fvyu xeml'
app.config['MAIL_DEFAULT_SENDER'] = 'hemaa210604@gmail.com'

mail = Mail(app)

app.config['UPLOAD_FOLDER'] = r'D:/clg stuffs/yug prj/flask_test1_UED (5) blog/flask_test1_UED/upload'

# Define paths for encrypted and decrypted files
ENCRYPTED_FOLDER = r'D:/clg stuffs/yug prj/flask_test1_UED (5) blog/flask_test1_UED/ensol'
DECRYPTED_FOLDER = r'D:/clg stuffs/yug prj/flask_test1_UED (5) blog/flask_test1_UED/decrypt'

USERNAME = 'xyz'
PASSWORD = 'xyz'

# Security questions and answers
SECURITY_QUESTIONS = {
    'cook': 'briyani',
    'first_flight': 'mumbai'
}

# Dictionary to store shareable links with recipient email and expiration time
shared_links = {}

def remove_expired_links():
    current_time = datetime.now()
    expired_links = [link for link, (recipient_email, filename, expiration_time) in shared_links.items() if expiration_time < current_time]
    for link in expired_links:
        del shared_links[link]

def generate_token():
    return secrets.token_urlsafe(16)

def share_file_via_email(filename, shared_link, recipient_email):
    with app.app_context():
        msg = Message(subject='Shared Encrypted File',
                      recipients=[recipient_email])
        msg.body = f'You have received a shared encrypted file. Access it using the following link: {shared_link}'
        
        # Attach the encrypted file to the email
        with app.open_resource(os.path.join(ENCRYPTED_FOLDER, filename), 'rb') as encrypted_file:
            msg.attach(filename, 'application/octet-stream', encrypted_file.read())
        
        mail.send(msg)

@app.route("/share", methods=["GET", "POST"])
def share_file():
    remove_expired_links()
    if request.method == "POST":
        recipient_email = request.form.get('recipient_email')
        security_answer = request.form.get('security_answer_flight')
        if not recipient_email:
            return render_template("result.html", message="Recipient email is required.")
        elif not verify_security_answer('first_flight', security_answer):
            return render_template("result.html", message="Security answer is incorrect.")
        
        selected_files = request.files.getlist('files[]')  # Get the list of selected files
        if not selected_files:
            return render_template("result.html", message="No files selected.")
        
        for file in selected_files:
            filename = secure_filename(file.filename)
            if filename.endswith('.encrypted'):
                token = generate_token()
                shared_links[token] = (recipient_email, filename, datetime.now() + timedelta(days=1))
                shared_link = url_for('download_shared_file', token=token, _external=True)
                share_file_via_email(filename, shared_link, recipient_email)
            else:
                return render_template("result.html", message="Invalid file format.")
        
        return render_template("result.html", message="Files shared successfully.")
    else:
        encrypted_files = os.listdir(ENCRYPTED_FOLDER)  # Get a list of encrypted files
        return render_template("share.html", encrypted_files=encrypted_files)

def verify_security_answer(question, answer):
    return SECURITY_QUESTIONS.get(question) == answer

@app.route("/download/<token>", methods=["GET", "POST"])
def download_shared_file(token):
    remove_expired_links()
    link_data = shared_links.get(token)
    if link_data is not None and len(link_data) >= 2:
        recipient_email = link_data[0]
        filename = link_data[1]
        encrypted_file_path = os.path.join(ENCRYPTED_FOLDER, filename)
        
        if os.path.exists(encrypted_file_path):
            if request.method == "POST":
                passcode = request.form.get("passcode")
                if verify_passcode(passcode):
                    return send_file(encrypted_file_path, as_attachment=True)
                else:
                    return render_template("passcode.html", message="Incorrect passcode.")
            else:
                return render_template("passcode.html")
        else:
            return render_template("result.html", message="Encrypted file not found.")
    else:
        return render_template("result.html", message="Invalid or expired link.")

DEFAULT_PASSCODE = "123456"

def verify_passcode(passcode):
    return passcode == DEFAULT_PASSCODE


def load_or_generate_key():
    if os.path.exists("Secret.key"):
        return load_key()
    else:
        generate_key()
        return load_key()

def generate_key():
    if not os.path.exists("Secret.key"):
        key = Fernet.generate_key()
        with open("Secret.key", "wb") as key_file:
            key_file.write(key)

def load_key():
    if os.path.exists("Secret.key"):
        with open("Secret.key", "rb") as key_file:
            return key_file.read()
    else:
        raise FileNotFoundError("Secret.key not found")

def encrypt(filename, key):
    f = Fernet(key)
    with open(filename, "rb") as file:
        file_data = file.read()
        encrypted_data = f.encrypt(file_data)
    encrypted_filename = os.path.join(ENCRYPTED_FOLDER, os.path.basename(filename) + ".encrypted")
    os.makedirs(os.path.dirname(encrypted_filename), exist_ok=True)
    with open(encrypted_filename, "wb") as encrypted_file:
        encrypted_file.write(encrypted_data)
    return encrypted_filename

def decrypt(filename, key):
    f = Fernet(key)
    with open(filename, "rb") as file:
        encrypted_data = file.read()
        try:
            decrypted_data = f.decrypt(encrypted_data)
        except InvalidToken:
            app.logger.error("Invalid token. Failed to decrypt file: %s", filename)
            return None
    decrypted_filename = os.path.join(DECRYPTED_FOLDER, os.path.basename(filename)[:-10])
    os.makedirs(os.path.dirname(decrypted_filename), exist_ok=True)
    with open(decrypted_filename, "wb") as decrypted_file:
        decrypted_file.write(decrypted_data)
    return decrypted_filename

def send_email_notification(operation, files):
    msg = Message(subject='File {} Notification'.format(operation),
                  recipients=['hemaa210604@gmail.com'])
    msg.body = 'Files {}d successfully: {}'.format(operation, ', '.join(files))
    mail.send(msg)

@app.route("/", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form['username']
        password = request.form['password']
        security_answer_cook = request.form['security_answer_cook']  # Access the security answer for cooking question
        if username == USERNAME and password == PASSWORD and security_answer_cook == 'briyani':
            session['logged_in'] = True
            return redirect(url_for('index'))
        else:
            return render_template('login.html', error='Invalid username, password, or security answer')
    return render_template('login.html', error='')


@app.route("/blog")
def blog():
    return render_template("blog.html")


@app.route("/index", methods=["GET", "POST"])
def index():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    
    if request.method == "POST":
        secret_key = request.form.get("secret_key")  # Get the secret key 
        files = request.files.getlist("files[]")
        
        if secret_key not in ['e', 'd']:  # Ensure the secret key is valid
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
                message = f"Files encrypted successfully."
            else:
                decrypt(file_path, key)
                message = f"Files decrypted successfully."
                
        send_email_notification('Encryption' if secret_key == 'e' else 'Decryption', [file.filename for file in files])     

        return render_template("result.html", message=message)
    
    return render_template("index.html")

if __name__ == "__main__":
    app.run(debug=True)
