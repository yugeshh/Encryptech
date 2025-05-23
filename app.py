from importlib.metadata import files
from flask import Flask, render_template, request, redirect, session, url_for, send_file
from werkzeug.utils import secure_filename
from cryptography.fernet import Fernet, InvalidToken
from flask_mail import Mail, Message
import os
from datetime import datetime, timedelta
import secrets
import json
import platform
import shutil
import stat
import logging

app = Flask(__name__)
app.secret_key = b'_5#y2L"F4Q8z/n/xec]/'

app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'yugee03@gmail.com'
app.config['MAIL_PASSWORD'] = 'xwdr szkx fvyu xeml'
app.config['MAIL_DEFAULT_SENDER'] = 'yugee03@gmail.com'

mail = Mail(app)

app.config['UPLOAD_FOLDER'] = r'D:/2nd year internship/recovery/flask_test1_UED zip/flask_test1_UED/upload'

# Define paths for encrypted and decrypted files
ENCRYPTED_FOLDER = r'D:/2nd year internship/recovery/flask_test1_UED zip/flask_test1_UED/ensol'
DECRYPTED_FOLDER = r'D:/2nd year internship/recovery/flask_test1_UED zip/flask_test1_UED/decrypt'

USERNAME = 'yugesh'
PASSWORD = 'CFCYUGEE'

# Security questions and answers
SECURITY_QUESTIONS = {
    'cook': 'briyani',
    'first_flight': 'mumbai'
}

# Dictionary to store shareable links with recipient email, expiration time, and access status
shared_links = {}

def remove_expired_links():
    """
    Remove links from shared_links if their expiration time has passed.
    """
    current_time = datetime.now()
    expired_links = [
        link
        for link, (recipient_email, filename, expiration_time, accessed) in shared_links.items()
        if expiration_time < current_time
    ]
    for link in expired_links:
        del shared_links[link]

LOG_FILE = "activity_log.txt"

LOG_FILE = "activity_log.txt"  # You can change this path as needed

def log_activity(event_type, description=None):
    """Logs activity with timestamp. Supports both simple and detailed formats."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    if description is not None:
        # New detailed format
        log_entry = f"{timestamp} | {event_type} | {description}\n"
    else:
        # Fallback to simple format
        log_entry = f"{timestamp} - {event_type}\n"

    with open(LOG_FILE, "a") as log_file:
        log_file.write(log_entry)

'''def log_activity(action, details):
    """Logs encryption, decryption, and sharing activities with timestamps."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"{timestamp} | {action} | {details}\n"
    with open(LOG_FILE, "a") as log_file:
        log_file.write(log_entry)'''

@app.route("/activity_log")
def view_activity_log():
    if not session.get('logged_in'):
        return redirect(url_for('login'))

    try:
        with open("activity_log.txt", "r") as file:
            log_contents = file.readlines()
    except FileNotFoundError:
        log_contents = ["No logs found."]

    return render_template("activity_log.html", logs=log_contents)




@app.route('/view_log')
def view_log():
    # Logic to serve the activity log file
    return send_file('activity_log.txt', as_attachment=False)

@app.route('/send_email')
def send_email():
    # Logic for the send email page
    return "Send Email Page"        


BLOG_DATA_FILE = "blog_data.json"

def load_blog_data():
    if os.path.exists(BLOG_DATA_FILE):
        with open(BLOG_DATA_FILE, "r", encoding="utf-8") as file:
            return json.load(file)
    return []

def save_blog_data(posts):
    with open(BLOG_DATA_FILE, "w", encoding="utf-8") as file:
        json.dump(posts, file, indent=4)

@app.route("/blog_1", methods=["GET"])
def show_blog():
    posts = load_blog_data()
    return render_template("blog_1.html", posts=posts)

@app.route("/blog/add", methods=["GET", "POST"])
def add_blog():
    if request.method == "POST":
        title = request.form.get("title")
        content = request.form.get("content")

        if not title or not content:
            return render_template("add_blog.html", message="Title and content are required.")

        post = {
            "title": title,
            "content": content,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }

        posts = load_blog_data()
        posts.insert(0, post)  # Newest post on top
        save_blog_data(posts)

        log_activity("Blog Post Added", f"Title: {title}")
        return redirect(url_for("show_blog"))

    return render_template("add_blog.html")

@app.route("/menu")
def menu():
    """Displays the main menu after successful login."""
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    log_activity("Menu Access", f"User: {session.get('username', 'Unknown')}")
    return render_template("menu.html")

def generate_token():
    return secrets.token_urlsafe(16)


@app.route("/hacking_practice", methods=["GET", "POST"])
def hacking_practice():
    if not session.get('logged_in'):
        return redirect(url_for('login'))

    message = None
    if request.method == "POST":
        user_input = request.form.get("test_input")

        # Normalize the input for consistent detection
        input_lower = user_input.lower() if user_input else ""
        input_upper = user_input.upper() if user_input else ""

        # SQL Injection detection
        if any(x in input_upper for x in ["' OR ", "'--", "' UNION", "1=1", "%27"]):
            message = "Potential SQL injection detected!"
            log_activity("SQL Injection Attempt", f"User input: {user_input}")

        # XSS detection
        elif "<script>" in input_lower or "onerror=" in input_lower or "%3cscript" in input_lower:
            message = "Potential XSS attack detected!"
            log_activity("XSS Attempt", f"User input: {user_input}")

        # Command Injection detection
        elif any(x in user_input for x in [";", "|", "$(", "&", "`"]):
            message = "Potential command injection detected!"
            log_activity("Command Injection Attempt", f"User input: {user_input}")

        # Directory Traversal detection
        elif "../" in user_input or "..\\" in user_input:
            message = "Potential directory traversal attack detected!"
            log_activity("Directory Traversal Attempt", f"User input: {user_input}")

        else:
            message = "Input received and logged."
            log_activity("User Input", f"Clean input received: {user_input}")

    return render_template("hacking_practice.html", message=message)



def share_file_via_email(filename, shared_link, recipient_email, file_description):
    """
    Sends an email notification with a shared file link.
    """
    msg = Message(subject=f"File Shared: {filename}",
                  recipients=[recipient_email])
    msg.body = f"The file '{filename}' has been shared with you.\n\nDescription: {file_description}\n\nLink: {shared_link}"
    mail.send(msg)


def make_file_read_only(file_path):
    # Check if the OS is Windows or Unix-based (Linux/Mac)
    if platform.system() == "Windows":
        # For Windows: We can set the file attributes to read-only
        os.chmod(file_path, stat.S_IREAD)  # Read-only permission on Windows
    else:
        # For Unix-based systems (Linux/macOS): We can remove write permission for the owner
        os.chmod(file_path, stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)  

def encrypt_file(file_path):
    # You can implement actual encryption here, for example, using Fernet or any encryption method
    encrypted_path = file_path + '.encrypted'
    shutil.copy(file_path, encrypted_path)  # In a real scenario, use an actual encryption method
    return encrypted_path

@app.route("/blog")
def blog():
    return render_template("blog.html")



@app.route("/share", methods=["GET", "POST"])
def share_file():
    remove_expired_links()

    if request.method == "POST":
        recipient_email = request.form.get('recipient_email')
        security_answer = request.form.get('security_answer_flight')
        file_description = request.form.get('file_description')  # Get file description

        if not recipient_email:
            return render_template("result.html", message="Recipient email is required.")
        elif not verify_security_answer('first_flight', security_answer):
            return render_template("result.html", message="Security answer is incorrect.")

        selected_files = request.files.getlist('files[]')
        if not selected_files:
            return render_template("result.html", message="No files selected.")

        # Track shared filenames for email notification
        shared_filenames = []

        for file in selected_files:
            filename = secure_filename(file.filename)
            if filename.endswith('.encrypted'):
                token = generate_token()
                shared_links[token] = (
                    recipient_email,
                    filename,
                    datetime.now() + timedelta(minutes=5),
                    False,
                )
                shared_link = url_for('download_shared_file', token=token, _external=True)
                share_file_via_email(filename, shared_link, recipient_email, file_description)  # Pass description
                shared_filenames.append(filename)  # Add filename to the list
            else:
                return render_template("result.html", message="Invalid file format. Only encrypted files are allowed.")

        # Send email notification to the user (yugee03@gmail.com)
        send_email_notification("Shared", shared_filenames)

        return render_template("result.html", message="Files shared successfully.")
    else:
        encrypted_files = os.listdir(ENCRYPTED_FOLDER)
        return render_template("share.html", encrypted_files=encrypted_files)



def verify_security_answer(question, answer):
    return SECURITY_QUESTIONS.get(question) == answer

import logging
from datetime import datetime

# Configure logging to log debug messages to the console
logging.basicConfig(level=logging.DEBUG)

@app.route("/download/<token>", methods=["GET", "POST"])
def download_shared_file(token):
    # Remove expired links before processing
    remove_expired_links()

    # Check if the token exists in shared_links
    if token not in shared_links:
        app.logger.debug(f"Invalid token: {token}")
        return render_template("result.html", message="Invalid data in the link.")

    # Retrieve data from shared_links
    recipient_email, filename, expiration_time, accessed = shared_links[token]

    # Check if the link has expired
    if datetime.now() > expiration_time:
        app.logger.debug(f"Link expired: {token}")
        return render_template("result.html", message="Link has expired.")

    # If the link has already been accessed, return a message
    if accessed:
        app.logger.debug("The link has already been accessed.")
        return render_template("result.html", message="This link has already been accessed.")

    # If it's a POST request, verify passcode and allow download
    if request.method == "POST":
        # Get the passcode entered by the user
        passcode = request.form.get("passcode")
        app.logger.debug(f"Entered passcode: {passcode}")  # Log the entered passcode

        # Verify the passcode
        if verify_passcode(passcode):
            # After successful access, mark the link as accessed
            shared_links[token] = (recipient_email, filename, expiration_time, True)

            # Send the file for download
            encrypted_file_path = os.path.join(ENCRYPTED_FOLDER, filename)
            if os.path.exists(encrypted_file_path):
                return send_file(encrypted_file_path, as_attachment=True)
            else:
                app.logger.debug(f"File not found: {encrypted_file_path}")
                return render_template("result.html", message="Encrypted file not found.")
        else:
            # If the passcode is incorrect
            app.logger.debug("Incorrect passcode entered.")
            return render_template("passcode.html", message="Incorrect passcode. Please try again.")
    
    # If it's a GET request, render the passcode form
    return render_template("passcode.html")




DEFAULT_PASSCODE = "66543211"

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
                  recipients=['yugee03@gmail.com'])
    msg.body = 'Files {}d successfully: {}'.format(operation, ', '.join(files))
    mail.send(msg)

def send_file_shared_notification(filename, recipient_email, file_description):
    """
    Sends a notification email to the admin ('yugee03@gmail.com') with the details of the shared file.
    """
    msg = Message(subject=f"File Shared: {filename}",
                  recipients=['yugee03@gmail.com'])
    msg.body = f"The file '{filename}' has been shared with {recipient_email}.\n\n" \
               f"Description: {file_description}\n\n" \
               f"Shared on: {datetime.now()}\n\n"
    mail.send(msg)


@app.route("/", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form['username']
        password = request.form['password']
        security_answer_cook = request.form['security_answer_cook']  # Access the security answer for cooking question
        if username == USERNAME and password == PASSWORD and security_answer_cook == 'briyani':
            session['logged_in'] = True
            return redirect(url_for('menu'))
        else:
            return render_template('login.html', error='Invalid username, password, or security answer')
    return render_template('login.html', error='')

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