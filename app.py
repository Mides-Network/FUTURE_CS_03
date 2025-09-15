import os
import base64
from flask import Flask, render_template, request, send_from_directory, flash, redirect, url_for
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from werkzeug.utils import secure_filename

# Initialize Flask
app = Flask(__name__)
app.secret_key = os.urandom(16)

# Folders
UPLOAD_FOLDER = "uploads"
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Get encryption key from environment variable
file_key_b64 = os.getenv("FILE_KEY_B64")
if not file_key_b64:
    raise ValueError("FILE_KEY_B64 environment variable not set!")

FILE_KEY = base64.b64decode(file_key_b64)

# AES helpers
def encrypt_file(filepath):
    with open(filepath, "rb") as f:
        data = f.read()

    cipher = AES.new(FILE_KEY, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(data)

    encrypted_data = cipher.nonce + tag + ciphertext
    with open(filepath, "wb") as f:
        f.write(encrypted_data)

def decrypt_file(filepath):
    with open(filepath, "rb") as f:
        nonce = f.read(16)
        tag = f.read(16)
        ciphertext = f.read()

    cipher = AES.new(FILE_KEY, AES.MODE_EAX, nonce=nonce)
    data = cipher.decrypt_and_verify(ciphertext, tag)
    return data

# Routes
@app.route("/")
def index():
    files = os.listdir(UPLOAD_FOLDER)
    return render_template("index.html", files=files)

@app.route("/upload", methods=["POST"])
def upload_file():
    if "file" not in request.files:
        flash("No file part")
        return redirect(url_for("index"))

    file = request.files["file"]
    if file.filename == "":
        flash("No selected file")
        return redirect(url_for("index"))

    filename = secure_filename(file.filename)
    filepath = os.path.join(app.config["UPLOAD_FOLDER"], filename)
    file.save(filepath)

    encrypt_file(filepath)
    flash("File uploaded and encrypted successfully!")
    return redirect(url_for("index"))

@app.route("/download/<filename>")
def download_file(filename):
    filepath = os.path.join(app.config["UPLOAD_FOLDER"], filename)

    decrypted_data = decrypt_file(filepath)
    temp_path = os.path.join(app.config["UPLOAD_FOLDER"], "decrypted_" + filename)

    with open(temp_path, "wb") as f:
        f.write(decrypted_data)

    return send_from_directory(app.config["UPLOAD_FOLDER"], "decrypted_" + filename, as_attachment=True)

if __name__ == "__main__":
    app.run(debug=True)