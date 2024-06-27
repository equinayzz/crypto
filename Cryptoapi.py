#==========================================================================================
# Cara menjalankan:
# $username = "admin"
# $password = "admin"                                                
# $pair = "$($username):$($password)"                                
# $encodedCredentials = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($pair))
# $basicAuthHeader = @{Authorization = "Basic $encodedCredentials"}  

# Invoke-WebRequest -Method Post -Uri "http://localhost:5000/encrypt" -ContentType "application/json" -Body '{"text":"Hello, World!"}' -Headers $basicAuthHeader
#==========================================================================================

# crypto_api.py

# from flask import Flask, request, jsonify, render_template
# from flask_httpauth import HTTPBasicAuth
# from Crypto.Cipher import AES
# from Crypto.Random import get_random_bytes
# from pymongo import MongoClient
# import os
# from werkzeug.security import generate_password_hash, check_password_hash

# app = Flask(__name__, template_folder="templates")
# auth = HTTPBasicAuth()

# @app.route('/')
# def index():
#     return render_template('index.html')

# # Konfigurasi MongoDB URI dari environment variable
# MONGO_URI = os.environ.get('MONGO_URI', 'mongodb://mongo:27017')
# client = MongoClient(MONGO_URI)
# db = client['crypto_db']
# collection = db['messages']

# @app.route('/reg', methods=['POST'])
# def registration():
#     if request.method == 'POST':
#         #ambil data dari form
#         req=request.get_json()
#         username=req["username"]
#         password=generate_password_hash(req["password"])
        
#         #cek apakah sudah ada di database
#         if users_collection.find_one({'username': username}):
#             message = "Username '{}' already exists. Choose a different one.".format(username)
#         else:
#             users_collection.insert_one({'username': username, 'password': password})
#             message = "Registration successful. Please see details in /info."
            
#     return message

# # Enkripsi teks menggunakan AES
# def encrypt_text(text, key):
#     cipher = AES.new(key, AES.MODE_EAX)
#     nonce = cipher.nonce
#     ciphertext, tag = cipher.encrypt_and_digest(text.encode('utf-8'))
#     return nonce + ciphertext + tag

# # Dekripsi teks menggunakan AES
# def decrypt_text(encrypted_text, key):
#     nonce = encrypted_text[:16]
#     tag = encrypted_text[-16:]
#     ciphertext = encrypted_text[16:-16]
#     cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
#     decrypted_text = cipher.decrypt_and_verify(ciphertext, tag)
#     return decrypted_text.decode('utf-8')

# # API endpoint untuk enkripsi teks
# @app.route('/encrypt', methods=['POST'])
# @auth.login_required
# def encrypt():
#     data = request.get_json()
#     text = data['text']
#     key = get_random_bytes(16)  # Generate random 16-byte key
#     encrypted_text = encrypt_text(text, key)
#     return jsonify({'encrypted_text': encrypted_text.hex(), 'key': key.hex()}), 200

# # API endpoint untuk dekripsi teks
# @app.route('/decrypt', methods=['POST'])
# @auth.login_required
# def decrypt():
#     data = request.get_json()
#     encrypted_text = bytes.fromhex(data['encrypted_text'])
#     key = bytes.fromhex(data['key'])
#     decrypted_text = decrypt_text(encrypted_text, key)
#     return jsonify({'decrypted_text': decrypted_text}), 200

# # Endpoint root untuk memberikan informasi API
# @app.route('/', methods=['GET'])
# def home():
#     return "Welcome to Crypto API! Please use /encrypt or /decrypt endpoints.", 200

# # Registrasi basic authentication
# @auth.verify_password
# def verify_password(username, password):
#     data = users_collection.find_one({'username': username})
#     if data and check_password_hash(data["password"], password):
#         return username

# if __name__ == '__main__':
#     app.run(debug=True, host='0.0.0.0')

from flask import Flask, request, jsonify
from flask_httpauth import HTTPBasicAuth
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from pymongo import MongoClient
import os
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
auth = HTTPBasicAuth()

# Konfigurasi MongoDB URI dari environment variable
MONGO_URI = os.environ.get('MONGO_URI', 'mongodb://mongo:27017')
client = MongoClient(MONGO_URI)
db = client['crypto_db']
collection = db['messages']
users_collection = db['users']

# Registrasi basic authentication
@auth.verify_password
def verify_password(username, password):
    user = users_collection.find_one({'username': username})
    if user and check_password_hash(user["password"], password):
        return True
    return False

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    # Check if username already exists
    if users_collection.find_one({'username': username}):
        return jsonify({'message': 'Username already exists'}), 400

    # Generate hashed password
    hashed_password = generate_password_hash(password)

    # Insert user into database
    user = {'username': username, 'password': hashed_password}
    users_collection.insert_one(user)

    return jsonify({'message': 'User registered successfully'}), 201

# Enkripsi teks menggunakan AES
def encrypt_text(text, key):
    cipher = AES.new(key, AES.MODE_EAX)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(text.encode('utf-8'))
    return nonce + ciphertext + tag

# Dekripsi teks menggunakan AES
def decrypt_text(encrypted_text, key):
    nonce = encrypted_text[:16]
    tag = encrypted_text[-16:]
    ciphertext = encrypted_text[16:-16]
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    decrypted_text = cipher.decrypt_and_verify(ciphertext, tag)
    return decrypted_text.decode('utf-8')

# API endpoint untuk enkripsi teks
@app.route('/encrypt', methods=['POST'])
@auth.login_required
def encrypt():
    data = request.get_json()
    text = data['text']
    key = get_random_bytes(16)  # Generate random 16-byte key
    encrypted_text = encrypt_text(text, key)
    return jsonify({'encrypted_text': encrypted_text.hex(), 'key': key.hex()}), 200

# API endpoint untuk dekripsi teks
@app.route('/decrypt', methods=['POST'])
@auth.login_required
def decrypt():
    data = request.get_json()
    encrypted_text = bytes.fromhex(data['encrypted_text'])
    key = bytes.fromhex(data['key'])
    decrypted_text = decrypt_text(encrypted_text, key)
    return jsonify({'decrypted_text': decrypted_text}), 200

# Endpoint root untuk memberikan informasi API
@app.route('/', methods=['GET'])
def home():
    return "Welcome to Crypto API! Please use /encrypt or /decrypt endpoints.", 200

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')


