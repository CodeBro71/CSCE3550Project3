import jwt
import base64
import os
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from Crypto.Cipher import AES
from dotenv import load_dotenv
from flask import Flask, request, jsonify
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from uuid import uuid4
from argon2 import PasswordHasher
import datetime
import sqlite3

# create a database to store the keys
connection = sqlite3.connect('totally_not_my_privateKeys.db')
cursor = connection.cursor()
cursor.execute('''CREATE TABLE IF NOT EXISTS keys(
    kid INTEGER PRIMARY KEY AUTOINCREMENT,
    key BLOB NOT NULL,
    exp INTEGER NOT NULL
)''')
connection.commit()

# create users table in db
cursor.execute('''CREATE TABLE IF NOT EXISTS users(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    email TEXT UNIQUE,
    date_registered TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP      
)''')
connection.commit()

# create auth_logs table in db
cursor.execute('''CREATE TABLE IF NOT EXISTS auth_logs(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    request_ip TEXT NOT NULL,
    request_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    user_id INTEGER,  
    FOREIGN KEY(user_id) REFERENCES users(id)
)''')
connection.commit()

# generate keys
rsa_keys = rsa.generate_private_key(65537, 2048)

# serialize keys
public_key = rsa_keys.public_key().public_bytes( serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
private_key = rsa_keys.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption())

# get AES key from NOT_MY_KEY environment variable
load_dotenv()
hex_key = os.environ.get('NOT_MY_KEY')
encryption_key = bytes.fromhex(hex_key)

# function to encrpyt a bytes object
def encrypt(msg):
    cipher = AES.new(encryption_key, AES.MODE_EAX)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(msg)
    return nonce, ciphertext, tag

# function to decrypt a bytes object
def decrypt(nonce, ciphertext, tag):
    cipher = AES.new(encryption_key, AES.MODE_EAX, nonce=nonce)
    bytes = cipher.decrypt(ciphertext)
    try:
        cipher.verify(tag)
        return bytes
    except:
        return False
    
# encrypt the private key with AES
nonce, ciphertext, tag = encrypt(private_key)

# taken from provided project 1 code
def int_to_base64(value):
    """Convert an integer to a Base64URL-encoded string"""
    value_hex = format(value, 'x')
    # Ensure even length
    if len(value_hex) % 2 == 1:
        value_hex = '0' + value_hex
    value_bytes = bytes.fromhex(value_hex)
    encoded = base64.urlsafe_b64encode(value_bytes).rstrip(b'=')
    return encoded.decode('utf-8')

# insert an unexpired encrypted key into the database
exp_time = int((datetime.datetime.now() + datetime.timedelta(hours = 1)).timestamp())
cursor.execute("INSERT INTO keys (key, exp) VALUES (?, ?)", (ciphertext, exp_time))
connection.commit()

# insert an expired encrypted key into the database
exp_time = int((datetime.datetime.now() - datetime.timedelta(hours = 1)).timestamp())
cursor.execute("INSERT INTO keys (key, exp) VALUES (?, ?)", (ciphertext, exp_time))
connection.commit()

connection.close()

# flask for http and server handling
app = Flask(__name__)
# limiter that limits requests to 10 per second
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["10/second"],
    storage_uri="memory://"
)

# route and function for /register
@app.route("/register", methods=["POST"])
@limiter.exempt
def register():
    # get username and email from POSTed JSON
    data = request.get_json()
    username = data["username"]
    email = data["email"]

    # generate password with UUIDv4
    password = uuid4()

    # hash the password with argon2
    ph = PasswordHasher()
    hash = ph.hash(password.bytes)

    # get time of registration
    date_registered = datetime.datetime.now(datetime.UTC)

    # insert user data into db
    connection = sqlite3.connect('totally_not_my_privateKeys.db')
    cursor = connection.cursor()
    cursor.execute("INSERT INTO users (username, password_hash, email, date_registered) VALUES (?, ?, ?, ?)", (username, hash, email, date_registered))
    connection.commit()
    connection.close()

    return jsonify({"password": password})

# route and function for /auth
@app.route("/auth", methods = ["POST"])
def auth():
    payload_data = {
            "Username": "root",
            "Password": "123442069",
            "exp" : datetime.datetime.now(datetime.UTC) - datetime.timedelta(hours = 1)
    }
    header = {}

    connection = sqlite3.connect('totally_not_my_privateKeys.db')
    cursor = connection.cursor()

    # expired case
    if request.args.get("expired") is not None:   
        header = {"kid": "expired"}

        # get the expired key from the database
        cursor.execute("SELECT key FROM keys WHERE exp < ?", (int(datetime.datetime.now().timestamp()),))
        key = cursor.fetchone()

    # unexpired case
    else:
        payload_data["exp"] += datetime.timedelta(hours = 2) 
        header = {"kid": "unexpired"}

        # get the unexpired key from the database
        cursor.execute("SELECT key FROM keys WHERE exp > ?", (int(datetime.datetime.now().timestamp()),))
        key = cursor.fetchone()

    # get request ip address and username from request
    data = request.get_json()
    username = data["username"]
    request_ip = request.remote_addr

    # get user_id from users table
    cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
    connection.commit()
    user_data = cursor.fetchone()
    user_id = user_data[0]

    # update auth_logs table
    cursor.execute("INSERT INTO auth_logs (request_ip, user_id) VALUES (?, ?)", (request_ip, user_id))
    connection.commit()

    connection.close()

    # decrypt key from db
    decrypted_key = decrypt(nonce, key[0], tag)

    # return token signed with key from database
    return jsonify({"token": jwt.encode(payload_data, decrypted_key, "RS256", header)})

# route and function for verifying
@app.route('/.well-known/jwks.json', methods=['GET'])
@limiter.exempt
def get_jwks():
    # get the unexpired key from the database
    connection = sqlite3.connect('totally_not_my_privateKeys.db')
    cursor = connection.cursor()
    cursor.execute("SELECT key FROM keys WHERE exp > ?", (int(datetime.datetime.now().timestamp()),))
    pems = cursor.fetchall()
    connection.close()

    key = decrypt(nonce, pems[0][0], tag)
    print("key")
    # get the public numbers from the key
    numbers = serialization.load_pem_private_key(key, password=None).private_numbers()

    # construct the jwks with data from the database
    jwks = {
        "keys": [
            {
                "alg": "RS256",
                "kty": "RSA",
                "use": "sig",
                "kid": "unexpired",
                "n": int_to_base64(numbers.public_numbers.n),
                "e": int_to_base64(numbers.public_numbers.e),
            }
        ]
    }

    return jsonify(jwks)

# run server on port 8080 (on localhost)
if __name__ == "__main__":
    try:
        app.run(port = 8080)
    # clean up the database when the server is stopped (with SIGINT)
    finally:
        connection = sqlite3.connect('totally_not_my_privateKeys.db')
        cursor = connection.cursor()
        cursor.execute("DROP TABLE keys")
        cursor.execute("DROP TABLE users")
        cursor.execute("DROP TABLE auth_logs")
        connection.commit()
        connection.close()
    #app.run(port=8080)
