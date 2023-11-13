from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
import base64
import uuid
from datetime import datetime
import bcrypt
from cryptography.fernet import Fernet
import os

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///mydatabase.db'
db = SQLAlchemy(app)
cipher_suite = None


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    hashed_password = db.Column(db.String(120), nullable=False)
    token = db.Column(db.String(36), unique=True)
    private_key = db.Column(db.Text, nullable=False)
    public_key = db.Column(db.Text, nullable=False)

    @classmethod
    def create(cls, username, password, public_key):
        hashed_password = hash_password(password)
        key = RSA.generate(2048)
        private_key = key.export_key()
        token = str(uuid.uuid4())
        user = cls(username=username, hashed_password=hashed_password,
                   token=token, private_key=private_key, public_key=public_key)
        db.session.add(user)
        db.session.commit()
        return token, key.publickey().export_key()


class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    _encrypted_text = db.Column(db.Text, nullable=False)
    datetime = db.Column(db.DateTime, default=datetime.utcnow)

    @classmethod
    def create(cls, sender_id, receiver_id, text):
        message = cls(sender_id=sender_id, receiver_id=receiver_id, text=text)
        db.session.add(message)
        db.session.commit()

    @property
    def text(self):
        return cipher_suite.decrypt(self._encrypted_text.encode('utf-8')).decode('utf-8')

    @text.setter
    def text(self, plaintext):
        self._encrypted_text = cipher_suite.encrypt(plaintext.encode('utf-8')).decode('utf-8')


@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    login = data.get('username')
    password = data.get('password')
    users_key = data.get('public_key')

    if not login or not password:
        return jsonify({'error': 'Missing login or password'}), 400
    existing_user = User.query.filter_by(username=login).first()
    if existing_user:
        return jsonify({'error': 'User already exists'}), 409

    token, public_key = User.create(login, password, users_key)

    return jsonify({'token': token, 'public_key': public_key.decode('utf-8')}), 201


@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    users_key = data.get('public_key')

    user = User.query.filter_by(username=username).first()

    if user and bcrypt.checkpw(password.encode('utf-8'), user.hashed_password):

        token = str(uuid.uuid4())
        key = RSA.generate(2048)
        private_key = key.export_key()
        public_key = key.publickey().export_key()

        user.token = token
        user.private_key = private_key
        user.public_key = users_key
        db.session.commit()

        return jsonify({'token': token, 'public_key': public_key.decode('utf-8')}), 200
    else:
        return jsonify({'error': 'Invalid credentials or user not existing'}), 401


@app.route('/message', methods=['POST'])
def post_message():
    token = request.headers.get('Authorization')
    data = request.get_json()

    if not token or 'receiver' not in data or 'text' not in data:
        return jsonify({'error': 'Missing data'}), 400

    sender = User.query.filter_by(token=token).first()
    if not sender:
        return jsonify({'error': 'Invalid token'}), 403

    receiver = User.query.filter_by(username=data['receiver']).first()
    if not receiver:
        return jsonify({'error': 'Receiver not found'}), 404

    try:
        receiver_private_key = RSA.import_key(receiver.private_key)
        cipher_rsa = PKCS1_v1_5.new(receiver_private_key)
        decrypted_message = cipher_rsa.decrypt(base64.b64decode(data['text']), None)

        # Check if decryption was successful
        if decrypted_message is None:
            raise ValueError('Unable to decrypt message')

        new_message = Message(
            sender_id=sender.id,
            receiver_id=receiver.id,
            text=decrypted_message.decode('utf-8'),
            datetime=datetime.now()
        )

        db.session.add(new_message)
        db.session.commit()

        return jsonify({'message': 'Message sent successfully'}), 201
    except ValueError as e:
        return jsonify({'error': str(e)}), 422


@app.route('/', methods=['GET'])
def get_message():
    token = request.headers.get('Authorization')

    if not token:
        return jsonify({'error': 'Missing token'}), 400

    # Find the user by the token
    user = User.query.filter_by(token=token).first()
    if not user:
        return jsonify({'error': 'Invalid token'}), 403

    # Get the messages where the user is either the sender or receiver
    user_messages = Message.query.filter(
        (Message.sender_id == user.id) | (Message.receiver_id == user.id)
    ).all()

    encrypted_messages = []
    public_key = RSA.import_key(user.public_key)
    cipher = PKCS1_v1_5.new(public_key)

    # Encrypt the messages before sending them
    for msg in user_messages:
        # Retrieve the associated user for each message
        sender = User.query.get(msg.sender_id)
        receiver = User.query.get(msg.receiver_id)

        encrypted_text = cipher.encrypt(msg.text.encode('utf-8'))
        encrypted_message = base64.b64encode(encrypted_text).decode('utf-8')
        encrypted_messages.append({
            'sender': sender.username,
            'receiver': receiver.username,
            'text': encrypted_message,
            'datetime': msg.datetime.isoformat()  # Ensure datetime is in ISO format
        })

    return jsonify(encrypted_messages)


# Hash a password
def hash_password(plain_text_password):
    password_bytes = plain_text_password.encode('utf-8')
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password_bytes, salt)
    return hashed_password


# Check a password
def check_password(plain_text_password, hashed_password):
    password_bytes = plain_text_password.encode('utf-8')
    return bcrypt.checkpw(password_bytes, hashed_password)


def get_or_create_key(file_path):
    try:
        if not os.path.exists(file_path):
            key = Fernet.generate_key()
            with open(file_path, 'wb') as key_file:
                key_file.write(key)
            return key
        else:
            with open(file_path, 'rb') as key_file:
                key = key_file.read()
            return key
    except Exception as e:
        print(f"An error occurred while handling the key file: {e}")
        raise


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    fernet_key = get_or_create_key("./fernet.key")
    cipher_suite = Fernet(fernet_key)
    app.run(debug=True)
