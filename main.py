from flask import Flask, request, jsonify
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
import base64
import uuid
from datetime import datetime

app = Flask(__name__)

users = {}  # This stores user information including their tokens
messages = []  # This stores messages


@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    login = data.get('username')
    password = data.get('password')
    username = data.get('username', login)
    users_key = data.get('public_key')

    if not login or not password:
        return jsonify({'error': 'Missing login or password'}), 400
    if login in users:
        return jsonify({'error': 'User already exists'}), 409

    token = str(uuid.uuid4())

    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()

    users[login] = {
        'password': password,
        'username': username,
        'token': token,
        'private_key': private_key,
        'public_key': users_key
    }
    return jsonify({'token': token, 'public_key': public_key}), 201


@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    login = data.get('username')
    password = data.get('password')

    user = users.get(login)
    if user and user['password'] == password:
        token = str(uuid.uuid4())
        user['token'] = token
        return jsonify({'token': token}), 200
    else:
        return jsonify({'error': 'Invalid credentials'}), 401


@app.route('/message', methods=['POST'])
def post_message():
    token = request.headers.get('Authorization')
    data = request.get_json()

    if not token or 'receiver' not in data or 'text' not in data:
        return jsonify({'error': 'Missing data'}), 400

    user_info = next((d for u, d in users.items() if d['token'] == token), None)

    if not user_info:
        return jsonify({'error': 'Invalid token'}), 403

    private_key = RSA.import_key(users[data['receiver']]['private_key'])
    cipher = PKCS1_v1_5.new(private_key)
    decrypted_message = cipher.decrypt(base64.b64decode(data['text']))

    messages.append({
        'sender': user_info['username'],
        'receiver': data['receiver'],
        'text': decrypted_message.decode('utf-8'),
        'datetime': datetime.now().isoformat()  # ISO 8601 format
    })
    return jsonify({'message': 'Message sent successfully'}), 201


@app.route('/', methods=['GET'])
def get_message():
    token = request.headers.get('Authorization')

    if not token:
        return jsonify({'error': 'Missing token'}), 400

    user_info = next((d for u, d in users.items() if d['token'] == token), None)
    if not user_info:
        return jsonify({'error': 'Invalid token'}), 403

    user_messages = [item for item in messages if
                      item['sender'] == user_info['username'] or item['receiver'] == user_info['login']]

    encrypted_messages = []
    public_key = RSA.import_key(user_info['public_key'])
    cipher = PKCS1_v1_5.new(public_key)

    for msg in user_messages:
        encrypted_text = cipher.encrypt(msg['text'].encode('utf-8'))
        encrypted_message = base64.b64encode(encrypted_text).decode('utf-8')
        encrypted_messages.append({
            'sender': msg['sender'],
            'receiver': msg['receiver'],
            'text': encrypted_message,
            'datetime': msg['datetime']
        })

    return jsonify(encrypted_messages)


if __name__ == '__main__':
    app.run(debug=True)
