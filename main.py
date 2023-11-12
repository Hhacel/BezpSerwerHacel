from flask import Flask, request, jsonify
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

    if not login or not password:
        return jsonify({'error': 'Missing login or password'}), 400
    if login in users:
        return jsonify({'error': 'User already exists'}), 409

    token = str(uuid.uuid4())
    users[login] = {
        'password': password,
        'username': username,
        'token': token
    }
    return jsonify({'token': token}), 201


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

    messages.append({
        'sender': user_info['username'],
        'receiver': data['receiver'],
        'text': data['text'],
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

    users_messages = [item for item in messages if
                      item['sender'] == user_info['username'] or item['receiver'] == user_info['login']]

    return jsonify(users_messages)


if __name__ == '__main__':
    app.run(debug=True)
