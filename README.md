# Chat API Documentation

This API allows users to register, login, send encrypted messages, and retrieve their encrypted message history with an integrated SQLAlchemy database.

## Getting Started

To run the API, you will need Python, Flask, Flask-SQLAlchemy, PyCryptodome, and bcrypt installed on your system. You should also ensure you have a `mydatabase.db` file created in the root directory or update the `SQLALCHEMY_DATABASE_URI` to match your database configuration. Once you have the prerequisites, you can run the API server using the following command from the terminal:

```
python main.py
```

This will start the Flask development server, and the API will be available at `http://127.0.0.1:5000/`.

## API Endpoints

### Register

- **URL**: `/register`
- **Method**: `POST`
- **Body**:
  - `username`: The username of the new user.
  - `password`: The password for the new user.
  - `public_key`: User's public RSA key.
- **Success Response**: 
  - **Code**: `201 CREATED`
  - **Content**: `{ 'token': 'generated_token', 'public_key': 'server_generated_public_key' }`
- **Error Response**:
  - **Code**: `400 BAD REQUEST` (Missing login or password)
  - **Code**: `409 CONFLICT` (User already exists)
- **Example**:
  {
    "username": "johndoe",
    "password": "s3cr3t",
    "public_key": "user_public_key_string"
  }

### Login

- **URL**: `/login`
- **Method**: `POST`
- **Body**:
  - `username`: Registered username.
  - `password`: Password for the user.
  - `public_key`: User's public RSA key.
- **Success Response**: 
  - **Code**: `200 OK`
  - **Content**: `{ 'token': 'newly_generated_token', 'public_key': 'server_generated_public_key' }`
- **Error Response**:
  - **Code**: `401 UNAUTHORIZED` (Invalid credentials or user not existing)
- **Example**:
  {
    "username": "johndoe",
    "password": "s3cr3t",
    "public_key": "new_user_public_key_string"
  }

### Send Message

- **URL**: `/message`
- **Method**: `POST`
- **Headers**:
  - `Authorization`: Token received upon login or registration.
- **Body**:
  - `receiver`: Username of the message receiver.
  - `text`: Base64-encoded encrypted text content of the message.
- **Success Response**: 
  - **Code**: `201 CREATED`
  - **Content**: `{ 'message': 'Message sent successfully' }`
- **Error Response**:
  - **Code**: `400 BAD REQUEST` (Missing data)
  - **Code**: `403 FORBIDDEN` (Invalid token)
  - **Code**: `404 NOT FOUND` (Receiver not found)
  - **Code**: `422 UNPROCESSABLE ENTITY` (Unable to decrypt message)
- **Example**:
  {
    "receiver": "janedoe",
    "text": "Base64_encoded_encrypted_text"
  }

### Get Messages

- **URL**: `/`
- **Method**: `GET`
- **Headers**:
  - `Authorization`: Token received upon login or registration.
- **Success Response**: 
  - **Code**: `200 OK`
  - **Content**: List of encrypted messages involving the user.
- **Error Response**:
  - **Code**: `400 BAD REQUEST` (Missing token)
  - **Code**: `403 FORBIDDEN` (Invalid token)
- **Example**: Not applicable (returns encrypted data)

## Models

### User

- Stores user credentials, tokens, and RSA keys.
- `id`: Primary key.
- `username`: Unique username.
- `hashed_password`: Password hashed using bcrypt.
- `token`: Unique session token.
- `private_key`: RSA private key for user.
- `public_key`: RSA public key for user.

### Message

- Stores the messages sent between users.
- `id`: Primary key.
- `sender_id`: ForeignKey to User model (sender).
- `receiver_id`: ForeignKey to User model (receiver).
- `text`: Encrypted message text.
- `datetime`: Timestamp of when the message was sent.

## Notes

- Passwords are hashed using bcrypt before storing in the database.
- Messages are encrypted using RSA encryption.
- The API uses an SQLite database to persist data.
- The token is required for authorization on message-related actions.

## Dependencies

- Flask: A lightweight WSGI web application framework.
- Flask-SQLAlchemy: An extension for Flask that adds support for SQLAlchemy.
- PyCryptodome: A self-contained cryptographic library for Python.
- bcrypt: A library for hashing passwords.
