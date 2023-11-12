## Getting Started

To run the API, you will need Python, Flask, PyCryptodome, and bcrypt installed on your system. Once you have the prerequisites, you can run the API server using the following command from the terminal:

```
python app.py
```

This will start the Flask development server, and the API will be available at `http://127.0.0.1:5000/`.

## API Endpoints

### Register

- **URL**: `/register`
- **Method**: `POST`
- **Body**:
  - `username`: The username of the new user.
  - `password`: The password for the new user.
  - `public_key`: User's public key.
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
- **Success Response**: 
  - **Code**: `200 OK`
  - **Content**: `{ 'token': 'newly_generated_token' }`
- **Error Response**:
  - **Code**: `401 UNAUTHORIZED` (Invalid credentials or user not existing)
- **Example**:
  {
    "username": "johndoe",
    "password": "s3cr3t"
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
- **Example**:
  {
    "receiver": "janedoe",
    "text": "{RSA ENCRYPTED TEXT}"
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
- **Example**: 
[
    {
      "sender": "johndoe",
      "receiver": "janedoe",
      "text": "{RSA ENCRYPTED TEXT}",
      "datetime": "2023-01-01T12:00:00Z"
    }
]

## Notes

- Passwords are hashed using bcrypt before storing.
- Messages are encrypted using RSA encryption. Each user has a unique public/private key pair.
- The API does not currently implement a persistent storage system, which means that data will not persist if the server is restarted.
- The token is required for authorization on message-related actions.

## Dependencies

- Flask: A lightweight WSGI web application framework.
- PyCryptodome: A self-contained cryptographic library for Python.
- bcrypt: A library for hashing passwords.
