# Chat API Documentation

This API allows users to register, login, send messages, and retrieve their message history.

## Getting Started

To run the API, you will need Python and Flask installed on your system. Once you have the prerequisites, you can run the API server using the following command from the terminal:

```sh
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
- **Success Response**: 
  - **Code**: `201 CREATED`
  - **Content**: `{ 'token': 'generated_token' }`
- **Error Response**:
  - **Code**: `400 BAD REQUEST` (Missing login or password)
  - **Code**: `409 CONFLICT` (User already exists)
- **Example**:
  {
    "username": "johndoe",
    "password": "s3cr3t"
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
  - **Code**: `401 UNAUTHORIZED` (Invalid credentials)
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
  - `text`: The text content of the message.
- **Success Response**: 
  - **Code**: `201 CREATED`
  - **Content**: `{ 'message': 'Message sent successfully' }`
- **Error Response**:
  - **Code**: `400 BAD REQUEST` (Missing data)
  - **Code**: `403 FORBIDDEN` (Invalid token)
- **Example**:
  {
    "receiver": "janedoe",
    "text": "Hello, Jane!"
  }

### Get Messages

- **URL**: `/`
- **Method**: `GET`
- **Headers**:
  - `Authorization`: Token received upon login or registration.
- **Success Response**: 
  - **Code**: `200 OK`
  - **Content**: List of messages involving the user.
- **Error Response**:
  - **Code**: `400 BAD REQUEST` (Missing token)
  - **Code**: `403 FORBIDDEN` (Invalid token)
- **Example**:
  [
    {
      "sender": "johndoe",
      "receiver": "janedoe",
      "text": "Hello, Jane!",
      "datetime": "2023-01-01T12:00:00Z"
    }
  ]

## Notes

- The token is required for authorization on message-related actions.
- The API does not currently implement encryption for passwords or secure token handling.
- The current implementation uses an in-memory structure to store users and messages, which means that data will not persist if the server is restarted.
