# Password Manager Application

A secure and user-friendly password manager built with Python and Tkinter, utilizing SQLite for data storage and Fernet for encryption. This application allows users to store, manage, and protect their passwords efficiently, with added security measures like master password verification and encrypted data storage.

## Features

- **User Authentication**: Secure login and signup system using SHA-256 hashing and Fernet encryption.
- **Password Encryption**: Passwords are stored in an encrypted format using user-specific keys.
- **Master Password Protection**: Before viewing any stored passwords, users must enter their master password for added security.
- **Password Management**: Add, view, update, and delete stored passwords for various services.
- **Multi-User Support**: Supports multiple users with separate storage and encryption keys.
- **Logout Functionality**: Users can log out of the application to secure their session.
- **User-friendly Interface**: Simple and intuitive GUI built with Tkinter.

## Getting Started

### Prerequisites

- Python 3.x
- `cryptography` library for encryption
- `tkinter` library for GUI
- SQLite3 for database management

### Installation

1. **Clone the repository**:
   ```bash
   git clone https://github.com/your-username/password-manager.git
   cd password-manager
   ```

2. **Install the required dependencies**:
   ```bash
   pip install cryptography
   ```

3. **Run the application**:
   ```bash
   python password_manager.py
   ```

### Usage

1. **Signup**: If you are a new user, create an account by providing a username and password.
2. **Login**: Existing users can log in using their credentials.
3. **Add Password**: After logging in, you can add new passwords for different services.
4. **View Passwords**: View stored passwords after verifying the master password.
5. **Update Passwords**: Modify existing passwords for any service.
6. **Delete Passwords**: Remove passwords that are no longer needed.
7. **Logout**: Securely log out of your session.

## Code Overview

- **`password_manager.py`**: Main application file containing all the logic for user authentication, password management, and GUI components.

### Key Functions

- **`signup(username, password)`**: Registers a new user, storing encrypted credentials in the database.
- **`login(username, password, window)`**: Authenticates existing users by comparing hashed and encrypted credentials.
- **`add_password(user_id, service, username, password, user_key)`**: Adds a new password for a specific service, encrypted with the user's key.
- **`retrieve_passwords(user_id, user_key)`**: Retrieves and decrypts stored passwords for the logged-in user.
- **`delete_passwords(user_id, ids_to_delete)`**: Deletes selected passwords from the database.
- **`update_password(user_id, password_id, new_password, user_key)`**: Updates an existing password with a new encrypted password.
- **`generate_and_store_key(username)`**: Generates and stores a unique encryption key for each user.
- **`load_key(username)`**: Loads an existing encryption key for a user.

## Security

- **Encryption**: Uses the `Fernet` encryption scheme to securely store passwords.
- **Hashing**: Passwords are hashed using SHA-256 before being encrypted and stored.
- **Master Password**: Users must enter their master password before viewing any stored passwords, ensuring an additional layer of security.

## Contributing

Contributions are welcome! Please follow these steps:

1. Fork the repository.
2. Create a new branch (`git checkout -b feature-branch`).
3. Make your changes.
4. Commit your changes (`git commit -m 'Add new feature'`).
5. Push to the branch (`git push origin feature-branch`).
6. Create a new Pull Request.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgements

- [Fernet Encryption](https://cryptography.io/en/latest/fernet/)
- [SQLite](https://www.sqlite.org/index.html)
- [Tkinter](https://docs.python.org/3/library/tkinter.html)
- [Python](https://www.python.org/)

---

*This project was created for educational purposes and is a simple example of a password manager application. For real-world applications, consider using more advanced and tested solutions.*

### Instructions for Use
1. Replace `your-username` in the clone command with your actual GitHub username.
2. Add more details to the **Contributing** and **Acknowledgements** sections as needed.
3. You may also include screenshots or GIFs in the README to visually demonstrate how to use the application.