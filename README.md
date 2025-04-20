# DSA-JAVA
# Secure Password Manager
A robust, secure, and user-friendly password manager built with Python and Streamlit, designed to safely store, manage, and generate strong passwords. This application leverages cryptographic techniques to ensure the security of your sensitive data and integrates with MongoDB for persistent storage.
Features

# Secure Password Storage: 
Encrypts passwords using the Fernet symmetric encryption (from the cryptography library) and optionally AES-GCM for enhanced security.
User Authentication: Supports user registration and login with securely hashed master passwords using bcrypt.
Password Generation: Generates strong, customizable passwords with options for length, numbers, and symbols.
MongoDB Integration: Stores user data and encrypted passwords in a MongoDB database for reliable persistence.
Streamlit UI: Provides an intuitive web-based interface for easy interaction.
Password Management: Allows users to add, view, and copy passwords securely with master password verification.
Session Management: Maintains user sessions using Streamlit's session state for a seamless experience.

# Tech Stack

Python: Core programming language.
Streamlit: For the web-based user interface.
MongoDB: Database for storing user data and encrypted passwords.
Cryptography Libraries:
cryptography.fernet: For symmetric encryption of passwords.
pycryptodome: For AES-GCM encryption (optional alternative).
bcrypt: For secure hashing of master passwords.


PyMongo: For MongoDB interactions.
python-dotenv: For managing environment variables.

Installation
Prerequisites

Python 3.8+
MongoDB instance (local or cloud, e.g., MongoDB Atlas)
Git (optional, for cloning the repository)

# Steps

Set Up a Virtual Environment (recommended):
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate


Install Dependencies:
pip install -r requirements.txt


Configure Environment Variables:Create a .env file in the project root and add your MongoDB URI:
MONGO_URI=mongodb://your-mongodb-uri


Run the Application:
streamlit run app.py


Access the App:Open your browser and navigate to http://localhost:8501.


Usage

Register:

Go to the "Register" tab.
Enter a unique username and a strong master password.
Confirm the password and click "Register".


Login:

Go to the "Login" tab.
Enter your username and master password.
Click "Login" to access your dashboard.


Manage Passwords:

View Passwords: Verify your master password to see your stored passwords. Click "Show password" to view or "Copy" to copy to the clipboard.
Add Password: Enter a service/website name and either manually input a password or use a generated one. Click "Save Password".
Generate Password: Customize the password length and character types, then click "Generate Password". Copy or use it directly in the "Add Password" tab.


Logout:

Click the "Logout" button in the sidebar to end your session.



Security Features

Password Encryption: All passwords are encrypted using Fernet (based on AES-128 in CBC mode) or AES-GCM (with scrypt key derivation for enhanced security).
Master Password Hashing: Master passwords are hashed with bcrypt for secure storage.
Secure Key Management: Encryption keys are stored securely and generated only once per installation.
Session Security: Streamlit session state ensures secure user sessions without storing sensitive data in plaintext.

## Project Structure
secure-password-manager/
app.py                  
PasswordManager.py      
PasswordEncryptor.py    
PasswordGenerator.py    
DatabaseHandler.py      
.env                   
requirements.txt       
README.md               

# Requirements
See requirements.txt for a complete list. Key dependencies include:
streamlit
pymongo
python-dotenv
cryptography
pycryptodome
bcrypt






