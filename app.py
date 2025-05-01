import streamlit as st
import hashlib
import json
import os
from datetime import datetime, timedelta
from cryptography.fernet import Fernet

# Constants
USERS_FILE = 'users.json'
LOCKOUT_DURATION = timedelta(minutes=5)
MAX_FAILED_ATTEMPTS = 3

# Generate or load encryption key
if not os.path.exists('secret.key'):
    key = Fernet.generate_key()
    with open('secret.key', 'wb') as key_file:
        key_file.write(key)
else:
    with open('secret.key', 'rb') as key_file:
        key = key_file.read()
cipher = Fernet(key)

# Load users data
def load_users():
    if not os.path.exists(USERS_FILE):
        return {}
    with open(USERS_FILE, 'r') as f:
        return json.load(f)

# Save users data
def save_users(users):
    with open(USERS_FILE, 'w') as f:
        json.dump(users, f)

# Hash password
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# Encrypt data
def encrypt_data(data):
    return cipher.encrypt(data.encode()).decode()

# Decrypt data
def decrypt_data(encrypted_data):
    return cipher.decrypt(encrypted_data.encode()).decode()

# Authenticate user
def authenticate(username, password):
    users = load_users()
    user = users.get(username)

    if not user:
        return False, "User does not exist."

    # Check for lockout
    lockout_time = user.get("lockout_time")
    if lockout_time:
        lockout_time = datetime.fromisoformat(lockout_time)
        if datetime.now() < lockout_time:
            remaining = lockout_time - datetime.now()
            return False, f"Account locked. Try again in {int(remaining.total_seconds() // 60)} minutes."

    # Verify password
    if user["password"] == hash_password(password):
        # Reset failed attempts
        user["failed_attempts"] = 0
        user["lockout_time"] = None
        users[username] = user
        save_users(users)
        return True, "Login successful."
    else:
        # Increment failed attempts
        user["failed_attempts"] += 1
        if user["failed_attempts"] >= MAX_FAILED_ATTEMPTS:
            user["lockout_time"] = (datetime.now() + LOCKOUT_DURATION).isoformat()
            message = f"Account locked due to {MAX_FAILED_ATTEMPTS} failed attempts. Try again in {LOCKOUT_DURATION.total_seconds() // 60} minutes."
        else:
            message = f"Incorrect password. {MAX_FAILED_ATTEMPTS - user['failed_attempts']} attempts remaining."
        users[username] = user
        save_users(users)
        return False, message

# Registration
def register(username, password):
    users = load_users()
    if username in users:
        return False, "Username already exists."
    users[username] = {
        "password": hash_password(password),
        "failed_attempts": 0,
        "lockout_time": None,
        "data": ""
    }
    save_users(users)
    return True, "Registration successful."

# Streamlit UI
def main():
    st.title("🔐 Secure Multi-User Application")

    if 'authenticated' not in st.session_state:
        st.session_state['authenticated'] = False
    if 'username' not in st.session_state:
        st.session_state['username'] = ""

    menu = ["Home", "Login", "Register"]
    if st.session_state['authenticated']:
        menu = ["Home", "Store Data", "Retrieve Data", "Logout"]
    choice = st.sidebar.selectbox("Menu", menu)

    if choice == "Home":
        st.subheader("Welcome to the Secure Application")
        if st.session_state['authenticated']:
            st.success(f"Logged in as {st.session_state['username']}")
        else:
            st.info("Please log in to access more features.")

    elif choice == "Login":
        st.subheader("Login")

        username = st.text_input("Username")
        password = st.text_input("Password", type="password")

        if st.button("Login"):
            success, message = authenticate(username, password)
            if success:
                st.success(message)
                st.session_state['authenticated'] = True
                st.session_state['username'] = username
            else:
                st.error(message)

    elif choice == "Register":
        st.subheader("Register")

        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        confirm_password = st.text_input("Confirm Password", type="password")

        if st.button("Register"):
            if password != confirm_password:
                st.error("Passwords do not match.")
            else:
                success, message = register(username, password)
                if success:
                    st.success(message)
                else:
                    st.error(message)

    elif choice == "Store Data":
        st.subheader("Store Data Securely")
        if st.session_state['authenticated']:
            data = st.text_area("Enter data to encrypt and store:")
            if st.button("Store"):
                users = load_users()
                username = st.session_state['username']
                encrypted = encrypt_data(data)
                users[username]['data'] = encrypted
                save_users(users)
                st.success("Data stored securely.")
        else:
            st.error("Please log in to store data.")

    elif choice == "Retrieve Data":
        st.subheader("Retrieve Your Data")
        if st.session_state['authenticated']:
            users = load_users()
            username = st.session_state['username']
            encrypted = users[username].get('data', '')
            if encrypted:
                decrypted = decrypt_data(encrypted)
                st.success(f"Your data: {decrypted}")
            else:
                st.info("No data found.")
        else:
            st.error("Please log in to retrieve data.")

    elif choice == "Logout":
        st.session_state['authenticated'] = False
        st.session_state['username'] = ""
        st.success("Logged out successfully.")

if __name__ == "__main__":
    main()
