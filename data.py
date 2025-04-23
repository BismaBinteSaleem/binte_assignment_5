import streamlit as st
import hashlib
import os
import json
from cryptography.fernet import Fernet

# File paths for key and data storage
KEY_FILE = "secret.key"
DATA_FILE = "stored_data.json"

# Load or generate a secret key
if os.path.exists(KEY_FILE):
    with open(KEY_FILE, "rb") as key_file:
        KEY = key_file.read()
else:
    KEY = Fernet.generate_key()
    with open(KEY_FILE, "wb") as key_file:
        key_file.write(KEY)

cipher = Fernet(KEY)

# Load stored data
if os.path.exists(DATA_FILE):
    with open(DATA_FILE, "r") as file:
        stored_data = json.load(file)
else:
    stored_data = {}

# Save data function
def save_data():
    with open(DATA_FILE, "w") as file:
        json.dump(stored_data, file)

# Initialize session state variables
if 'failed_attempts' not in st.session_state:
    st.session_state.failed_attempts = 0
if 'authorized' not in st.session_state:
    st.session_state.authorized = True  # Initially authorized

# Function to hash passkey
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

# Function to encrypt data
def encrypt_data(text):
    return cipher.encrypt(text.encode()).decode()

# Function to decrypt data
def decrypt_data(label, passkey):
    global stored_data

    if label in stored_data:
        hashed_passkey = hash_passkey(passkey)
        if stored_data[label]["passkey"] == hashed_passkey:
            # Reset failed attempts after successful decryption
            st.session_state.failed_attempts = 0
            return cipher.decrypt(stored_data[label]["encrypted_text"].encode()).decode()
    
    st.session_state.failed_attempts += 1
    return None

# Streamlit UI setup
st.title("🔒 Secure Data Storage System")

# Navigation menu
menu = ["Home", "Store Data", "Retrieve Data", "Login"]
choice = st.sidebar.selectbox("Navigation", menu)

if choice == "Home":
    st.subheader("🏠 Welcome to the Secure Data System")
    st.write("Use this app to securely store and retrieve data with unique passkeys.")
    st.write("Explore the app through the navigation bar!")

elif choice == "Store Data":
    st.subheader("📂 Store Data Securely")

    # Input fields for storing data
    label = st.text_input("Enter a Label for your Data:")
    user_data = st.text_area("Enter Your Data:")
    passkey = st.text_input("Enter Passkey:", type="password")

    if st.button("Encrypt & Save"):
        if label and user_data and passkey:
            hashed_passkey = hash_passkey(passkey)
            encrypted_text = encrypt_data(user_data)
            stored_data[label] = {"encrypted_text": encrypted_text, "passkey": hashed_passkey}
            save_data()  # Save to file
            st.success("✅ Your data is safely stored!")
        else:
            st.error("⚠️ All fields are required!")

elif choice == "Retrieve Data":
    st.subheader("🔍 Retrieve Your Data")

    # Check if the user is authorized
    if not st.session_state.authorized:
        st.warning("🔐 Please login to continue.")
        st.experimental_rerun()

    label = st.text_input("Enter Label of Your Data:")
    passkey = st.text_input("Enter Passkey:", type="password")

    if st.button("Decrypt"):
        if label and passkey:
            decrypted_text = decrypt_data(label, passkey)
            
            if decrypted_text:
                st.success(f"✅ Decrypted Data: {decrypted_text}")
            else:
                attempts_left = 3 - st.session_state.failed_attempts
                st.error(f"❌ Incorrect passkey. Attempts remaining: {attempts_left}")
                if st.session_state.failed_attempts >= 3:
                    st.session_state.authorized = False
                    st.warning("🔒 Too many failed attempts. Redirecting to Login Page.")
                    st.experimental_rerun()
        else:
            st.error("⚠️ Both fields are required!")

elif choice == "Login":
    st.subheader("🔑 Reauthorization Required")

    # Login page
    login_pass = st.text_input("Enter Master Password:", type="password")

    if st.button("Login"):
        if login_pass == "admin123":  # Hardcoded for demo purposes
            st.session_state.failed_attempts = 0
            st.session_state.authorized = True
            st.success("✅ Login successful! Returning to Retrieve Data...")
            st.experimental_rerun()
        else:
            st.error("❌ Incorrect password. Please try again.")