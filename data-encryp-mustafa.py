import streamlit as st
from cryptography.fernet import Fernet, InvalidToken
from datetime import datetime, timedelta

max_attempts = 3
lockout_duration = timedelta(minutes=1)

if "authenticated" not in st.session_state:
    st.session_state.authenticated = False

if "attempts" not in st.session_state:
    st.session_state.attempts = 0

if "lockout_time" not in st.session_state:
    st.session_state.lockout_time = None

if "key" not in st.session_state:
    st.session_state.key = Fernet.generate_key()
    st.session_state.cipher = Fernet(st.session_state.key)

def encrypt_message(message):
    return st.session_state.cipher.encrypt(message.encode()).decode()

def decrypt_message(token):
    try:
        return st.session_state.cipher.decrypt(token.encode()).decode()
    except InvalidToken:
        return None

def login():
    st.title("Secure Data Encryption System")
    if st.session_state.lockout_time and datetime.now() < st.session_state.lockout_time:
        st.warning("Too many failed attempts. Please try again later.")
        return
    username = st.text_input("Username", max_chars=20)
    password = st.text_input("Password", type="password")
    if st.button("Login"):
        if username == "admin" and password == "admin123":
            st.session_state.authenticated = True
            st.session_state.attempts = 0
            st.session_state.lockout_time = None
            st.success("Login successful!")
        else:
            st.session_state.attempts += 1
            if st.session_state.attempts >= max_attempts:
                st.session_state.lockout_time = datetime.now() + lockout_duration
            st.error("Invalid credentials. Please try again.")

def encryption_system():
    st.sidebar.title("Navigation")
    choice = st.sidebar.radio("Select an action", ["Encrypt", "Decrypt"])

    if choice == "Encrypt":
        plain_text = st.text_area("Enter the text to encrypt", height=200, key="plain_text")
        if st.button("Encrypt Text"):
            if plain_text:
                encrypted = encrypt_message(plain_text)
                st.session_state.encrypted_text = encrypted
                st.session_state.key_display = st.session_state.key.decode()
                st.success(f"Encrypted Text:\n{encrypted}")
                st.info(f"Encryption Key:\n{st.session_state.key.decode()}")
            else:
                st.error("Please enter some text to encrypt.")

    elif choice == "Decrypt":
        encrypted_text = st.text_area("Enter the encrypted text", height=200, value=st.session_state.get("encrypted_text", ""), key="encrypted_text")
        user_key = st.text_input("Enter encryption key", type="password", value=st.session_state.get("key_display", ""))
        if st.button("Decrypt Text"):
            if user_key.encode() == st.session_state.key:
                decrypted = decrypt_message(encrypted_text)
                if decrypted:
                    st.success(f"Decrypted Text:\n{decrypted}")
                else:
                    st.error("Invalid encrypted text!")
            else:
                st.error("Invalid encryption key!")

def main():
    if not st.session_state.authenticated:
        login()
    else:
        encryption_system()

if __name__ == "__main__":
    main()
