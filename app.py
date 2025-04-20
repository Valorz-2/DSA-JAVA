import streamlit as st
import bcrypt
from PasswordManager import PasswordManager
from DatabaseHandler import DatabaseHandler
from PasswordGenerator import PasswordGenerator
import json

# Configure Streamlit page
st.set_page_config(
    page_title="Secure Password Manager",
    page_icon="🔒",
    layout="centered"
)

# Initialize DatabaseHandler
db_handler = DatabaseHandler()

# Session state initialization
if "logged_in" not in st.session_state:
    st.session_state.logged_in = False
if "username" not in st.session_state:
    st.session_state.username = ""
if "master_password" not in st.session_state:
    st.session_state.master_password = ""
if "current_tab" not in st.session_state:
    st.session_state.current_tab = "Login"
if "generated_password" not in st.session_state:
    st.session_state.generated_password = ""

# Helper functions
def login_user(username, master_password):
    user_data = db_handler.load_user(username)
    if user_data and bcrypt.checkpw(master_password.encode('utf-8'), user_data['master_password_hash']):
        st.session_state.logged_in = True
        st.session_state.username = username
        st.session_state.master_password = master_password
        return True
    return False

def register_user(username, master_password):
    if db_handler.load_user(username):
        return False

    # Generate hash separately instead of accessing it from PasswordManager
    master_password_hash = bcrypt.hashpw(master_password.encode('utf-8'), bcrypt.gensalt())
    password_manager = PasswordManager(master_password)
    db_handler.save_user(username, master_password_hash, {})
    return True

def add_password(username, master_password, service, password):
    password_manager = PasswordManager(master_password)
    encrypted_password = password_manager.encrypt_password(password)
    user_data = db_handler.load_user(username)

    if 'passwords' not in user_data:
        user_data['passwords'] = {}

    user_data['passwords'][service] = encrypted_password
    db_handler.update_passwords(username, user_data['passwords'])

def get_passwords(username, master_password):
    password_manager = PasswordManager(master_password)
    user_data = db_handler.load_user(username)

    if not user_data or 'passwords' not in user_data:
        return {}

    passwords = {}
    for service, encrypted_password in user_data['passwords'].items():
        try:
            passwords[service] = password_manager.decrypt_password(encrypted_password)
        except Exception as e:
            print(f"Error decrypting password for {service}: {e}")
            passwords[service] = "DECRYPTION_ERROR"
    return passwords

def generate_password(length, use_numbers, use_symbols):
    password_generator = PasswordGenerator(length, use_numbers, use_symbols)
    return password_generator.generate()

def logout():
    st.session_state.logged_in = False
    st.session_state.username = ""
    st.session_state.master_password = ""
    st.session_state.current_tab = "Login"

# Main app UI
st.title("Secure Password Manager")

if not st.session_state.logged_in:
    # Login/Register tabs
    tab1, tab2 = st.tabs(["Login", "Register"])

    with tab1:
        st.header("Login")
        login_username = st.text_input("Username", key="login_username")
        login_password = st.text_input("Master Password", type="password", key="login_password")
        login_button = st.button("Login")

        if login_button:
            if login_user(login_username, login_password):
                st.success("Login successful!")
                st.rerun()
            else:
                st.error("Invalid username or password")

    with tab2:
        st.header("Register")
        reg_username = st.text_input("Username", key="reg_username")
        reg_password = st.text_input("Master Password", type="password", key="reg_password")
        confirm_password = st.text_input("Confirm Master Password", type="password", key="confirm_password")
        register_button = st.button("Register")

        if register_button:
            if reg_password != confirm_password:
                st.error("Passwords do not match")
            elif not reg_username or not reg_password:
                st.error("Username and password are required")
            else:
                if register_user(reg_username, reg_password):
                    st.success("Registration successful! Please login.")
                    st.session_state.current_tab = "Login"
                    st.rerun()
                else:
                    st.error("Username already exists")
else:
    # Logged in view
    st.sidebar.title(f"Welcome, {st.session_state.username}")
    st.sidebar.button("Logout", on_click=logout)

    # Main tabs for password management
    tab1, tab2, tab3 = st.tabs(["View Passwords", "Add Password", "Generate Password"])

    with tab1:
        st.header("Your Passwords")
        master_password_verify = st.text_input("Enter Master Password to View Passwords", type="password",
                                               key="master_password_verify")

        if st.button("Verify Master Password"):
            if bcrypt.checkpw(master_password_verify.encode('utf-8'),
                              db_handler.load_user(st.session_state.username)['master_password_hash']):
                passwords = get_passwords(st.session_state.username, st.session_state.master_password)

                if not passwords:
                    st.info("No passwords saved yet. Add some passwords to get started!")
                else:
                    # Initialize session state for popup control
                    if "show_password_popup" not in st.session_state:
                        st.session_state.show_password_popup = False
                    if "current_password" not in st.session_state:
                        st.session_state.current_password = ""
                    if "current_service" not in st.session_state:
                        st.session_state.current_service = ""


                    # Function to show a password popup
                    def show_password(service, pwd):
                        st.session_state.show_password_popup = True
                        st.session_state.current_password = pwd
                        st.session_state.current_service = service


                    # Function to close the popup
                    def close_popup():
                        st.session_state.show_password_popup = False


                    # Display the popup if active
                    if st.session_state.show_password_popup:
                        with st.dialog(f"Password for {st.session_state.current_service}", on_dismiss=close_popup):
                            st.write(f"**Service:** {st.session_state.current_service}")
                            st.write(f"**Password:** {st.session_state.current_password}")
                            st.button("Close", on_click=close_popup)

                    # Display the password list
                    for service, password in passwords.items():
                        col1, col2, col3 = st.columns([2, 3, 1])
                        with col1:
                            st.text(service)
                        with col2:
                            st.text("••••••••")
                            st.button("Show password", key=f"show_{service}", on_click=show_password,
                                      args=(service, password))
                        with col3:
                            if st.button("Copy", key=f"copy_{service}"):
                                st.toast(f"Password for {service} copied to clipboard!")
            else:
                st.error("Incorrect master password")

    with tab2:
        st.header("Add New Password")
        service = st.text_input("Service/Website", key="new_service")

        # Option to enter password manually or use generated one
        password_option = st.radio(
            "Password options",
            ["Enter manually", "Use generated password"],
            horizontal=True
        )

        if password_option == "Enter manually":
            password = st.text_input("Password", key="new_password", type="password")
        else:
            password = st.session_state.generated_password
            st.text(f"Using: {'•' * len(password)}")

        if st.button("Save Password"):
            if not service or not password:
                st.error("Service and password are required")
            else:
                add_password(st.session_state.username, st.session_state.master_password, service, password)
                st.success(f"Password for {service} saved successfully!")
                st.session_state.generated_password = ""  # Clear generated password
                st.rerun()

    with tab3:
        st.header("Generate Strong Password")

        length = st.slider("Password Length", min_value=8, max_value=32, value=16)

        col1, col2 = st.columns(2)
        with col1:
            use_numbers = st.checkbox("Include Numbers", value=True)
        with col2:
            use_symbols = st.checkbox("Include Symbols", value=True)

        if st.button("Generate Password"):
            generated = generate_password(length, use_numbers, use_symbols)
            st.session_state.generated_password = generated
            st.code(generated, language=None)
            st.success("Password generated! You can use this in the 'Add Password' tab.")

        if st.session_state.generated_password and st.button("Copy to Clipboard"):
            st.toast("Generated password copied to clipboard!")