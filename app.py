import streamlit as st
import bcrypt
from PasswordManager import PasswordManager
from DatabaseHandler import DatabaseHandler
from PasswordGenerator import PasswordGenerator
import base64
from datetime import datetime
import pyperclip

# Configure Streamlit page
st.set_page_config(
    page_title="Secure Password Manager",
    page_icon="🔒",
    layout="centered"
)

# Cache the background image to avoid reloading
@st.cache_data
def load_background_image():
    with open(r"C:\Users\heman\Documents\DSA Project\backend\c64388745778f06331fd6571e4363935.jpg", "rb") as image_file:
        return base64.b64encode(image_file.read()).decode()

# Load background image
encoded_image = load_background_image()

# Inject custom CSS for animations, background, and text color
st.markdown(f"""
    <style>
    /* Background image styling and remove top bar */
    .stApp {{
        background-image: url('data:image/jpeg;base64,{encoded_image}');
        background-size: cover;
        background-position: center;
        background-repeat: no-repeat;
        background-attachment: fixed;
        opacity: 0.9;
        padding-top: 0px !important;
    }}

    /* Title animation and glow effect */
    .title {{
        font-size: 2.5em;
        font-weight: bold;
        color: #ffffff;
        text-align: center;
        animation: slideIn 1.5s ease-out, glow 2s infinite alternate;
        margin-bottom: 20px;
    }}

    /* Slide-in animation */
    @keyframes slideIn {{
        0% {{
            transform: translateY(-100vh);
            opacity: 0;
        }}
        100% {{
            transform: translateY(0);
            opacity: 1;
        }}
    }}

    /* Glow effect (white only) */
    @keyframes glow {{
        0% {{
            text-shadow: 0 0 5px #ffffff, 0 0 10px #ffffff, 0 0 15px #ffffff;
        }}
        100% {{
            text-shadow: 0 0 10px #ffffff, 0 0 20px #ffffff, 0 0 30px #ffffff;
        }}
    }}

    /* Ensure text remains readable */
    .stTextInput, .stButton, .stTabs, .stSidebar, .stToast, .stSuccess, .stError, .stInfo {{
        background-color: rgba(255, 255, 255, 0.0);
        border-radius: 5px;
        padding: 5px;
    }}

    /* Adjust sidebar styling */
    .stSidebar {{
        background-color: rgba(0, 0, 0, 0.7);
        color: #ffffff;
    }}

    /* Change text color for login and register page elements */
    .stHeader, .stTextInput label, .stButton > button {{
        color: #32CD32 !important;
    }}

    /* Change tab text color for Login and Register */
    .stTabs [data-baseweb="tab"] {{
        color: #ffffff !important;
    }}

    /* Ensure active tab text is also styled */
    .stTabs [data-baseweb="tab"][aria-selected="true"] {{
        color: #32CD32 !important;
    }}
    </style>
""", unsafe_allow_html=True)

# Cache DatabaseHandler initialization
@st.cache_resource
def init_db_handler():
    return DatabaseHandler()

# Initialize DatabaseHandler
db_handler = init_db_handler()

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
if "master_password_verified" not in st.session_state:
    st.session_state.master_password_verified = False
if "last_login" not in st.session_state:
    st.session_state.last_login = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
if "passwords_cache" not in st.session_state:
    st.session_state.passwords_cache = None

# Helper functions
@st.cache_data(show_spinner=False)
def login_user(username, master_password):
    user_data = db_handler.load_user(username)
    if user_data and bcrypt.checkpw(master_password.encode('utf-8'), user_data['master_password_hash']):
        return True, user_data
    return False, None

@st.cache_data(show_spinner=False)
def register_user(username, master_password):
    if db_handler.load_user(username):
        return False
    master_password_hash = bcrypt.hashpw(master_password.encode('utf-8'), bcrypt.gensalt())
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
    # Invalidate cache
    st.session_state.passwords_cache = None

@st.cache_data(show_spinner=False)
def get_passwords(username, master_password, _cache_key):
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
    st.session_state.master_password_verified = False
    st.session_state.passwords_cache = None

def verify_master_password(entered_password):
    user_data = db_handler.load_user(st.session_state.username)
    if user_data and bcrypt.checkpw(entered_password.encode('utf-8'), user_data['master_password_hash']):
        return True
    return False

@st.cache_data(show_spinner=False)
def get_password_count(username):
    user_data = db_handler.load_user(username)
    return len(user_data.get('passwords', {}))

# Main app UI
st.markdown('<div class="title">Secure Password Manager</div>', unsafe_allow_html=True)

if not st.session_state.logged_in:
    tab1, tab2 = st.tabs(["Login", "Register"])

    with tab1:
        st.header("Login")
        with st.form("login_form"):
            login_username = st.text_input("Username", key="login_username")
            login_password = st.text_input("Master Password", type="password", key="login_password")
            login_button = st.form_submit_button("Login")
            if login_button:
                success, user_data = login_user(login_username, login_password)
                if success:
                    st.session_state.logged_in = True
                    st.session_state.username = login_username
                    st.session_state.master_password = login_password
                    st.session_state.last_login = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    st.success("Login successful!")
                else:
                    st.error("Invalid username or password")

    with tab2:
        st.header("Register")
        with st.form("register_form"):
            reg_username = st.text_input("Username", key="reg_username")
            reg_password = st.text_input("Master Password", type="password", key="reg_password")
            confirm_password = st.text_input("Confirm Master Password", type="password", key="confirm_password")
            register_button = st.form_submit_button("Register")
            if register_button:
                if reg_password != confirm_password:
                    st.error("Passwords do not match")
                elif not reg_username or not reg_password:
                    st.error("Username and password are required")
                else:
                    if register_user(reg_username, reg_password):
                        st.success("Registration successful! Please login.")
                        st.session_state.current_tab = "Login"
                    else:
                        st.error("Username already exists")
else:
    st.sidebar.title(f"Welcome, {st.session_state.username}")
    st.sidebar.write(f"**Last Login:** {st.session_state.last_login}")
    st.sidebar.write(f"**Saved Passwords:** {get_password_count(st.session_state.username)}")
    st.sidebar.button("Logout", on_click=logout)

    tab1, tab2, tab3 = st.tabs(["View Passwords", "Add Password", "Generate Password"])

    with tab1:
        st.header("Your Passwords")
        if not st.session_state.master_password_verified:
            with st.form("verify_form"):
                master_password_verify = st.text_input("Enter Master Password to View Passwords", type="password", key="master_password_verify")
                verify_button = st.form_submit_button("Verify Master Password")
                if verify_button:
                    if verify_master_password(master_password_verify):
                        st.session_state.master_password_verified = True
                        st.success("Master password verified!")
                    else:
                        st.error("Incorrect master password")
        else:
            # Use cached passwords if available
            cache_key = f"{st.session_state.username}_{st.session_state.master_password}"
            if st.session_state.passwords_cache is None:
                st.session_state.passwords_cache = get_passwords(st.session_state.username, st.session_state.master_password, cache_key)
            passwords = st.session_state.passwords_cache

            if not passwords:
                st.info("No passwords saved yet. Add some passwords to get started!")
            else:
                if "show_password_popup" not in st.session_state:
                    st.session_state.show_password_popup = False
                if "current_password" not in st.session_state:
                    st.session_state.current_password = ""
                if "current_service" not in st.session_state:
                    st.session_state.current_service = ""

                def show_password(service, pwd):
                    st.session_state.show_password_popup = True
                    st.session_state.current_password = pwd
                    st.session_state.current_service = service

                def close_popup():
                    st.session_state.show_password_popup = False

                if st.session_state.show_password_popup:
                    with st.container():
                        st.subheader(f"Password for {st.session_state.current_service}")
                        st.write(f"**Service:** {st.session_state.current_service}")
                        st.write(f"**Password:** {st.session_state.current_password}")
                        if st.button("Close", key="close_popup"):
                            close_popup()

                for service, password in passwords.items():
                    col1, col2, col3 = st.columns([2, 3, 1])
                    with col1:
                        st.text(service)
                    with col2:
                        st.text("••••••••")
                        st.button("Show password", key=f"show_{service}", on_click=show_password, args=(service, password))
                    with col3:
                        if st.button("Copy", key=f"copy_{service}"):
                            pyperclip.copy(password)
                            st.write(f"Password for {service} copied to clipboard!")

    with tab2:
        st.header("Add New Password")
        with st.form("add_password_form"):
            service = st.text_input("Service/Website", key="new_service")
            password_option = st.radio("Password options", ["Enter manually", "Use generated password"], horizontal=True)
            if password_option == "Enter manually":
                password = st.text_input("Password", key="new_password", type="password")
            else:
                password = st.session_state.generated_password
                st.text(f"Using: {'•' * len(password)}")
            save_button = st.form_submit_button("Save Password")
            if save_button:
                if not service or not password:
                    st.error("Service and password are required")
                else:
                    add_password(st.session_state.username, st.session_state.master_password, service, password)
                    st.success(f"Password for {service} saved successfully!")
                    st.session_state.generated_password = ""

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
            st.write("Generated password copied to clipboard!")
