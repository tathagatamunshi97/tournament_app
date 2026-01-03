import streamlit as st
import json
import hashlib
from cryptography.fernet import Fernet
from base64 import urlsafe_b64encode

# ---------------- CONFIG ----------------
ADMIN_PASSWORD = "admin123"  # change this
DATA_FILE = "data.json"

# ---------------- HELPERS ----------------
def load_data():
    try:
        with open(DATA_FILE, "r") as f:
            return json.load(f)
    except:
        return {
            "registry_locked": False,
            "users": [],
            "commits": {},
            "confirmations": []
        }

def save_data(data):
    with open(DATA_FILE, "w") as f:
        json.dump(data, f, indent=2)

def derive_key(password: str):
    digest = hashlib.sha256(password.encode()).digest()
    return urlsafe_b64encode(digest)

def encrypt_data(data, password):
    key = derive_key(password)
    return Fernet(key).encrypt(json.dumps(data).encode()).decode()

def decrypt_data(token, password):
    key = derive_key(password)
    return json.loads(Fernet(key).decrypt(token.encode()).decode())

# ---------------- APP ----------------
st.set_page_config(page_title="Secret Draft Commit", layout="centered")
st.title("🔐 Secret Draft Commit & Reveal")

data = load_data()

# ---------------- ADMIN PANEL ----------------
with st.sidebar:
    st.header("Admin Panel")
    admin_pass = st.text_input("Admin Password", type="password")

    if admin_pass == ADMIN_PASSWORD:
        st.success("Admin authenticated")

        if not data["registry_locked"]:
            new_user = st.text_input("Add Player Name")
            if st.button("Add Player"):
                if new_user and new_user not in data["users"]:
                    data["users"].append(new_user)
                    save_data(data)
                    st.success(f"{new_user} added")

            if st.button("🔒 Lock Registry"):
                data["registry_locked"] = True
                save_data(data)
                st.warning("Registry locked")

        else:
            st.info("Registry already locked")

# ---------------- REGISTRY VIEW ----------------
st.subheader("Registered Players")
st.write(data["users"])

if not data["registry_locked"]:
    st.warning("Waiting for admin to lock registry.")
    st.stop()

# ---------------- USER SUBMISSION ----------------
st.subheader("Submit Your Picks")

username = st.selectbox("Your Name", [""] + data["users"])
password = st.text_input("Your Password", type="password")

if username in data["commits"]:
    st.info("You have already submitted your encrypted picks.")
else:
    st.markdown("### Epic Players (2)")
    epic1 = st.text_input("Epic Player 1")
    epic2 = st.text_input("Epic Player 2")

    st.markdown("### Featured Players (4)")
    f1 = st.text_input("Featured Player 1")
    f2 = st.text_input("Featured Player 2")
    f3 = st.text_input("Featured Player 3")
    f4 = st.text_input("Featured Player 4")

    if st.button("🔐 Encrypt & Submit"):
        if not username or not password:
            st.error("Name and password required")
        else:
            picks = {
                "epic": [epic1, epic2],
                "featured": [f1, f2, f3, f4]
            }
            encrypted = encrypt_data(picks, password)
            data["commits"][username] = encrypted
            save_data(data)
            st.success("Picks encrypted & submitted")

# ---------------- CONFIRM REVEAL ----------------
st.subheader("Reveal Confirmation")

if username and username not in data["confirmations"]:
    if st.button("✅ Confirm Reveal"):
        data["confirmations"].append(username)
        save_data(data)
        st.success("Confirmation recorded")

st.write(f"Confirmations: {len(data['confirmations'])}/{len(data['users'])}")

# ---------------- REVEAL ----------------
if len(data["confirmations"]) == len(data["users"]):
    st.subheader("🎉 REVEAL PHASE")

    reveal_user = st.selectbox("Reveal Your Picks", [""] + data["users"])
    reveal_pass = st.text_input("Your Password for Reveal", type="password", key="reveal")

    if st.button("🔓 Decrypt"):
        try:
            encrypted = data["commits"][reveal_user]
            decrypted = decrypt_data(encrypted, reveal_pass)
            st.success("Decrypted Successfully")
            st.json(decrypted)
        except:
            st.error("Wrong password or corrupted data")
else:
    st.info("Waiting for all confirmations before reveal.")
