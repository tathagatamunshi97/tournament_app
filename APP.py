import streamlit as st
import hashlib, json, base64, time
from cryptography.fernet import Fernet
from pathlib import Path

DATA_FILE = Path("draft_data.json")

# ---------- Crypto helpers ----------
def derive_key(password):
    return base64.urlsafe_b64encode(
        hashlib.sha256(password.encode()).digest()
    )

def encrypt(data, password):
    return Fernet(derive_key(password)).encrypt(data.encode()).decode()

def decrypt(token, password):
    return Fernet(derive_key(password)).decrypt(token.encode()).decode()

def sha256(text):
    return hashlib.sha256(text.encode()).hexdigest()

# ---------- Storage ----------
def load():
    if DATA_FILE.exists():
        return json.loads(DATA_FILE.read_text())
    return {"submissions": {}, "reveal_confirmed": []}

def save(data):
    DATA_FILE.write_text(json.dumps(data, indent=2))

data = load()

# ---------- UI ----------
st.set_page_config("Secret Draft App", layout="centered")
st.title("🔐 Secret Draft Submission")

phase = st.radio(
    "Phase",
    ["Commit Picks", "Confirm Reveal", "Reveal Picks"]
)

# ---------- PHASE 1: COMMIT ----------
if phase == "Commit Picks":
    st.subheader("Submit Your Picks (Locked)")

    user = st.text_input("Username")
    password = st.text_input("Password (DO NOT FORGET)", type="password")

    st.markdown("### 🏆 Epic Players (Priority 1–2)")
    epic = {}
    for i in range(1, 3):
        epic[f"priority_{i}"] = st.text_input(f"Epic Player {i}")

    st.markdown("### ⭐ Featured Players (Priority 1–4)")
    featured = {}
    for i in range(1, 5):
        featured[f"priority_{i}"] = st.text_input(f"Featured Player {i}")

    if st.button("Lock Picks"):
        if not user or not password:
            st.error("Username and password required")
        elif user in data["submissions"]:
            st.error("You have already submitted")
        else:
            payload = {
                "epic": epic,
                "featured": featured,
                "submitted_at": time.time()
            }

            plaintext = json.dumps(payload, sort_keys=True)
            encrypted = encrypt(plaintext, password)
            commit_hash = sha256(encrypted)

            data["submissions"][user] = {
                "encrypted": encrypted,
                "hash": commit_hash
            }
            save(data)

            st.success("✅ Picks locked")
            st.code(f"Commit hash:\n{commit_hash}")

# ---------- PHASE 2: CONFIRM ----------
elif phase == "Confirm Reveal":
    st.subheader("Confirm Reveal")

    user = st.selectbox(
        "Select your username",
        list(data["submissions"].keys())
    )

    if st.button("Confirm"):
        if user not in data["reveal_confirmed"]:
            data["reveal_confirmed"].append(user)
            save(data)
        st.success("Confirmed")

    st.info(
        f"Confirmed: {len(data['reveal_confirmed'])} / "
        f"{len(data['submissions'])}"
    )

# ---------- PHASE 3: REVEAL ----------
elif phase == "Reveal Picks":
    st.subheader("Reveal (Only After All Confirmed)")

    if set(data["reveal_confirmed"]) != set(data["submissions"].keys()):
        st.warning("Waiting for all users to confirm reveal")
    else:
        user = st.selectbox("Select user", data["submissions"].keys())
        password = st.text_input("Password", type="password")

        if st.button("Reveal"):
            try:
                encrypted = data["submissions"][user]["encrypted"]
                original_hash = data["submissions"][user]["hash"]

                decrypted = decrypt(encrypted, password)
                if sha256(encrypted) != original_hash:
                    st.error("❌ Hash mismatch")
                else:
                    picks = json.loads(decrypted)
                    st.success("✅ Verified Picks")
                    st.json(picks)

            except Exception:
                st.error("Wrong password")
