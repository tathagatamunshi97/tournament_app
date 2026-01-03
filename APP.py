import streamlit as st
import hashlib, json, base64, os
from cryptography.fernet import Fernet
from collections import defaultdict

# ================= CONFIG =================
STATE_FILE = "draft_state.json"
ADMIN_PASSWORD_HASH = hashlib.sha256("admin123".encode()).hexdigest()
st.set_page_config("Secure Draft App", layout="centered")

# ================= CRYPTO =================
def derive_key(password):
    return base64.urlsafe_b64encode(hashlib.sha256(password.encode()).digest())

def encrypt(data, password):
    return Fernet(derive_key(password)).encrypt(json.dumps(data).encode()).decode()

def decrypt(token, password):
    return json.loads(Fernet(derive_key(password)).decrypt(token.encode()).decode())

# ================= SHARED STATE =================
def load_state():
    if os.path.exists(STATE_FILE):
        with open(STATE_FILE, "r") as f:
            return json.load(f)
    return {
        "phase": 1,
        "admin_locked": False,
        "users": {},           # username -> {password_hash, confirmed}
        "encrypted_picks": {}, # username -> encrypted data
        "approved": [],        # usernames
        "decrypted": {}        # username -> picks
    }

def save_state(state):
    with open(STATE_FILE, "w") as f:
        json.dump(state, f, indent=2)

shared_state = load_state()

# ================= SESSION STATE =================
if "current_user" not in st.session_state:
    st.session_state.current_user = None
if "is_admin" not in st.session_state:
    st.session_state.is_admin = False

# ================= AUTO ADVANCE =================
def auto_advance(state):
    # Phase 1 -> 2: admin locked
    if state["phase"] == 1 and state["admin_locked"]:
        state["phase"] = 2

    # Phase 2 -> 3: at least one player confirmed
    if state["phase"] == 2:
        if any(u["confirmed"] for u in state["users"].values()):
            state["phase"] = 3

    # Phase 3 -> 4: all picks submitted
    if state["phase"] == 3 and len(state["encrypted_picks"]) == len(state["users"]):
        state["phase"] = 4

    # Phase 4 -> 5: all approved
    if state["phase"] == 4 and set(state["approved"]) == set(state["users"].keys()):
        state["phase"] = 5

    # Phase 5 -> 6: all decrypted
    if state["phase"] == 5 and len(state["decrypted"]) == len(state["users"]):
        state["phase"] = 6

auto_advance(shared_state)
save_state(shared_state)

# ================= SIDEBAR =================
st.sidebar.title("📊 Draft Status")
st.sidebar.write(f"Phase: {shared_state['phase']}")
st.sidebar.write("Players:", list(shared_state["users"].keys()))
st.sidebar.write("Admin Locked:", shared_state["admin_locked"])

# ================= ADMIN PAGE =================
if shared_state["phase"] == 1:
    st.title("👑 Admin: Create Player List")
    admin_pw = st.text_input("Admin Password", type="password")
    if hashlib.sha256(admin_pw.encode()).hexdigest() == ADMIN_PASSWORD_HASH:
        st.session_state.is_admin = True
        st.success("Admin authenticated")

        if not shared_state["admin_locked"]:
            new_user = st.text_input("Add player username")
            if st.button("Add Player"):
                if not new_user:
                    st.error("Username required")
                elif new_user in shared_state["users"]:
                    st.error("User already exists")
                else:
                    shared_state["users"][new_user] = {"password_hash": None, "confirmed": False}
                    save_state(shared_state)
                    st.success(f"Added {new_user}")
                    st.rerun()

            if shared_state["users"]:
                st.subheader("Current Players")
                st.write(list(shared_state["users"].keys()))

            if st.button("🔒 Lock Player List"):
                if len(shared_state["users"]) < 2:
                    st.error("At least 2 players required")
                else:
                    shared_state["admin_locked"] = True
                    auto_advance(shared_state)
                    save_state(shared_state)
                    st.success("Player list locked")
                    st.rerun()
        else:
            st.info("Player list locked. Waiting for players to confirm.")
            st.write(list(shared_state["users"].keys()))
    else:
        st.warning("Admin-only page")
        st.write(list(shared_state["users"].keys()))

# ================= PLAYER LOGIN / REGISTRATION =================
def player_login():
    if st.session_state.current_user:
        return st.session_state.current_user

    st.subheader("🔐 Player Login")
    user = st.text_input("Username")
    if not user:
        st.stop()
    
    record = shared_state["users"].get(user)
    if not record:
        st.error("User not registered")
        st.stop()

    if not record["confirmed"]:
        # Show registration form
        password = st.text_input("Set Your Password", type="password")
        if st.button("Confirm Registration"):
            if not password:
                st.error("Password required")
            else:
                record["password_hash"] = hashlib.sha256(password.encode()).hexdigest()
                record["confirmed"] = True
                shared_state["users"][user] = record
                auto_advance(shared_state)
                save_state(shared_state)
                st.success("Registration confirmed")
                st.rerun()
        st.stop()
    else:
        # Confirm login for already registered users
        password = st.text_input("Password", type="password")
        if st.button("Login"):
            if hashlib.sha256(password.encode()).hexdigest() != record["password_hash"]:
                st.error("Wrong password")
            else:
                st.session_state.current_user = user
                st.success(f"Logged in as {user}")
                st.rerun()
        st.stop()

# ================= PHASE 2: PLAYER REGISTRATION =================
if shared_state["phase"] == 2:
    st.title("🖊 Player Registration / Login")
    player_login()
    st.info("Please register or login to continue once the admin has locked the player list.")
    st.write("Players:", list(shared_state["users"].keys()))

# ================= PHASE 3: COMMIT PICKS =================
if shared_state["phase"] == 3:
    st.title("📦 Commit Picks")
    user = player_login()

    if user in shared_state["encrypted_picks"]:
        st.info("You have already submitted picks")
    else:
        with st.form("commit"):
            st.subheader("🏆 Epics")
            e1 = st.text_input("Epic Priority 1")
            e2 = st.text_input("Epic Priority 2")
            st.subheader("⭐ Featured")
            f1 = st.text_input("Featured Priority 1")
            f2 = st.text_input("Featured Priority 2")
            f3 = st.text_input("Featured Priority 3")
            f4 = st.text_input("Featured Priority 4")
            password = st.text_input("Confirm Password", type="password")
            if st.form_submit_button("Encrypt & Submit"):
                payload = {"epics": [e1, e2], "featured": [f1, f2, f3, f4]}
                shared_state["encrypted_picks"][user] = encrypt(payload, password)
                auto_advance(shared_state)
                save_state(shared_state)
                st.success("Picks locked")
                st.rerun()

# ================= PHASE 4: APPROVE =================
if shared_state["phase"] == 4:
    st.title("✅ Approve Reveal")
    user = player_login()

    if user in shared_state["approved"]:
        st.info("You have already approved")
    else:
        if st.button("Approve Reveal"):
            shared_state["approved"].append(user)
            auto_advance(shared_state)
            save_state(shared_state)
            st.success("Approved")
            st.rerun()

    st.write("Approved so far:", shared_state["approved"])

# ================= PHASE 5: DECRYPT =================
if shared_state["phase"] == 5:
    st.title("🔓 Decrypt Picks")
    user = player_login()
    if user in shared_state["decrypted"]:
        st.success("Already decrypted")
    else:
        password = st.text_input("Password", type="password")
        if st.button("Decrypt My Picks"):
            try:
                shared_state["decrypted"][user] = decrypt(shared_state["encrypted_picks"][user], password)
                auto_advance(shared_state)
                save_state(shared_state)
                st.success("Decrypted successfully")
                st.rerun()
            except:
                st.error("Wrong password")

# ================= PHASE 6: REVEAL =================
if shared_state["phase"] == 6:
    st.title("🎉 Auction Highlights")
    epic_map = defaultdict(list)
    featured_map = defaultdict(list)
    for u, d in shared_state["decrypted"].items():
        epic_map[d["epics"][0]].append(u)
        featured_map[d["featured"][0]].append(u)
        featured_map[d["featured"][1]].append(u)

    st.subheader("🏆 Epics (Priority 1)")
    for p, users in epic_map.items():
        if len(users) == 1:
            st.success(f"{p} → {users[0]}")
        else:
            st.warning(f"{p} → Auction between {users}")

    st.subheader("⭐ Featured (Priority 1–2)")
    for p, users in featured_map.items():
        if len(users) == 1:
            st.success(f"{p} → {users[0]}")
        else:
            st.warning(f"{p} → Auction between {users}")
