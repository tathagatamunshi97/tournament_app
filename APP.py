import streamlit as st
import json, hashlib, base64
from cryptography.fernet import Fernet
from collections import defaultdict

# ================= CONFIG =================

ADMIN_PASSWORD_HASH = hashlib.sha256("admin123".encode()).hexdigest()
st.set_page_config("Secure Draft App", layout="centered")

# ================= CRYPTO =================

def derive_key(password):
    return base64.urlsafe_b64encode(hashlib.sha256(password.encode()).digest())

def encrypt(data, password):
    return Fernet(derive_key(password)).encrypt(
        json.dumps(data).encode()
    ).decode()

def decrypt(token, password):
    return json.loads(
        Fernet(derive_key(password)).decrypt(token.encode()).decode()
    )

# ================= INIT =================

def init_state():
    defaults = {
        "phase": 1,
        "admin_locked": False,
        "users": {},                    # username -> {password_hash, confirmed}
        "encrypted_picks": {},          # username -> encrypted blob
        "approved": set(),              # usernames
        "decrypted": {},                # username -> picks
        "current_user": None            # session-bound identity
    }
    for k, v in defaults.items():
        if k not in st.session_state:
            st.session_state[k] = v

init_state()

# ================= AUTO ADVANCE =================

def auto_advance():
    if st.session_state.phase == 1 and st.session_state.admin_locked:
        st.session_state.phase = 2

    if (
        st.session_state.phase == 2
        and all(u["confirmed"] for u in st.session_state.users.values())
    ):
        st.session_state.phase = 3

    if (
        st.session_state.phase == 3
        and len(st.session_state.encrypted_picks) == len(st.session_state.users)
    ):
        st.session_state.phase = 4

    if (
        st.session_state.phase == 4
        and st.session_state.approved == set(st.session_state.users.keys())
    ):
        st.session_state.phase = 5

    if (
        st.session_state.phase == 5
        and len(st.session_state.decrypted) == len(st.session_state.users)
    ):
        st.session_state.phase = 6

auto_advance()

# ================= SIDEBAR =================

st.sidebar.title("📊 Draft Status")
st.sidebar.write(f"Phase: {st.session_state.phase}")
st.sidebar.write("Players:", list(st.session_state.users.keys()))

# ================= LOGIN =================

def player_login():
    if st.session_state.current_user:
        return st.session_state.current_user

    st.subheader("🔐 Player Login")
    user = st.text_input("Username")
    password = st.text_input("Password", type="password")

    if st.button("Login"):
        record = st.session_state.users.get(user)
        if not record:
            st.error("User not registered")
        elif not record["confirmed"]:
            st.error("Registration not confirmed yet")
        elif hashlib.sha256(password.encode()).hexdigest() != record["password_hash"]:
            st.error("Wrong password")
        else:
            st.session_state.current_user = user
            st.success(f"Logged in as {user}")
            st.rerun()

    st.stop()

# ================= PHASE 1: ADMIN =================

if st.session_state.phase == 1:
    st.title("👑 Admin: Create Player List")

    admin_pw = st.text_input("Admin Password", type="password")

    if hashlib.sha256(admin_pw.encode()).hexdigest() == ADMIN_PASSWORD_HASH:
        st.success("Admin authenticated")

        if not st.session_state.admin_locked:
            new_user = st.text_input("Add player username")

            if st.button("Add Player"):
                if not new_user:
                    st.error("Username required")
                elif new_user in st.session_state.users:
                    st.error("User already exists")
                else:
                    st.session_state.users[new_user] = {
                        "password_hash": None,
                        "confirmed": False
                    }
                    st.success(f"Added {new_user}")
                    st.rerun()

            if st.session_state.users:
                st.subheader("Current Players")
                st.write(list(st.session_state.users.keys()))

            if st.button("🔒 Lock Player List"):
                if len(st.session_state.users) < 2:
                    st.error("At least 2 players required")
                else:
                    st.session_state.admin_locked = True
                    st.success("Player list locked")
                    st.rerun()
        else:
            st.info("Player list locked")
            st.write(list(st.session_state.users.keys()))
    else:
        st.warning("Admin-only access")
        if st.session_state.users:
            st.subheader("Registered Players (View Only)")
            st.write(list(st.session_state.users.keys()))

# ================= PHASE 2: CONFIRM =================

if st.session_state.phase == 2:
    st.title("🔐 Player Registration Confirmation")

    user = st.text_input("Username")
    password = st.text_input("Set Password", type="password")

    if st.button("Confirm Registration"):
        if user not in st.session_state.users:
            st.error("Not registered")
        elif st.session_state.users[user]["confirmed"]:
            st.info("Already confirmed")
        else:
            st.session_state.users[user]["password_hash"] = hashlib.sha256(
                password.encode()
            ).hexdigest()
            st.session_state.users[user]["confirmed"] = True
            st.success("Registration confirmed")
            st.rerun()

    st.subheader("Confirmed Players")
    st.write([u for u, v in st.session_state.users.items() if v["confirmed"]])

# ================= PHASE 3: COMMIT =================

if st.session_state.phase == 3:
    st.title("📦 Commit Picks")
    user = player_login()

    if user in st.session_state.encrypted_picks:
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
                payload = {
                    "epics": [e1, e2],
                    "featured": [f1, f2, f3, f4]
                }
                st.session_state.encrypted_picks[user] = encrypt(payload, password)
                st.success("Picks locked")
                st.rerun()

# ================= PHASE 4: APPROVE =================

if st.session_state.phase == 4:
    st.title("✅ Approve Reveal")
    user = player_login()

    if user in st.session_state.approved:
        st.info("You have already approved")
    else:
        if st.button("Approve Reveal"):
            st.session_state.approved.add(user)
            st.success("Approved")
            st.rerun()

    st.write("Approved so far:", list(st.session_state.approved))

# ================= PHASE 5: DECRYPT =================

if st.session_state.phase == 5:
    st.title("🔓 Decrypt Picks")
    user = player_login()

    if user in st.session_state.decrypted:
        st.success("You have already decrypted")
    else:
        password = st.text_input("Password", type="password")
        if st.button("Decrypt My Picks"):
            try:
                st.session_state.decrypted[user] = decrypt(
                    st.session_state.encrypted_picks[user], password
                )
                st.success("Decrypted successfully")
                st.rerun()
            except:
                st.error("Wrong password")

# ================= PHASE 6: REVEAL =================

if st.session_state.phase == 6:
    st.title("🎉 Auction Highlights")

    epic_map = defaultdict(list)
    featured_map = defaultdict(list)

    for u, d in st.session_state.decrypted.items():
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
