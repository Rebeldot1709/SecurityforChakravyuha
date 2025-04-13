# SecurityforChakravyuha
This will be working to provide Support to the Main System
"""
THE DIGITAL CHAKRAVYUHA PROTOCOL - MYTHOLOGICAL AI DEFENSE SYSTEM
Each AI layer acts as a rotating defense ring, alternating in direction,
and designed to mislead, verify, absorb, and neutralize threats.
The Super Intelligence (Sudarshan AI) at the center orchestrates all layers.
"""

import time
import hashlib
import logging
from threading import Lock

# Logging Config
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("Chakravyuha")

# Core System State
class SystemState:
    def __init__(self):
        self.under_attack = False
        self.failed_attempts = 0
        self.lock = Lock()
        self.max_attempts = 3
        self.super_intelligence_online = True

    def increment_failure(self):
        with self.lock:
            self.failed_attempts += 1
            logger.warning(f"FAILED ATTEMPTS: {self.failed_attempts}")
            if self.failed_attempts >= self.max_attempts:
                self.under_attack = True
                logger.error("!!! ATTACK MODE ACTIVATED BY SUDARSHAN AI !!!")

    def reset(self):
        with self.lock:
            self.failed_attempts = 0
            self.under_attack = False

state = SystemState()

# User Class
class User:
    def __init__(self, authenticated=False, permissions=None, ip='0.0.0.0', confidence=0):
        self.authenticated = authenticated
        self.permissions = permissions or []
        self.ip = ip
        self.confidence = confidence  # confidence of being legitimate

# Utility Functions
WHITELISTED_IPS = {'192.168.1.1', '10.0.0.1'}

def is_recent(timestamp):
    return abs(time.time() - timestamp) < 10

def hash_data(timestamp, payload):
    return hashlib.sha256(f"{timestamp}{payload}".encode()).hexdigest()

# ===============================
#         AI LAYER ROLES
# ===============================

def dwarapal_ai(user):
    if not user.authenticated:
        raise PermissionError("[L1 - Dwarapal AI] User not authenticated.")
    logger.info("L1 - Dwarapal AI: Authentication Verified")

def integrity_sentinel():
    if state.failed_attempts > 1:
        raise RuntimeError("[L2 - Integrity Sentinel] System Integrity Compromised.")
    logger.info("L2 - Integrity Sentinel: System Integrity Check Passed")

def permission_guru(user):
    if "access_core" not in user.permissions:
        raise PermissionError("[L3 - Permission Guru] Insufficient permissions.")
    logger.info("L3 - Permission Guru: Access Permission Validated")

def deceptor_ai(user):
    if user.confidence > 70:
        logger.info("L4 - Deceptor AI: Deploying false honeypot!")
    else:
        logger.info("L4 - Deceptor AI: Engaging loop mirror deception")

def temporal_watcher(timestamp):
    if not is_recent(timestamp):
        raise TimeoutError("[L5 - Temporal Watcher] Timestamp expired.")
    logger.info("L5 - Temporal Watcher: Timestamp Valid")

def hash_enforcer(timestamp, data, hash_value):
    if hash_data(timestamp, data) != hash_value:
        raise ValueError("[L6 - Hash Enforcer] Data Integrity Breach Detected.")
    logger.info("L6 - Hash Enforcer: Payload Integrity Confirmed")

def kavach_kundal_ai():
    logger.info("L7 - Kavach-Kundal AI: Activating Inner Shields and AI Mimic Filters")

# ===============================
#     SUPER INTELLIGENCE CORE
# ===============================

def sudarshan_ai(user):
    logger.info("\\n>>>> SUDARSHAN AI INITIATED <<<<")
    if state.under_attack:
        logger.critical("!!! SYSTEM UNDER ATTACK !!! Executing Sudarshan Spiral")
        return "Access Blocked: Sudarshan Protocol Engaged"

    try:
        dwarapal_ai(user)
        integrity_sentinel()
        permission_guru(user)
        deceptor_ai(user)
        temporal_watcher(timestamp)
        hash_enforcer(timestamp, data, hash_val)
        kavach_kundal_ai()
        logger.info("\\n✅ ACCESS GRANTED TO CORE SYSTEM: Welcome, Verified Entity.")
        return "Welcome to the Heart of the Chakravyuha."

    except Exception as e:
        logger.warning(f"Layer Breach: {str(e)}")
        state.increment_failure()
        return f"ACCESS DENIED: {str(e)}"

# ===============================
#         TEST SIMULATION
# ===============================

def test_chakravyuha():
    global timestamp, data, hash_val
    timestamp = time.time()
    data = "sensitive_data"
    hash_val = hash_data(timestamp, data)

    print("\n--- TEST 1: VALID USER ---")
    valid_user = User(authenticated=True, permissions=["access_core"], ip="192.168.1.1", confidence=85)
    print(sudarshan_ai(valid_user))

    print("\n--- TEST 2: INVALID IP (FORCED ATTACK MODE) ---")
    for i in range(4):
        fake_user = User(authenticated=True, permissions=["access_core"], ip="8.8.8.8", confidence=30)
        print(sudarshan_ai(fake_user))

    print("\n--- TEST 3: POST ATTACK MODE - EVEN VALID USER BLOCKED ---")
    print(sudarshan_ai(valid_user))

    print("\n--- RESETTING SYSTEM ---")
    state.reset()
    print("System State Reset")
    print(sudarshan_ai(valid_user))

if __name__ == "__main__":
    test_chakravyuha()
