#!/usr/bin/env python3
"""
Nova EDR Kill Switch — Emergency override control.

Usage:
    python3 -m nova_edr.killswitch setup
    python3 -m nova_edr.killswitch disable --password <PASSWORD>
    python3 -m nova_edr.killswitch enable --password <PASSWORD>
    python3 -m nova_edr.killswitch status
    python3 -m nova_edr.killswitch emergency --recovery-key <KEY>
"""

import argparse
import hashlib
import json
import logging
import os
import secrets
import signal
import subprocess
import sys
import time
from pathlib import Path

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
log = logging.getLogger("nova.killswitch")

CONFIG_DIR = Path(__file__).parent.parent / "config"
HASH_FILE = CONFIG_DIR / "killswitch.hash"
RECOVERY_FILE = CONFIG_DIR / "recovery.hash"
DISABLED_FILE = CONFIG_DIR / "DISABLED"
LOG_DIR = Path(__file__).parent.parent / "logs"
ACTION_LOG = LOG_DIR / "killswitch.log"

def _ensure_dirs():
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    LOG_DIR.mkdir(parents=True, exist_ok=True)

def _log_action(action: str, details: str = ""):
    _ensure_dirs()
    timestamp = time.strftime("%Y-%m-%dT%H:%M:%S")
    entry = f"[{timestamp}] {action.upper()}: {details}\n"
    with open(ACTION_LOG, "a") as f:
        f.write(entry)
    log.info(f"{action.upper()}: {details}")

def _hash_password(password: str, salt: bytes = None) -> dict:
    if not salt:
        salt = os.urandom(32)
    key = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt,
        100000
    )
    return {
        'salt': salt.hex(),
        'hash': key.hex()
    }

def _verify_password(password: str) -> bool:
    if not HASH_FILE.exists():
        log.error("Kill switch not set up. Run 'setup' first.")
        return False
    
    try:
        data = json.loads(HASH_FILE.read_text())
        salt = bytes.fromhex(data['salt'])
        stored_hash = data['hash']
        
        check = hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),
            salt,
            100000
        ).hex()
        
        return check == stored_hash
    except Exception as e:
        log.error(f"Error verifying password: {e}")
        return False

def _verify_recovery_key(key: str) -> bool:
    if not RECOVERY_FILE.exists():
        log.error("No recovery key configured. Run 'setup' first.")
        return False
    
    try:
        data = json.loads(RECOVERY_FILE.read_text())
        salt = bytes.fromhex(data['salt'])
        stored_hash = data['hash']
        
        check = hashlib.pbkdf2_hmac(
            'sha256',
            key.encode('utf-8'),
            salt,
            100000
        ).hex()
        
        return check == stored_hash
    except Exception as e:
        log.error(f"Error verifying recovery key: {e}")
        return False

def _unfreeze_all():
    """Send SIGCONT to all processes. Last resort unfreeze."""
    log.warning("Attempting to unfreeze ALL processes (SIGCONT)...")
    try:
        # Using killall -CONT -1 (all processes usually requires root)
        # Or iterate /proc. Let's try to be smart and iterate psutil if available,
        # otherwise fallback to broad system command.
        
        import psutil
        count = 0
        for proc in psutil.process_iter():
            try:
                proc.send_signal(signal.SIGCONT)
                count += 1
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        log.info(f"Sent SIGCONT to {count} accessible processes.")
    except ImportError:
        # Fallback for systems without psutil installed in this env
        subprocess.run(["killall", "-CONT", "-u", os.environ.get("USER", "root")], stderr=subprocess.DEVNULL)
        log.info("Sent SIGCONT via killall")

def setup():
    _ensure_dirs()
    if HASH_FILE.exists():
        print("Kill switch password already set. Overwrite? [y/N] ", end="")
        if input().lower() != 'y':
            return

    import getpass
    p1 = getpass.getpass("Enter new kill switch password: ")
    p2 = getpass.getpass("Confirm password: ")
    
    if p1 != p2:
        print("Passwords do not match.")
        sys.exit(1)
        
    if not p1:
        print("Password cannot be empty.")
        sys.exit(1)

    data = _hash_password(p1)
    HASH_FILE.write_text(json.dumps(data))
    
    # Generate recovery key
    recovery_key = secrets.token_hex(16)  # 32-char hex string
    recovery_data = _hash_password(recovery_key)
    RECOVERY_FILE.write_text(json.dumps(recovery_data))
    
    print(f"\nPassword saved to {HASH_FILE}")
    print(f"\n{'='*60}")
    print(f"  RECOVERY KEY (save this somewhere safe!):")
    print(f"  {recovery_key}")
    print(f"{'='*60}")
    print(f"\n  This key is your emergency override if you forget your")
    print(f"  password or need to unfreeze a bricked system.")
    print(f"  It will NOT be shown again.\n")
    _log_action("setup", "Password and recovery key updated")

def disable(password: str):
    if not _verify_password(password):
        log.error("Invalid password.")
        sys.exit(1)
        
    _ensure_dirs()
    DISABLED_FILE.write_text(f"Disabled at {time.time()}")
    
    _unfreeze_all()
    
    # Stop systemd service if running
    try:
        subprocess.run(["systemctl", "--user", "stop", "nova-edr"], check=False)
        log.info("Stopped nova-edr systemd service")
    except FileNotFoundError:
        pass

    _log_action("disable", "EDR disabled, processes unfrozen")
    print("Nova EDR has been DISABLED. Monitoring stopped. Processes unfrozen.")

def enable(password: str):
    if not _verify_password(password):
        log.error("Invalid password.")
        sys.exit(1)
        
    if DISABLED_FILE.exists():
        DISABLED_FILE.unlink()
        
    # Restart systemd service
    try:
        subprocess.run(["systemctl", "--user", "start", "nova-edr"], check=False)
        log.info("Started nova-edr systemd service")
    except FileNotFoundError:
        pass
        
    _log_action("enable", "EDR enabled")
    print("Nova EDR has been ENABLED.")

def status():
    if not HASH_FILE.exists():
        print("Status: NOT CONFIGURED (Run setup first)")
        return

    if DISABLED_FILE.exists():
        content = DISABLED_FILE.read_text()
        print(f"Status: DISABLED")
        print(f"Info: {content}")
    else:
        print("Status: ENABLED")
        
    if ACTION_LOG.exists():
        print("\nLast 5 actions:")
        lines = ACTION_LOG.read_text().splitlines()[-5:]
        for line in lines:
            print(f"  {line}")

def emergency(recovery_key: str):
    if not _verify_recovery_key(recovery_key):
        log.error("Invalid recovery key.")
        print("DENIED — invalid recovery key.")
        sys.exit(1)
    
    print("!!! EMERGENCY MODE !!!")
    print("Unfreezing ALL processes and disabling EDR...")
    
    _unfreeze_all()
    
    _ensure_dirs()
    DISABLED_FILE.write_text(f"Emergency disable at {time.time()}")
    
    # Stop systemd service if running
    try:
        subprocess.run(["systemctl", "--user", "stop", "nova-edr"], check=False)
    except FileNotFoundError:
        pass
    
    _log_action("emergency", "Emergency override — processes unfrozen, EDR disabled")
    print("Emergency override complete. EDR disabled, all processes unfrozen.")
    print("Run 'enable --password <PASSWORD>' to restart monitoring.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Nova EDR Kill Switch")
    subparsers = parser.add_subparsers(dest="command", required=True)
    
    subparsers.add_parser("setup", help="Set up kill switch password")
    
    disable_parser = subparsers.add_parser("disable", help="Disable EDR and unfreeze everything")
    disable_parser.add_argument("--password", required=True, help="Kill switch password")
    
    enable_parser = subparsers.add_parser("enable", help="Re-enable EDR")
    enable_parser.add_argument("--password", required=True, help="Kill switch password")
    
    subparsers.add_parser("status", help="Show current status")
    
    emergency_parser = subparsers.add_parser("emergency", help="Emergency override (requires recovery key)")
    emergency_parser.add_argument("--recovery-key", required=True, help="Recovery key from setup")
    
    args = parser.parse_args()
    
    if args.command == "setup":
        setup()
    elif args.command == "disable":
        disable(args.password)
    elif args.command == "enable":
        enable(args.password)
    elif args.command == "status":
        status()
    elif args.command == "emergency":
        emergency(args.recovery_key)
