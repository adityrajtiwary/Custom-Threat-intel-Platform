import os
import getpass
import secrets
import pyotp
import qrcode
from auth import hash_password

USERNAME = "nobody"

print("=== Admin Setup ===")
pw1 = getpass.getpass("Naya password daal: ")
pw2 = getpass.getpass("Password dobara: ")
if pw1 != pw2:
    print("Password match nahi hua. Dobara chala.")
    raise SystemExit(1)
if len(pw1) < 8:
    print("Password kam se kam 8 characters ka rakh.")
    raise SystemExit(1)

hashed = hash_password(pw1)

# MFA secret
mfa_secret = pyotp.random_base32()

# JWT secret (random, strong)
jwt_secret = secrets.token_urlsafe(48)

# .env me daalo (purane auth lines hata ke)
env_path = ".env"
lines = []
if os.path.exists(env_path):
    with open(env_path) as f:
        lines = [l for l in f if not l.startswith(("ADMIN_USER", "ADMIN_PASS_HASH", "MFA_SECRET", "JWT_SECRET"))]

lines.append(f"ADMIN_USER={USERNAME}\n")
lines.append(f"ADMIN_PASS_HASH={hashed}\n")
lines.append(f"MFA_SECRET={mfa_secret}\n")
lines.append(f"JWT_SECRET={jwt_secret}\n")

with open(env_path, "w") as f:
    f.writelines(lines)

# QR code -- terminal me dikhao (phone se scan karega)
uri = pyotp.totp.TOTP(mfa_secret).provisioning_uri(name=USERNAME, issuer_name="ThreatIntel")
qr = qrcode.QRCode()
qr.add_data(uri)
qr.make()
print("\n=== MFA QR Code -- Google Authenticator / Authy se scan kar ===\n")
qr.print_ascii(invert=True)
print(f"\nAgar QR na scan ho, ye secret manually daal app me:\n  {mfa_secret}\n")
print("Setup done! Username: nobody")
