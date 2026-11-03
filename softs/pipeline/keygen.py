"""Create the signing key for the software catalog. Run it ONCE, on your own machine
or server (not in CI):

    python3 softs/pipeline/keygen.py

It prints:
  SOFTS_SIGNING_KEY  -> add as a GitHub repository secret (Settings > Secrets and
                        variables > Actions). Keep a copy offline; never commit it.
  public key         -> goes into panel/trust/softs.json ("keys"), shipped with the panel.
"""
import base64

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

k = Ed25519PrivateKey.generate()
priv = k.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
pub = k.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
print('SOFTS_SIGNING_KEY (secret):', base64.b64encode(priv).decode())
print('Public key (panel/trust/softs.json):', base64.b64encode(pub).decode())
