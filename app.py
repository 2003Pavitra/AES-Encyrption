import os
import base64
from flask import Flask, request, jsonify
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

app = Flask(__name__)

# --- Load AES Key from Environment ---
AES_KEY_B64 = os.getenv("AES_KEY_B64")
if AES_KEY_B64:
    try:
        KEY = base64.b64decode(AES_KEY_B64)
        if len(KEY) not in (16, 24, 32):
            raise ValueError("Invalid AES key length. Must be 16, 24, or 32 bytes.")
    except Exception as e:
        raise RuntimeError("Invalid AES_KEY_B64: " + str(e))
else:
    # Temporary key for local testing (not for production!)
    print("⚠️ AES_KEY_B64 not set — generating a temporary key (do not use in production).")
    KEY = get_random_bytes(32)


# --- Encryption Helper ---
def aes_encrypt(plaintext: str, aad: str = "") -> str:
    nonce = get_random_bytes(12)
    cipher = AES.new(KEY, AES.MODE_GCM, nonce=nonce)
    if aad:
        cipher.update(aad.encode())
    ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode())
    combined = nonce + tag + ciphertext
    return base64.b64encode(combined).decode()


# --- Decryption Helper ---
def aes_decrypt(ciphertext_b64: str, aad: str = "") -> str:
    raw = base64.b64decode(ciphertext_b64)
    if len(raw) < 28:  # 12 nonce + 16 tag = 28 minimum
        raise ValueError("Ciphertext too short.")
    nonce, tag, ciphertext = raw[:12], raw[12:28], raw[28:]
    cipher = AES.new(KEY, AES.MODE_GCM, nonce=nonce)
    if aad:
        cipher.update(aad.encode())
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    return plaintext.decode(errors="ignore")


# --- Flask Routes ---
@app.route("/")
def home():
    return (
        "<h2>AES Encryption/Decryption API</h2>"
        "<p>Use POST /encrypt or /decrypt</p>"
        "<p>JSON Example: {'plaintext':'hello world'}</p>"
    )


@app.route("/encrypt", methods=["POST"])
def encrypt_route():
    data = request.get_json(force=True, silent=True)
    if not data or "plaintext" not in data:
        return jsonify({"error": "Missing 'plaintext' field"}), 400

    plaintext = data["plaintext"]
    aad = data.get("aad", "")
    try:
        ciphertext = aes_encrypt(plaintext, aad)
        return jsonify({"ciphertext": ciphertext})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/decrypt", methods=["POST"])
def decrypt_route():
    data = request.get_json(force=True, silent=True)
    if not data or "ciphertext" not in data:
        return jsonify({"error": "Missing 'ciphertext' field"}), 400

    ciphertext = data["ciphertext"]
    aad = data.get("aad", "")
    try:
        plaintext = aes_decrypt(ciphertext, aad)
        return jsonify({"plaintext": plaintext})
    except Exception as e:
        return jsonify({"error": "Decryption failed: " + str(e)}), 400


# --- Run the App ---
if __name__ == "__main__":
    port = int(os.getenv("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
