import os
import base64
from flask import Flask, request, jsonify
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

app = Flask(__name__)

# --- AES Key ---
AES_KEY_B64 = os.environ.get("AES_KEY_B64")
if AES_KEY_B64:
    try:
        KEY = base64.b64decode(AES_KEY_B64)
        if len(KEY) not in (16, 24, 32):
            raise ValueError("Invalid AES key length")
    except Exception as e:
        raise RuntimeError("Invalid AES_KEY_B64: " + str(e))
else:
    # Temporary key for testing (not secure for production)
    print("⚠️ AES_KEY_B64 not set — generating temporary key")
    KEY = get_random_bytes(32)

# --- AES-GCM Encryption ---
def encrypt_text(plaintext: str) -> str:
    cipher = AES.new(KEY, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode())
    data = cipher.nonce + tag + ciphertext
    return base64.b64encode(data).decode()

# --- AES-GCM Decryption ---
def decrypt_text(ciphertext_b64: str) -> str:
    data = base64.b64decode(ciphertext_b64)
    nonce, tag, ciphertext = data[:12], data[12:28], data[28:]
    cipher = AES.new(KEY, AES.MODE_GCM, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    return plaintext.decode(errors="ignore")

# --- Routes ---
@app.route('/')
def home():
    return "<h2>AES Encryption/Decryption API</h2><p>POST JSON to /encrypt or /decrypt</p>"

@app.route('/encrypt', methods=['POST'])
def encrypt_route():
    data = request.get_json(force=True)
    if not data or 'plaintext' not in data:
        return jsonify({'error': "Provide JSON with 'plaintext'"}), 400
    return jsonify({'ciphertext': encrypt_text(data['plaintext'])})

@app.route('/decrypt', methods=['POST'])
def decrypt_route():
    data = request.get_json(force=True)
    if not data or 'ciphertext' not in data:
        return jsonify({'error': "Provide JSON with 'ciphertext'"}), 400
    try:
        return jsonify({'plaintext': decrypt_text(data['ciphertext'])})
    except Exception:
        return jsonify({'error': 'Decryption failed. Invalid key or data.'}), 400

# --- Run App ---
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)

