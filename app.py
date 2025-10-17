import base64
import os
from tkinter import *
from tkinter import messagebox
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

# -----------------------------
# AES Functions
# -----------------------------
def get_key():
    key_env = os.environ.get("AES_KEY_B64")
    if key_env:
        try:
            key = base64.b64decode(key_env)
            if len(key) not in (16, 24, 32):
                raise ValueError
            return key
        except Exception:
            messagebox.showerror("Error", "Invalid AES_KEY_B64 in environment.")
            return None
    else:
        # Temporary random key (for demo only)
        return get_random_bytes(32)

def encrypt_text():
    plaintext = encrypt_input.get("1.0", END).strip()
    if not plaintext:
        messagebox.showwarning("Warning", "Enter text to encrypt!")
        return
    key = get_key()
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode())
    data = cipher.nonce + tag + ciphertext
    encoded = base64.b64encode(data).decode()
    encrypt_output.delete("1.0", END)
    encrypt_output.insert(END, encoded)

def decrypt_text():
    ciphertext_b64 = decrypt_input.get("1.0", END).strip()
    if not ciphertext_b64:
        messagebox.showwarning("Warning", "Enter ciphertext to decrypt!")
        return
    try:
        data = base64.b64decode(ciphertext_b64)
        nonce, tag, ciphertext = data[:12], data[12:28], data[28:]
        key = get_key()
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        decrypt_output.delete("1.0", END)
        decrypt_output.insert(END, plaintext.decode(errors="ignore"))
    except Exception:
        messagebox.showerror("Error", "Decryption failed! Wrong key or invalid data.")

# -----------------------------
# GUI Layout
# -----------------------------
root = Tk()
root.title("AES Encryption & Decryption GUI")
root.geometry("900x500")
root.config(bg="#1e1e1e")
root.resizable(False, False)

title_label = Label(root, text="AES Encryption / Decryption", font=("Arial", 18, "bold"), fg="#00FFAA", bg="#1e1e1e")
title_label.pack(pady=10)

main_frame = Frame(root, bg="#1e1e1e")
main_frame.pack(pady=10)

# ENCRYPTION FRAME
encrypt_frame = LabelFrame(main_frame, text="Encryption", font=("Arial", 12, "bold"), fg="#00ccff", bg="#2a2a2a", bd=2, padx=10, pady=10)
encrypt_frame.grid(row=0, column=0, padx=15)

Label(encrypt_frame, text="Plaintext:", fg="white", bg="#2a2a2a", font=("Arial", 10, "bold")).pack(anchor="w")
encrypt_input = Text(encrypt_frame, height=6, width=40, wrap=WORD, bg="#252526", fg="white", insertbackground="white")
encrypt_input.pack(pady=5)

Button(encrypt_frame, text="Encrypt", command=encrypt_text, bg="#0078D7", fg="white", font=("Arial", 12, "bold"), width=15).pack(pady=5)

Label(encrypt_frame, text="Ciphertext (Base64):", fg="white", bg="#2a2a2a", font=("Arial", 10, "bold")).pack(anchor="w")
encrypt_output = Text(encrypt_frame, height=6, width=40, wrap=WORD, bg="#252526", fg="white", insertbackground="white")
encrypt_output.pack(pady=5)

# DECRYPTION FRAME
decrypt_frame = LabelFrame(main_frame, text="Decryption", font=("Arial", 12, "bold"), fg="#ff9966", bg="#2a2a2a", bd=2, padx=10, pady=10)
decrypt_frame.grid(row=0, column=1, padx=15)

Label(decrypt_frame, text="Ciphertext (Base64):", fg="white", bg="#2a2a2a", font=("Arial", 10, "bold")).pack(anchor="w")
decrypt_input = Text(decrypt_frame, height=6, width=40, wrap=WORD, bg="#252526", fg="white", insertbackground="white")
decrypt_input.pack(pady=5)

Button(decrypt_frame, text="Decrypt", command=decrypt_text, bg="#FF5722", fg="white", font=("Arial", 12, "bold"), width=15).pack(pady=5)

Label(decrypt_frame, text="Plaintext:", fg="white", bg="#2a2a2a", font=("Arial", 10, "bold")).pack(anchor="w")
decrypt_output = Text(decrypt_frame, height=6, width=40, wrap=WORD, bg="#252526", fg="white", insertbackground="white")
decrypt_output.pack(pady=5)

Label(root, text="Tip: Set AES_KEY_B64 env var for consistent key across sessions.", fg="gray", bg="#1e1e1e", font=("Arial", 10)).pack(pady=10)

root.mainloop()
