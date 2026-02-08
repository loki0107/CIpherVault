import customtkinter as ctk
from cryptography.fernet import Fernet

# --- Logic ---
key = None

def generate_key():
    global key
    key = Fernet.generate_key()
    key_entry.delete(0, ctk.END)
    key_entry.insert(0, key.decode())
    status_label.configure(text="New Key Generated! Save it securely.", text_color="#00FF00")

def perform_encryption():
    global key
    try:
        current_key = key_entry.get().encode()
        if not current_key:
            status_label.configure(text="Error: Key is missing!", text_color="#FF5555")
            return
        
        f = Fernet(current_key)
        message = input_text.get("1.0", ctk.END).strip()
        if not message:
            status_label.configure(text="Error: Message is empty!", text_color="#FF5555")
            return

        encrypted = f.encrypt(message.encode())
        output_text.delete("1.0", ctk.END)
        output_text.insert("1.0", encrypted.decode())
        status_label.configure(text="Encryption Successful!", text_color="#00FF00")
    except Exception as e:
        status_label.configure(text=f"Error: {str(e)}", text_color="#FF5555")

def perform_decryption():
    try:
        current_key = key_entry.get().encode()
        f = Fernet(current_key)
        cipher_text = input_text.get("1.0", ctk.END).strip()
        
        decrypted = f.decrypt(cipher_text.encode())
        output_text.delete("1.0", ctk.END)
        output_text.insert("1.0", decrypted.decode())
        status_label.configure(text="Decryption Successful!", text_color="#00FF00")
    except Exception as e:
        status_label.configure(text="Error: Invalid Key or Token", text_color="#FF5555")

# --- UI Setup ---
ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

app = ctk.CTk()
app.geometry("500x600")
app.title("CipherVault - Secure Encryption")

# Title
title_label = ctk.CTkLabel(app, text="CipherVault AES-128", font=("Roboto Medium", 24))
title_label.pack(pady=20)

# Key Section
key_frame = ctk.CTkFrame(app)
key_frame.pack(pady=10, padx=20, fill="x")

key_entry = ctk.CTkEntry(key_frame, placeholder_text="Enter Key or Generate New")
key_entry.pack(side="left", padx=10, pady=10, expand=True, fill="x")

gen_btn = ctk.CTkButton(key_frame, text="Generate Key", command=generate_key, width=100)
gen_btn.pack(side="right", padx=10)

# Input Section
input_label = ctk.CTkLabel(app, text="Input Text (Plain or Encrypted):", anchor="w")
input_label.pack(padx=25, anchor="w")
input_text = ctk.CTkTextbox(app, height=100)
input_text.pack(padx=20, pady=(5, 20), fill="x")

# Buttons
btn_frame = ctk.CTkFrame(app, fg_color="transparent")
btn_frame.pack(pady=5)
encrypt_btn = ctk.CTkButton(btn_frame, text="🔒 ENCRYPT", command=perform_encryption, fg_color="#1f538d")
encrypt_btn.grid(row=0, column=0, padx=10)
decrypt_btn = ctk.CTkButton(btn_frame, text="🔓 DECRYPT", command=perform_decryption, fg_color="#2d8d2d")
decrypt_btn.grid(row=0, column=1, padx=10)

# Output Section
output_label = ctk.CTkLabel(app, text="Result:", anchor="w")
output_label.pack(padx=25, pady=(20, 0), anchor="w")
output_text = ctk.CTkTextbox(app, height=100)
output_text.pack(padx=20, pady=5, fill="x")

# Status Bar
status_label = ctk.CTkLabel(app, text="Ready", text_color="gray")
status_label.pack(side="bottom", pady=10)

app.mainloop()