import os
import tkinter as tk
from tkinter import filedialog, messagebox
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes

BLOCK_SIZE = 16
KEY_SIZE = 32
SALT_SIZE = 16

# Derive encryption key from password
def derive_key(password, salt):
    return PBKDF2(password, salt, dkLen=KEY_SIZE, count=1000000)

# Pad data to be multiple of BLOCK_SIZE
def pad(data):
    padding = BLOCK_SIZE - len(data) % BLOCK_SIZE
    return data + bytes([padding]) * padding

# Unpad data
def unpad(data):
    return data[:-data[-1]]

# Encrypt file
def encrypt_file(file_path, password):
    with open(file_path, 'rb') as f:
        plaintext = f.read()

    salt = get_random_bytes(SALT_SIZE)
    key = derive_key(password.encode(), salt)
    iv = get_random_bytes(BLOCK_SIZE)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(plaintext))

    with open(file_path + '.enc', 'wb') as f:
        f.write(salt + iv + ciphertext)

    messagebox.showinfo("Success", "File encrypted successfully.")

# Decrypt file
def decrypt_file(file_path, password):
    with open(file_path, 'rb') as f:
        data = f.read()

    salt = data[:SALT_SIZE]
    iv = data[SALT_SIZE:SALT_SIZE + BLOCK_SIZE]
    ciphertext = data[SALT_SIZE + BLOCK_SIZE:]

    key = derive_key(password.encode(), salt)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ciphertext))

    decrypted_path = file_path.replace('.enc', '.dec')
    with open(decrypted_path, 'wb') as f:
        f.write(plaintext)

    messagebox.showinfo("Success", f"File decrypted to:\n{decrypted_path}")

# GUI
def select_encrypt():
    file_path = filedialog.askopenfilename()
    if file_path:
        password = password_entry.get()
        if password:
            encrypt_file(file_path, password)
        else:
            messagebox.showwarning("Missing", "Enter password!")

def select_decrypt():
    file_path = filedialog.askopenfilename(filetypes=[("Encrypted Files", "*.enc")])
    if file_path:
        password = password_entry.get()
        if password:
            decrypt_file(file_path, password)
        else:
            messagebox.showwarning("Missing", "Enter password!")

# Main Window
root = tk.Tk()
root.title("Advanced AES-256 File Encryptor")
root.geometry("400x200")
root.resizable(False, False)

tk.Label(root, text="Enter Password:", font=('Arial', 12)).pack(pady=10)
password_entry = tk.Entry(root, show="*", width=30, font=('Arial', 12))
password_entry.pack()

tk.Button(root, text="Encrypt File", command=select_encrypt, width=20, bg="#4caf50", fg="white").pack(pady=10)
tk.Button(root, text="Decrypt File", command=select_decrypt, width=20, bg="#2196f3", fg="white").pack(pady=5)

root.mainloop()
