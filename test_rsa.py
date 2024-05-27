#!/usr/bin/env python3

import random
from sympy import nextprime
import tkinter as tk
from tkinter import simpledialog, messagebox, filedialog
import hashlib

def generate_large_prime(keysize):
    """Generate a random large prime number."""
    random_large_number = random.getrandbits(keysize // 2)
    return nextprime(random_large_number)

def gcd(a, b):
    """Compute the greatest common divisor of a and b."""
    while b:
        a, b = b, a % b
    return a

def find_coprime(phi_n):
    """Find an integer e that is coprime to phi_n."""
    e = 2
    while e < phi_n:
        if gcd(e, phi_n) == 1:
            return e
        e += 1

def modinv(a, m):
    """Compute the modular inverse of a under modulo m."""
    m0, x0, x1 = m, 0, 1
    if m == 1:
        return 0
    while a > 1:
        q = a // m
        m, a = a % m, m
        x0, x1 = x1 - q * x0, x0
    if x1 < 0:
        x1 += m0
    return x1
def encrypt(plaintext, e, n):
    padded_message = oaep_pad(plaintext.encode(), 1024)  # keysize needs to match your settings
    ciphertext = [pow(int.from_bytes(padded_message[i:i+1], byteorder='big'), e, n) for i in range(0, len(padded_message), 1)]
    return ciphertext

def decrypt(ciphertext, d, n):
    decrypted_bytes = b''.join([int.to_bytes(pow(num, d, n), 1, byteorder='big') for num in ciphertext])
    return oaep_unpad(decrypted_bytes).decode()
    
"""
def encrypt(plaintext, e, n):
    Encrypt plaintext using the public key (e, n) with OAEP padding.
    plaintext = oaep_pad(plaintext.encode(), hash_algo=hashlib.sha256)
    ciphertext = [pow(int.from_bytes(plaintext[i:i+2], byteorder='big'), e, n) for i in range(0, len(plaintext), 2)]
    return ciphertext

def decrypt(ciphertext, d, n):
    Decrypt ciphertext using the private key (d, n) and remove OAEP padding.
    decrypted = b''.join([int.to_bytes(pow(num, d, n), 2, byteorder='big') for num in ciphertext])
    return oaep_unpad(decrypted).decode()

"""
def oaep_pad(message, keysize, hash_algo=hashlib.sha256):
    """ Apply OAEP padding to the message. """
    hash_len = hash_algo().digest_size
    max_message_length = keysize // 8 - 2 * hash_len - 2
    if len(message) > max_message_length:
        raise ValueError("Message too long.")
    padding_length = max_message_length - len(message)
    padding = b'\x00' * padding_length
    return b'\x00' * hash_len + padding + b'\x01' + message

def oaep_unpad(padded_message, hash_algo=hashlib.sha256):
    """ Remove OAEP padding from the message. """
    hash_len = hash_algo().digest_size
    # Find the separator, which is the first non-null byte after the hash length of zeros
    sep_index = padded_message.index(b'\x01', hash_len)
    return padded_message[sep_index + 1:]


"""def oaep_pad(data, hash_algo=hashlib.sha256):
     Apply OAEP padding to the data before encryption. 
    hash_len = hash_algo().digest_size
    padding_length = 128 - len(data) - 2 * hash_len - 2
    padding = bytes([0]*padding_length)
    pad = hash_algo(b'').digest() + padding + b'\x01' + data
    return pad

def oaep_unpad(data, hash_algo=hashlib.sha256):
    Remove OAEP padding after decryption.
    hash_len = hash_algo().digest_size
    return data[2 * hash_len + 1:]
"""
def main_gui():
    root = tk.Tk()
    root.title("RSA Encryption Tool")

    tk.Label(root, text="Enter Text to Encrypt:").pack()
    text_entry = tk.Entry(root, width=50)
    text_entry.pack()

    # Key generation
    keysize = 1024
    p = generate_large_prime(keysize)
    q = generate_large_prime(keysize)
    n = p * q
    phi_n = (p - 1) * (q - 1)
    e = find_coprime(phi_n)
    d = modinv(e, phi_n)

    def encrypt_message():
        plaintext = text_entry.get()
        if plaintext:
            ciphertext = encrypt(plaintext, e, n)
            formatted_cipher = ','.join(map(str, ciphertext))
            messagebox.showinfo("Encrypted", f"Encrypted Text: {formatted_cipher}")
            text_entry.delete(0, tk.END)
        else:
            messagebox.showerror("Error", "Please enter some text to encrypt")

    def decrypt_message():
        ciphertext_str = simpledialog.askstring("Decrypt", "Enter Ciphertext (comma separated integers):")
        ciphertext = list(map(int, ciphertext_str.split(',')))
        decrypted_text = decrypt(ciphertext, d, n)
        messagebox.showinfo("Decrypted", f"Decrypted Text: {decrypted_text}")

    def save_cipher():
        ciphertext_str = simpledialog.askstring("Save Ciphertext", "Enter Ciphertext to save:")
        file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt")])
        if file_path:
            with open(file_path, 'w') as file:
                file.write(ciphertext_str)

    tk.Button(root, text="Encrypt", command=encrypt_message).pack()
    tk.Button(root, text="Decrypt", command=decrypt_message).pack()
    tk.Button(root, text="Save Ciphertext", command=save_cipher).pack()

    root.mainloop()

if __name__ == "__main__":
    main_gui()

