#!/usr/bin/env python3

import gmpy2
from gmpy2 import mpz
import os

def generate_prime(bits):
  """Generates a random prime number with the specified number of bits."""
  seed_bytes = os.urandom(32)  # Use cryptographically secure random seed
  # Assuming your system is little-endian, extract the first 4 bytes as an integer
  seed = int.from_bytes(seed_bytes[:4], 'little')  # Adjust byte order if needed
  state = gmpy2.random_state(seed)
  return mpz(gmpy2.next_prime(gmpy2.mpz_urandomb(state, bits)))

def generate_keys(bits=2048):
  """Generates a public and private key pair for RSA encryption."""
  p = generate_prime(bits // 2)
  q = generate_prime(bits // 2)
  n = p * q
  phi_n = (p - 1) * (q - 1)

  e = mpz(65537)  # Common choice for e
  try:
      d = gmpy2.invert(e, phi_n)
  except ZeroDivisionError:
      raise ValueError("Failed to generate keys: e and phi_n don't have a modular inverse")

  return (e, n), (d, n)

def encrypt(plaintext, public_key):
  """Encrypts a plaintext message using the public key."""
  e, n = public_key
  m = mpz(plaintext)  # convert plaintext to an integer
  c = gmpy2.powmod(m, e, n)
  return c

def decrypt(ciphertext, private_key):
  """Decrypts a ciphertext using the private key."""
  d, n = private_key
  c = mpz(ciphertext)
  m = gmpy2.powmod(c, d, n)

  # Assuming the message can be represented by a Python integer
  decrypted_int = int(m)
  return decrypted_int  # Return raw decrypted bytes

def main():
  """Generates keys, encrypts a message, and decrypts it."""
  public_key, private_key = generate_keys(2048)

  print("Public key:", public_key)
  print("Private key:", private_key)
  # Get message input from the user
  message = input("Enter your message to encrypt: ")

  # Encode message to bytes before encryption (if needed for UTF-8)
  message_bytes = message.encode('utf-8')
  message_int = int.from_bytes(message_bytes, 'big')

  encrypted_msg = encrypt(message_int, public_key)
  print("Encrypted:", encrypted_msg)

  decrypted_int = decrypt(encrypted_msg, private_key)
  # Convert decrypted integer back to bytes (if encoded before)
  decrypted_bytes = decrypted_int.to_bytes((encrypted_msg.bit_length() + 7) // 8, 'big')
  decrypted_text = decrypted_bytes.decode('utf-8')  # Decode if necessary

  print("Decrypted:", decrypted_text)

if __name__ == "__main__":
  main()
