import unittest

from rsa import generate_large_prime, encrypt, decrypt, find_coprime, modinv, gcd


class TestRSAFunctions(unittest.TestCase):
    def test_prime_generation(self):
        prime = generate_large_prime(512)
        # Simple primality test; consider a more robust method or a property-based test
        self.assertTrue(prime > 1)

    def test_coprime(self):
        phi_n = 36  # Example value for phi(n)
        e = find_coprime(phi_n)
        self.assertTrue(e > 1 and gcd(e, phi_n) == 1)

    def test_modular_inverse(self):
        e = 7
        phi_n = 40
        d = modinv(e, phi_n)
        # 7 * 23 = 161, which is 1 modulo 40
        self.assertEqual(d, 23)


    def test_encryption_decryption(self):
    	keysize = 1024
    	p = generate_large_prime(keysize)
    	q = generate_large_prime(keysize)
    	n = p * q
    	phi_n = (p - 1) * (q - 1)
    	e = find_coprime(phi_n)
    	d = modinv(e, phi_n)
    	plaintext = "Hello, RSA!"
    	ciphertext = encrypt(plaintext, e, n)
    	decrypted_text = decrypt(ciphertext, d, n)
    	self.assertEqual(decrypted_text, plaintext)
    """def test_encryption_decryption(self):
        keysize = 512
        p = generate_large_prime(keysize)
        q = generate_large_prime(keysize)
        n = p * q
        phi_n = (p - 1) * (q - 1)
        e = find_coprime(phi_n)
        d = modinv(e, phi_n)
        plaintext = "Hello, RSA!"
        ciphertext = encrypt(plaintext, e, n)
        decrypted_text = decrypt(ciphertext, d, n)
        self.assertEqual(decrypted_text, plaintext)"""

if __name__ == '__main__':
    unittest.main()
