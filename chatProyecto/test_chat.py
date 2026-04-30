import unittest
import json
import rsa
import time
import socket
import threading
from utils import (
    sanitizar_texto,
    validar_mensaje,
    hashear_password,
    verificar_password,
    crearMensaje,
    convertir_mensaje,
    generar_claves_rsa,
    encriptar_rsa,
    desencriptar_rsa
)

class TestUtils(unittest.TestCase):

    def test_sanitizar_texto(self):
        # Remove control characters like \x00, \b but keep standard chars
        self.assertEqual(sanitizar_texto("Hola\x00\bMundo"), "HolaMundo")
        self.assertEqual(sanitizar_texto("A normal string"), "A normal string")
        self.assertEqual(sanitizar_texto(None), "")
        self.assertEqual(sanitizar_texto("    Trimmed   "), "Trimmed")

    def test_validar_mensaje(self):
        # Valid message
        valid = {"type": "message", "from": "user", "text": "hello"}
        self.assertTrue(validar_mensaje(valid))

        # Invalid due to extra long string
        invalid_from = {"type": "message", "from": "A" * 50, "text": "hello"}
        self.assertFalse(validar_mensaje(invalid_from))
        
        invalid_text = {"type": "message", "from": "user", "text": "A" * 3000}
        self.assertFalse(validar_mensaje(invalid_text))

        # Invalid type
        self.assertFalse(validar_mensaje([]))
        self.assertFalse(validar_mensaje(None))

    def test_password_hashing(self):
        password = "mypassword123"
        hashed = hashear_password(password)
        
        self.assertTrue(verificar_password(password, hashed))
        self.assertFalse(verificar_password("wrongpassword", hashed))

    def test_rsa_encryption(self):
        pub, priv = generar_claves_rsa()
        msj = "Este es un mensaje secreto."
        
        cifrado = encriptar_rsa(msj, pub)
        self.assertNotEqual(msj, cifrado)
        
        descifrado = desencriptar_rsa(cifrado, priv)
        self.assertEqual(msj, descifrado)
        
    def test_rsa_encryption_long(self):
        pub, priv = generar_claves_rsa()
        # Message longer than chunk size (117)
        msj = "A" * 500
        cifrado = encriptar_rsa(msj, pub)
        descifrado = desencriptar_rsa(cifrado, priv)
        self.assertEqual(msj, descifrado)

    def test_crear_convertir_mensaje(self):
        raw = crearMensaje("message", "A\x00", "B", "C")
        msg = convertir_mensaje(raw)
        
        self.assertIsNotNone(msg)
        self.assertEqual(msg["from"], "A")
        self.assertEqual(msg["text"], "B")
        self.assertEqual(msg["to"], "C")
        self.assertEqual(msg["type"], "message")
        self.assertTrue("time" in msg)

if __name__ == '__main__':
    unittest.main()
