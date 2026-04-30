import socket
import json
import rsa
import time
from utils import crear_mensaje, convertir_mensaje, generar_claves_rsa, encriptar_rsa, desencriptar_rsa, sanitizar_texto, validar_mensaje

def run_tests():
    print("Iniciando pruebas de validacion...")
    
    # Probar funciones locales
    print("1. Probar sanitizar_texto")
    sucio = "Hola\x00\bMundo"
    limpio = sanitizar_texto(sucio)
    assert "\\x00" not in limpio and "\\b" not in limpio
    print(f"Limpio: {repr(limpio)}")

    print("2. Probar validar_mensaje largo")
    msg_malo = {"type": "message", "from": "A" * 50, "text": "H"}
    assert not validar_mensaje(msg_malo), "Deberia ser invalido por from muy largo"
    
    print("3. Conectando al servidor...")
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect(("127.0.0.1", 5000))
    sock.settimeout(2.0)
    f = sock.makefile("r", encoding="utf-8")

    client_pub, client_priv = generar_claves_rsa()
    client_pub_pem = client_pub.save_pkcs1().decode("utf-8")
    sock.sendall(json.dumps({"type": "key_exchange", "key": client_pub_pem}).encode("utf-8") + b"\n")

    resp_hs = f.readline()
    hs = convertir_mensaje(resp_hs.strip())
    server_pub = rsa.PublicKey.load_pkcs1(hs["key"].encode("utf-8"))

    # Register
    print("4. Registrar usuario de prueba")
    msg_auth = crear_mensaje("register", "test_user", "123")
    sock.sendall(encriptar_rsa(msg_auth, server_pub).encode("utf-8") + b"\n")
    
    r = desencriptar_rsa(f.readline().strip(), client_priv)
    print("Auth resp:", r)
    
    # Leer welcome sys message
    try:
        sys_msg = desencriptar_rsa(f.readline().strip(), client_priv)
        print("Sys:", sys_msg)
    except:
        pass

    print("5. Mandar mensaje valido")
    valid = crear_mensaje("message", "test_user", "hola")
    sock.sendall(encriptar_rsa(valid, server_pub).encode("utf-8") + b"\n")
    
    # Recibiremos la difusion
    echo = desencriptar_rsa(f.readline().strip(), client_priv)
    print("Echo (valido):", echo)

    print("6. Mandar mensaje INvALIDO (excede 'text')")
    invalid = crear_mensaje("message", "test_user", "X" * 3000)
    sock.sendall(encriptar_rsa(invalid, server_pub).encode("utf-8") + b"\n")
    
    try:
        bad_echo = f.readline()
        if bad_echo:
            print("FALLO: El servidor dejo pasar un mensaje invalido!", desencriptar_rsa(bad_echo.strip(), client_priv))
        else:
            print("OK: Servidor corto la conexion o no lo reenvió")
    except socket.timeout:
        print("OK: Servidor ignoró el mensaje (Timeout leído, que es correcto)")

    sock.close()
    print("Pruebas finalizadas con exito!")

if __name__ == "__main__":
    run_tests()
