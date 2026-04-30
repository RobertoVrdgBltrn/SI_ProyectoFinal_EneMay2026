# client.py
# Cliente para chat por TCP o UDP
# Cambiar PROTOCOL para elegir el protocolo de comunicacion

import socket
import threading
import sys
import json
import rsa
from utils import (
    crear_mensaje,
    convertir_mensaje,
    actual_str,
    generar_claves_rsa,
    encriptar_rsa,
    desencriptar_rsa,
    validar_mensaje
)

# CONFIG
SERVER_HOST = "127.0.0.1"
SERVER_PORT = 5000
PROTOCOL = "TCP"


# Hilo que recibe mensajes cuando usamos TCP
def recibir_tcp(conn, client_priv):
    try:
        f = conn.makefile("r", encoding="utf-8")
        for linea in f:
            dato_cifrado = linea.strip()
            if dato_cifrado == "":
                continue
                
            dato = desencriptar_rsa(dato_cifrado, client_priv)
            if not dato:
                continue
                
            msg = convertir_mensaje(dato)
            if msg and validar_mensaje(msg):
                mostrar(msg)
    except Exception as e:
        print("Conexion cerrada o error:", e)
    finally:
        try:
            conn.close()
        except:
            pass


# Hilo que recibe datagramas cuando usamos UDP
def recibir_udp(sock):
    try:
        while True:
            datos, addr = sock.recvfrom(65535)
            try:
                msg = convertir_mensaje(datos.decode("utf-8"))
                if msg and validar_mensaje(msg):
                    mostrar(msg)
            except:
                pass
    except Exception as e:
        print("UDP cerrado:", e)


# Imprime mensajes de forma ordenada
def mostrar(msg):
    tipo = msg.get("type")
    t = msg.get("time")
    de = msg.get("from")
    txt = msg.get("text")
    para = msg.get("to")

    if tipo == "system":
        print(f"[{t}] * {txt}")
    elif tipo == "message":
        print(f"[{t}] [PÚBLICO] {de}: {txt}")
    elif tipo == "private":
        if para:
            print(f"[{t}] [PRIV] {de} -> {para}: {txt}")
        else:
            print(f"[{t}] [PRIV] {de}: {txt}")
    elif tipo in ("register_ok", "login_ok"):
        print(f"[{t}] {txt}")
    elif tipo in ("register_fail", "login_fail"):
        print(f"[{t}] ERROR: {txt}")
    else:
        print(f"[{t}] {de}: {txt}")


# Envia mensajes cuando se usa TCP
def enviar_mensajes_tcp(sock, username, server_pub):
    try:
        while True:
            texto = input()

            if texto == "/salir":
                msg = crear_mensaje("disconnect", username, "salio del chat")
                try:
                    cifrado = encriptar_rsa(msg, server_pub)
                    sock.sendall(cifrado.encode("utf-8") + b"\n")
                except:
                    pass
                print("Saliendo...")
                try:
                    sock.close()
                except:
                    pass
                break

            elif texto.startswith("/priv "):
                partes = texto.split(" ", 2)
                if len(partes) < 3:
                    print("Formato: /priv <usuario> <mensaje>")
                    continue
                dest = partes[1]
                contenido = partes[2]
                msg = crear_mensaje("private", username, contenido, dest)
                cifrado = encriptar_rsa(msg, server_pub)
                sock.sendall(cifrado.encode("utf-8") + b"\n")

            else:
                msg = crear_mensaje("message", username, texto)
                cifrado = encriptar_rsa(msg, server_pub)
                sock.sendall(cifrado.encode("utf-8") + b"\n")

    except:
        pass


# Envia mensajes cuando se usa UDP
def enviar_mensajes_udp(sock, username, server_addr):
    try:
        while True:
            linea = input()
            if linea == "":
                continue

            if linea.lower() == "/salir":
                msg = crear_mensaje("disconnect", username, "salio del chat")
                try:
                    sock.sendto(msg.encode("utf-8"), server_addr)
                except:
                    pass
                print("Saliendo...")
                break

            if linea.startswith("/priv "):
                try:
                    partes = linea.split(" ", 2)
                    destino = partes[1]
                    txt = partes[2]
                except:
                    print("Formato: /priv usuario mensaje")
                    continue
                msg = crear_mensaje("private", username, txt, destino)
                sock.sendto(msg.encode("utf-8"), server_addr)
            else:
                msg = crear_mensaje("message", username, linea)
                sock.sendto(msg.encode("utf-8"), server_addr)

    except Exception as e:
        print("Error UDP:", e)


# Inicio del cliente TCP
def iniciar_cliente_tcp():
    while True:
        # Menú de autenticacion 
        print("1) Iniciar sesion")
        print("2) Registrarse")
        opcion = input("Elige una opcion: ").strip()

        if opcion not in ("1", "2"):
            print("Opcion invalida. Intenta nuevamente.\n")
            continue

        usuario = input("Nombre de usuario: ").strip()
        if not usuario:
            print("El nombre no puede estar vacio. Intenta nuevamente.\n")
            continue

        password = input("Contrasena: ").strip()
        if not password:
            print("La contrasena no puede estar vacia. Intenta nuevamente.\n")
            continue

        # Conexion al servidor 
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.connect((SERVER_HOST, SERVER_PORT))
        except Exception as e:
            print("No se pudo conectar al servidor:", e, "\nIntenta de nuevo.\n")
            continue

        print("Generando claves RSA para comunicacion segura (1024 bits)...")
        client_pub, client_priv = generar_claves_rsa()

        # FASE 1: HANDSHAKE RSA 
        f = sock.makefile("r", encoding="utf-8")
        
        client_pub_pem = client_pub.save_pkcs1().decode("utf-8")
        handshake_msg = json.dumps({"type": "key_exchange", "key": client_pub_pem})
        sock.sendall(handshake_msg.encode("utf-8") + b"\n")
        
        resp_hs = f.readline()
        if not resp_hs:
            print("El servidor cerro la conexion sin enviar llave publica. Intenta de nuevo.\n")
            sock.close()
            continue
            
        hs = convertir_mensaje(resp_hs.strip())
        if not hs or hs.get("type") != "key_exchange" or not validar_mensaje(hs):
            print("Respuesta de intercambio de llaves invalida. Intenta de nuevo.\n")
            sock.close()
            continue
            
        try:
            server_pub = rsa.PublicKey.load_pkcs1(hs.get("key").encode("utf-8"))
        except Exception as e:
            print("Llave publica del servidor invalida:", e, "\nIntenta de nuevo.\n")
            sock.close()
            continue

        # FASE 2: AUTORIZACION (CIFRADA) 
        tipo_msg = "login" if opcion == "1" else "register"
        msg_credenciales = crear_mensaje(tipo_msg, usuario, password)
        
        # Enviar encriptado
        sock.sendall(encriptar_rsa(msg_credenciales, server_pub).encode("utf-8") + b"\n")

        # Leer respuesta del servidor (CRIPTADA) 
        linea_cifrada = f.readline()
        if not linea_cifrada:
            print("No respondio el servidor despues de enviar credenciales. Intenta de nuevo.\n")
            sock.close()
            continue

        linea_plano = desencriptar_rsa(linea_cifrada.strip(), client_priv)
        r = convertir_mensaje(linea_plano)
        if not r or not validar_mensaje(r):
            print("Respuesta invalida del servidor. Intenta de nuevo.\n")
            sock.close()
            continue

        tipo_resp = r.get("type")

        if tipo_resp in ("register_fail", "login_fail"):
            print("Error del servidor:", r.get("text"), "\nPor favor, intenta nuevamente.\n")
            sock.close()
            continue

        print("Listo, comunicacion cifrada con exito.")
        print("--- BIENVENIDO A LA SALA PÚBLICA (BROADCAST) ---")
        print("Escribe tus mensajes para hablar por la sala publica, o usa /priv <usuario> <msg> para privados. (/salir para terminar)")

        # Hilo receptor 
        threading.Thread(target=recibir_tcp, args=(sock, client_priv), daemon=True).start()

        # Hilo emisor 
        threading.Thread(
            target=enviar_mensajes_tcp, args=(sock, usuario, server_pub), daemon=True
        ).start()

        # Mantener el cliente activo
        try:
            while True:
                pass
        except KeyboardInterrupt:
            try:
                sock.close()
            except:
                pass
            print("Cliente TCP cerrado.")
            break


# Inicio del cliente UDP
def iniciar_cliente_udp():
    while True:
        usuario = input("Nombre usuario: ").strip()
        if usuario == "":
            print("No pusiste nombre. Intenta nuevamente.\n")
            continue

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        server_addr = (SERVER_HOST, SERVER_PORT)

        sock.sendto(crear_mensaje("register", usuario).encode("utf-8"), server_addr)

        sock.settimeout(5)
        try:
            datos, _ = sock.recvfrom(65535)
            r = convertir_mensaje(datos.decode("utf-8"))
            if not r or not validar_mensaje(r):
                print("Respuesta invalida del servidor UDP. Intenta de nuevo.\n")
                sock.close()
                continue

            if r.get("type") == "register_fail":
                print("Error:", r.get("text"), "\nIntenta de nuevo.\n")
                sock.close()
                continue
            print("Registrado.")
            print("--- BIENVENIDO A LA SALA PÚBLICA (BROADCAST) ---")
            print("Escribe tus mensajes para hablar por la sala publica, o usa /priv <usuario> <msg> para privados. (/salir para terminar)")
        except:
            print("No respondio el servidor o se agoto el tiempo. Verifica que este encendido.\n")
            sock.close()
            continue
        finally:
            sock.settimeout(None)

        threading.Thread(target=recibir_udp, args=(sock,), daemon=True).start()

        enviar_mensajes_udp(sock, usuario, server_addr)

        sock.close()
        break


if __name__ == "__main__":
    print("Cliente Chat. Protocolo:", PROTOCOL)
    if PROTOCOL == "TCP":
        iniciar_cliente_tcp()
    else:
        iniciar_cliente_udp()
