# client.py
# Cliente para chat por TCP o UDP
# Cambiar PROTOCOL para elegir el protocolo de comunicacion

import socket
import threading
import sys
from utils import crear_mensaje, convertir_mensaje, actual_str

# CONFIG
SERVER_HOST = "127.0.0.1"
SERVER_PORT = 5000
PROTOCOL = "TCP"


# Hilo que recibe mensajes cuando usamos TCP
def recibir_tcp(conn):
    try:
        f = conn.makefile("r", encoding="utf-8")
        for linea in f:
            linea = linea.strip()
            if linea == "":
                continue
            msg = convertir_mensaje(linea)
            if msg:
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
                if msg:
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
        print(f"[{t}] {de}: {txt}")
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
def enviar_mensajes_tcp(sock, username):
    try:
        while True:
            texto = input()

            if texto == "/salir":
                msg = crear_mensaje("disconnect", username, "salio del chat")
                try:
                    sock.sendall(msg.encode("utf-8") + b"\n")
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
                sock.sendall(msg.encode("utf-8") + b"\n")

            else:
                msg = crear_mensaje("message", username, texto)
                sock.sendall(msg.encode("utf-8") + b"\n")

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

    # ── Menú de autenticacion ──────────────────────────────
    print("1) Iniciar sesion")
    print("2) Registrarse")
    opcion = input("Elige una opcion: ").strip()

    if opcion not in ("1", "2"):
        print("Opcion invalida.")
        return

    usuario = input("Nombre de usuario: ").strip()
    if not usuario:
        print("El nombre no puede estar vacio.")
        return

    password = input("Contrasena: ").strip()
    if not password:
        print("La contrasena no puede estar vacia.")
        return

    # ── Conexion al servidor ───────────────────────────────
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.connect((SERVER_HOST, SERVER_PORT))
    except Exception as e:
        print("No se pudo conectar:", e)
        return

    # Determinar tipo de mensaje segun la opcion elegida
    tipo_msg = "login" if opcion == "1" else "register"

    # Enviar credenciales al servidor
    # La contrasena viaja en texto plano; el servidor la hashea al registrar
    # y la compara con bcrypt al hacer login
    sock.sendall(crear_mensaje(tipo_msg, usuario, password).encode("utf-8") + b"\n")

    # ── Leer respuesta del servidor ────────────────────────
    f = sock.makefile("r", encoding="utf-8")
    linea = f.readline()
    if not linea:
        print("No respondio el servidor.")
        sock.close()
        return

    r = convertir_mensaje(linea.strip())
    if not r:
        print("Respuesta invalida del servidor.")
        sock.close()
        return

    tipo_resp = r.get("type")

    if tipo_resp in ("register_fail", "login_fail"):
        print("Error:", r.get("text"))
        sock.close()
        return

    print(r.get("text"))
    print(
        "Listo, ya puedes escribir. (/priv <usuario> <msg> para privado | /salir para salir)"
    )

    # ── Hilo receptor ──────────────────────────────────────
    threading.Thread(target=recibir_tcp, args=(sock,), daemon=True).start()

    # ── Hilo emisor ────────────────────────────────────────
    threading.Thread(
        target=enviar_mensajes_tcp, args=(sock, usuario), daemon=True
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


# Inicio del cliente UDP
def iniciar_cliente_udp():
    usuario = input("Nombre usuario: ").strip()
    if usuario == "":
        print("No pusiste nombre.")
        return

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_addr = (SERVER_HOST, SERVER_PORT)

    sock.sendto(crear_mensaje("register", usuario).encode("utf-8"), server_addr)

    sock.settimeout(5)
    try:
        datos, _ = sock.recvfrom(65535)
        r = convertir_mensaje(datos.decode("utf-8"))
        if r.get("type") == "register_fail":
            print("Error:", r.get("text"))
            sock.close()
            return
        print("Registrado. Ya puedes escribir.")
    except:
        print("No respondio el servidor.")
        sock.close()
        return
    finally:
        sock.settimeout(None)

    threading.Thread(target=recibir_udp, args=(sock,), daemon=True).start()

    enviar_mensajes_udp(sock, usuario, server_addr)

    sock.close()


if __name__ == "__main__":
    print("Cliente Chat. Protocolo:", PROTOCOL)
    if PROTOCOL == "TCP":
        iniciar_cliente_tcp()
    else:
        iniciar_cliente_udp()
