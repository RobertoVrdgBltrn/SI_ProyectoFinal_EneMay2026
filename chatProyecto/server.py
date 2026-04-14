# server.py
# Servidor para chat por TCP o UDP
# Cambiar PROTOCOL = "TCP" o "UDP" segun lo que se quiere probar

import socket
import threading
import sys
from utils import (
    crearMensaje,
    leerMensaje,
    fecha_hora,
    log_evento,
    log_error,
    hashear_password,
    verificar_password,
    cargar_usuarios,
    guardar_usuarios,
)

# Configuracion basica del servidor
HOST = "127.0.0.1"
PORT = 5000
MAX_CLIENTS = 6
PROTOCOL = "TCP"

lock = threading.Lock()

if PROTOCOL == "TCP":
    usuarios = {}
else:
    usuarios = {}


# Envia un mensaje a todos los clientes conectados
def mandarATodos_tcp(msg_json):
    with lock:
        for nombre, conn in list(usuarios.items()):
            try:
                conn.sendall(msg_json.encode("utf-8") + b"\n")
            except:
                try:
                    conn.close()
                except:
                    pass
                del usuarios[nombre]


def mandarPrivado_tcp(user, msg_json):
    with lock:
        dest = usuarios.get(user)
        if dest:
            try:
                dest.sendall(msg_json.encode("utf-8") + b"\n")
            except:
                try:
                    dest.close()
                except:
                    pass
                del usuarios[user]


# Atiende a un cliente TCP individual en un hilo
def atenderCliente_tcp(conn, addr):

    nombreUser = None

    try:
        with conn:
            archivo = conn.makefile("r", encoding="utf-8")

            # Leer primer mensaje (login o register)
            primera = archivo.readline()
            if not primera:
                return

            msg = leerMensaje(primera.strip())

            # ── LOGIN (usuario existente) ──────────────────────────
            if msg and msg.get("type") == "login":
                usuario_bd = cargar_usuarios()
                pedido = msg.get("from")
                pw_recibido = msg.get("text", "")

                if pedido not in usuario_bd:
                    conn.sendall(
                        crearMensaje(
                            "login_fail", "SERVER", "Usuario no existe"
                        ).encode("utf-8")
                        + b"\n"
                    )
                    log_error(f"LOGIN FAIL (usuario no existe): {pedido} desde {addr}")
                    return

                if not verificar_password(pw_recibido, usuario_bd[pedido]):
                    conn.sendall(
                        crearMensaje(
                            "login_fail", "SERVER", "Contrasena incorrecta"
                        ).encode("utf-8")
                        + b"\n"
                    )
                    log_error(
                        f"LOGIN FAIL (contrasena incorrecta): {pedido} desde {addr}"
                    )
                    return

                with lock:
                    if pedido in usuarios:
                        conn.sendall(
                            crearMensaje(
                                "login_fail", "SERVER", "Ya esta conectado"
                            ).encode("utf-8")
                            + b"\n"
                        )
                        return
                    if len(usuarios) >= MAX_CLIENTS:
                        conn.sendall(
                            crearMensaje(
                                "login_fail", "SERVER", "Servidor lleno"
                            ).encode("utf-8")
                            + b"\n"
                        )
                        return
                    usuarios[pedido] = conn
                    nombreUser = pedido
                    conn.sendall(
                        crearMensaje("login_ok", "SERVER", "Login correcto").encode(
                            "utf-8"
                        )
                        + b"\n"
                    )

                log_evento(f"LOGIN OK: {pedido} desde {addr}")
                print(f"[{fecha_hora()}] {pedido} se conecto desde {addr}")

            # ── REGISTRO (usuario nuevo) ───────────────────────────
            elif msg and msg.get("type") == "register":
                pedido = msg.get("from")
                pw_texto = msg.get("text", "")

                if not pw_texto:
                    conn.sendall(
                        crearMensaje(
                            "register_fail", "SERVER", "Contrasena vacia"
                        ).encode("utf-8")
                        + b"\n"
                    )
                    return

                usuario_bd = cargar_usuarios()
                if pedido in usuario_bd:
                    conn.sendall(
                        crearMensaje(
                            "register_fail", "SERVER", "Usuario ya existe"
                        ).encode("utf-8")
                        + b"\n"
                    )
                    log_error(f"REGISTER FAIL (ya existe): {pedido} desde {addr}")
                    return

                usuario_bd[pedido] = hashear_password(pw_texto)
                guardar_usuarios(usuario_bd)

                with lock:
                    if len(usuarios) >= MAX_CLIENTS:
                        conn.sendall(
                            crearMensaje(
                                "register_fail", "SERVER", "Servidor lleno"
                            ).encode("utf-8")
                            + b"\n"
                        )
                        return
                    usuarios[pedido] = conn
                    nombreUser = pedido
                    conn.sendall(
                        crearMensaje(
                            "register_ok", "SERVER", "Registro OK, bienvenido"
                        ).encode("utf-8")
                        + b"\n"
                    )

                log_evento(f"REGISTER OK: {pedido} desde {addr}")
                print(f"[{fecha_hora()}] NUEVO USUARIO {pedido} desde {addr}")

            else:
                conn.sendall(
                    crearMensaje(
                        "register_fail", "SERVER", "Primer mensaje invalido"
                    ).encode("utf-8")
                    + b"\n"
                )
                return

            # Avisar a todos que alguien entro
            mandarATodos_tcp(
                crearMensaje("system", "SERVER", f"{nombreUser} entro al chat")
            )

            # Leer mensajes del cliente
            for linea in archivo:
                dato = linea.strip()
                if not dato:
                    continue

                msg = leerMensaje(dato)
                if not msg:
                    continue

                tipo = msg.get("type")

                if tipo == "message":
                    texto = msg.get("text")
                    print(f"[{fecha_hora()}] PUBLICO {msg.get('from')}: {texto}")
                    log_evento(f"MSG PUBLICO {msg.get('from')}: {texto}")
                    mandarATodos_tcp(crearMensaje("message", msg.get("from"), texto))

                elif tipo == "private":
                    dest = msg.get("to")
                    texto = msg.get("text")
                    print(
                        f"[{fecha_hora()}] PRIVADO {msg.get('from')} -> {dest}: {texto}"
                    )
                    log_evento(f"MSG PRIVADO {msg.get('from')} -> {dest}: {texto}")
                    mandarPrivado_tcp(
                        dest, crearMensaje("private", msg.get("from"), texto, dest)
                    )
                    conn.sendall(
                        crearMensaje("private", msg.get("from"), texto, dest).encode(
                            "utf-8"
                        )
                        + b"\n"
                    )

                elif tipo == "disconnect":
                    break

    except Exception as e:
        print("Error en cliente:", e)
        log_error(f"Error en cliente {nombreUser}: {e}")

    finally:
        if nombreUser:
            with lock:
                if nombreUser in usuarios:
                    try:
                        usuarios[nombreUser].close()
                    except:
                        pass
                    del usuarios[nombreUser]

            print(f"[{fecha_hora()}] {nombreUser} se desconecto")
            log_evento(f"DESCONEXION: {nombreUser}")
            mandarATodos_tcp(
                crearMensaje("system", "SERVER", f"{nombreUser} salio del chat")
            )


# Inicia servidor TCP
def servidor_tcp():
    print("Servidor TCP iniciado en", HOST, PORT)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((HOST, PORT))
    s.listen()

    try:
        while True:
            conn, addr = s.accept()
            hilo = threading.Thread(
                target=atenderCliente_tcp, args=(conn, addr), daemon=True
            )
            hilo.start()
    except KeyboardInterrupt:
        print("Servidor detenido")
    finally:
        s.close()


# Inicia servidor UDP
def servidor_udp():
    print("Servidor UDP iniciado en", HOST, PORT)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind((HOST, PORT))

    try:
        while True:
            data, addr = s.recvfrom(60000)
            txt = data.decode("utf-8").strip()
            msg = leerMensaje(txt)
            if not msg:
                continue

            tipo = msg.get("type")

            if tipo == "register":
                nombre = msg.get("from")
                with lock:
                    if nombre in usuarios:
                        s.sendto(
                            crearMensaje(
                                "register_fail", "SERVER", "Usuario repetido"
                            ).encode("utf-8"),
                            addr,
                        )
                        continue
                    if len(usuarios) >= MAX_CLIENTS:
                        s.sendto(
                            crearMensaje(
                                "register_fail", "SERVER", "Servidor lleno"
                            ).encode("utf-8"),
                            addr,
                        )
                        continue

                    usuarios[nombre] = addr
                    s.sendto(
                        crearMensaje("register_ok", "SERVER", "ok").encode("utf-8"),
                        addr,
                    )
                    print(f"[{fecha_hora()}] {nombre} registrado {addr}")
                    log_evento(f"REGISTER OK (UDP): {nombre} desde {addr}")

                    for u, a in usuarios.items():
                        if u != nombre:
                            s.sendto(
                                crearMensaje(
                                    "system", "SERVER", f"{nombre} entro"
                                ).encode("utf-8"),
                                a,
                            )
                continue

            if tipo == "message":
                de = msg.get("from")
                texto = msg.get("text")
                print(f"[{fecha_hora()}] PUBLICO {de}: {texto}")
                log_evento(f"MSG PUBLICO (UDP) {de}: {texto}")
                with lock:
                    for u, a in usuarios.items():
                        s.sendto(crearMensaje("message", de, texto).encode("utf-8"), a)
                continue

            if tipo == "private":
                de = msg.get("from")
                para = msg.get("to")
                texto = msg.get("text")
                print(f"[{fecha_hora()}] PRIVADO {de} -> {para}: {texto}")
                log_evento(f"MSG PRIVADO (UDP) {de} -> {para}: {texto}")
                with lock:
                    dest = usuarios.get(para)
                    if dest:
                        s.sendto(
                            crearMensaje("private", de, texto, para).encode("utf-8"),
                            dest,
                        )
                    yo = usuarios.get(de)
                    if yo:
                        s.sendto(
                            crearMensaje("private", de, texto, para).encode("utf-8"), yo
                        )
                continue

            if tipo == "disconnect":
                de = msg.get("from")
                print(f"[{fecha_hora()}] {de} se desconecto (UDP)")
                log_evento(f"DESCONEXION (UDP): {de}")
                with lock:
                    if de in usuarios:
                        del usuarios[de]
                    for u, a in usuarios.items():
                        s.sendto(
                            crearMensaje(
                                "system", "SERVER", f"{de} salio del chat"
                            ).encode("utf-8"),
                            a,
                        )
                continue

    except KeyboardInterrupt:
        print("Servidor UDP detenido")
    finally:
        s.close()


# MAIN
if __name__ == "__main__":
    print("Servidor de chat. Protocolo =", PROTOCOL)

    if PROTOCOL == "TCP":
        servidor_tcp()
    else:
        servidor_udp()
