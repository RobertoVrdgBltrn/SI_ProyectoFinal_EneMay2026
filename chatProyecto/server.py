# server.py
# Servidor para chat por TCP o UDP
# Cambiar PROTOCOL = "TCP" o "UDP" segun lo que se quiere probar

import socket
import threading
import sys
import json
import rsa
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
    generar_claves_rsa,
    encriptar_rsa,
    desencriptar_rsa,
    convertir_mensaje,
    validar_mensaje,
)

# Configuracion basica del servidor
HOST = "127.0.0.1"
PORT = 5000
MAX_CLIENTS = 6
PROTOCOL = "TCP"

lock = threading.Lock()

print("Generando claves RSA del servidor (1024 bits)...")
servidor_pub, servidor_priv = generar_claves_rsa()
claves_clientes_auth = {} # usuario -> llave publica

if PROTOCOL == "TCP":
    usuarios = {}
else:
    usuarios = {}


# Envia un mensaje a todos los clientes conectados
def mandarATodos_tcp(msg_json):
    """
    Recibe un mensaje JSON cifrado per-cliente con su respectiva llave publica.
    Itera sobre la lista de usuarios TCP y lo envía a todos los conectados.
    """
    with lock:
        for nombre, conn in list(usuarios.items()):
            try:
                pub_key = claves_clientes_auth.get(nombre)
                if pub_key:
                    cifrado = encriptar_rsa(msg_json, pub_key)
                    conn.sendall(cifrado.encode("utf-8") + b"\n")
            except:
                try:
                    conn.close()
                except:
                    pass
                if nombre in usuarios:
                    del usuarios[nombre]
                if nombre in claves_clientes_auth:
                    del claves_clientes_auth[nombre]

def mandarPrivado_tcp(user, msg_json):
    """
    Recibe un identificador de usuario y un mensaje, cifra el contenido especificamente
    con la llave publica guardada para ese usuario y se lo envia de manera unicast.
    """
    with lock:
        dest = usuarios.get(user)
        pub_key = claves_clientes_auth.get(user)
        if dest and pub_key:
            try:
                cifrado = encriptar_rsa(msg_json, pub_key)
                dest.sendall(cifrado.encode("utf-8") + b"\n")
            except:
                try:
                    dest.close()
                except:
                    pass
                if user in usuarios:
                    del usuarios[user]
                if user in claves_clientes_auth:
                    del claves_clientes_auth[user]


# Atiende a un cliente TCP individual en un hilo
def atenderCliente_tcp(conn, addr):
    """
    Ciclo de vida para un socket TCP individual:
    1. Intercambia llaves RSA públicas.
    2. Valida credenciales e inscribe al usuario.
    3. Mantiene un ciclo infinito escuchando peticiones, validando, y transmitiendolás
       hasta que el cliente cierra sesion.
    """

    nombreUser = None
    client_pub_key = None

    def enviar_anonimo(texto_json):
        if client_pub_key:
            cifrado = encriptar_rsa(texto_json, client_pub_key)
            conn.sendall(cifrado.encode("utf-8") + b"\n")

    try:
        with conn:
            archivo = conn.makefile("r", encoding="utf-8")

            # HANDSHAKE RSA 
            primera = archivo.readline()
            if not primera:
                return

            handshake_msg = convertir_mensaje(primera.strip())
            if not handshake_msg or handshake_msg.get("type") != "key_exchange" or not validar_mensaje(handshake_msg):
                return
            
            try:
                client_pub_key = rsa.PublicKey.load_pkcs1(handshake_msg.get("key").encode("utf-8"))
            except:
                return

            # Responder con la publica del servidor
            server_pub_str = servidor_pub.save_pkcs1().decode("utf-8")
            hs_resp = json.dumps({"type": "key_exchange", "key": server_pub_str})
            conn.sendall(hs_resp.encode("utf-8") + b"\n")

            # LEER PRIMER MENSAJE (LOGIN / REGISTER) CIFRADO 
            segunda = archivo.readline()
            if not segunda:
                return
            
            desencriptado = desencriptar_rsa(segunda.strip(), servidor_priv)
            if not desencriptado:
                return

            msg = leerMensaje(desencriptado)
            if not msg or not validar_mensaje(msg):
                return

            # LOGIN (usuario existente) 
            if msg and msg.get("type") == "login":
                usuario_bd = cargar_usuarios()
                pedido = msg.get("from")
                pw_recibido = msg.get("text", "")

                if pedido not in usuario_bd:
                    enviar_anonimo(crearMensaje("login_fail", "SERVER", "Usuario no existe"))
                    log_error(f"LOGIN FAIL (usuario no existe): {pedido} desde {addr}")
                    return

                if not verificar_password(pw_recibido, usuario_bd[pedido]):
                    enviar_anonimo(crearMensaje("login_fail", "SERVER", "Contrasena incorrecta"))
                    log_error(f"LOGIN FAIL (contrasena incorrecta): {pedido} desde {addr}")
                    return

                with lock:
                    if pedido in usuarios:
                        enviar_anonimo(crearMensaje("login_fail", "SERVER", "Ya esta conectado"))
                        return
                    if len(usuarios) >= MAX_CLIENTS:
                        enviar_anonimo(crearMensaje("login_fail", "SERVER", "Servidor lleno"))
                        return
                    usuarios[pedido] = conn
                    claves_clientes_auth[pedido] = client_pub_key
                    nombreUser = pedido
                    enviar_anonimo(crearMensaje("login_ok", "SERVER", "Login correcto"))

                log_evento(f"LOGIN OK: {pedido} desde {addr}")
                print(f"[{fecha_hora()}] {pedido} se conecto desde {addr}")

            # REGISTRO (usuario nuevo) 
            elif msg and msg.get("type") == "register":
                pedido = msg.get("from")
                pw_texto = msg.get("text", "")

                if not pw_texto:
                    enviar_anonimo(crearMensaje("register_fail", "SERVER", "Contrasena vacia"))
                    return

                usuario_bd = cargar_usuarios()
                if pedido in usuario_bd:
                    enviar_anonimo(crearMensaje("register_fail", "SERVER", "Usuario ya existe"))
                    log_error(f"REGISTER FAIL (ya existe): {pedido} desde {addr}")
                    return

                usuario_bd[pedido] = hashear_password(pw_texto)
                guardar_usuarios(usuario_bd)

                with lock:
                    if len(usuarios) >= MAX_CLIENTS:
                        enviar_anonimo(crearMensaje("register_fail", "SERVER", "Servidor lleno"))
                        return
                    usuarios[pedido] = conn
                    claves_clientes_auth[pedido] = client_pub_key
                    nombreUser = pedido
                    enviar_anonimo(crearMensaje("register_ok", "SERVER", "Registro OK, bienvenido"))

                log_evento(f"REGISTER OK: {pedido} desde {addr}")
                print(f"[{fecha_hora()}] NUEVO USUARIO {pedido} desde {addr}")

            else:
                enviar_anonimo(crearMensaje("register_fail", "SERVER", "Primer mensaje invalido"))
                return

            # Avisar a todos que alguien entro
            mandarATodos_tcp(
                crearMensaje("system", "SERVER", f"{nombreUser} entro al chat")
            )

            # Leer mensajes del cliente
            for linea in archivo:
                dato_cifrado = linea.strip()
                if not dato_cifrado:
                    continue

                dato = desencriptar_rsa(dato_cifrado, servidor_priv)
                if not dato:
                    continue

                msg = leerMensaje(dato)
                if not msg or not validar_mensaje(msg):
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
                    # Enviar al dest
                    mandarPrivado_tcp(
                        dest, crearMensaje("private", msg.get("from"), texto, dest)
                    )
                    # Devolverse una copia cifrada a sí mismo
                    enviar_anonimo(crearMensaje("private", msg.get("from"), texto, dest))

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
                if nombreUser in claves_clientes_auth:
                    del claves_clientes_auth[nombreUser]

            print(f"[{fecha_hora()}] {nombreUser} se desconecto")
            log_evento(f"DESCONEXION: {nombreUser}")
            mandarATodos_tcp(
                crearMensaje("system", "SERVER", f"{nombreUser} salio del chat")
            )


# Inicia servidor TCP
def servidor_tcp():
    """Configura e inicializa el socket TCP maestro. Despacha un hilo 'atenderCliente_tcp' por conexion entrante."""
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
    """
    Configura e inicializa el socket UDP maestro en un único hilo. Actúa como un bucle 
    de eventos simple (recepcion y difusion en base de los datagramas recividos).
    """
    print("Servidor UDP iniciado en", HOST, PORT)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind((HOST, PORT))

    try:
        while True:
            data, addr = s.recvfrom(60000)
            txt = data.decode("utf-8").strip()
            msg = leerMensaje(txt)
            if not msg or not validar_mensaje(msg):
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
