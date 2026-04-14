# server.py
# Servidor para chat por TCP o UDP
# Cambiar PROTOCOL = "TCP" o "UDP" segun lo que se quiere probar

import socket
import threading
import sys
from utils import crearMensaje, leerMensaje, fecha_hora

# Configuracion basica del servidor
HOST = "127.0.0.1"#IP del servidor
PORT = 12345 #Puerto donde escucha
MAX_CLIENTS = 6 #Maximo de usuarios permitidos
PROTOCOL = "TCP"#Cambiar a "UDP" si se quiere usar UDP

lock = threading.Lock() #Para evitar conflictos al modificar usuarios

#Lista de usuarios conectados
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
                #Si falla, se cierra y se elimina
                try:
                    conn.close()
                except:
                    pass
                del usuarios[nombre]

def mandarPrivado_tcp(user, msg_json):
    #Envia mensaje privado solo a un usuario
    with lock:
        dest = usuarios.get(user)
        if dest:
            try:
                dest.sendall(msg_json.encode("utf-8") + b"\n")
            except:
                #Si falla su socket, se elimina
                try:
                    dest.close()
                except:
                    pass
                del usuarios[user]

#Atiende a un cliente TCP individual en un hilo
def atenderCliente_tcp(conn, addr):
    
    nombreUser = None

    try:
        with conn:
            archivo = conn.makefile("r", encoding="utf-8")#Leer por lineas

            #Leer primer mensaje (registro)
            primera = archivo.readline()
            if not primera:
                return

            msg = leerMensaje(primera.strip())
            if not msg or msg.get("type") != "register":
                conn.sendall(crearMensaje("register_fail","SERVER","Error en registro").encode("utf-8") + b"\n")
                return

            pedido = msg.get("from")

            #Validar el nombre del usuario
            with lock:
                if pedido in usuarios:
                    conn.sendall(crearMensaje("register_fail","SERVER","usuario ya existe").encode("utf-8") + b"\n")
                    return
                if len(usuarios) >= MAX_CLIENTS:
                    conn.sendall(crearMensaje("register_fail","SERVER","Servidor lleno").encode("utf-8") + b"\n")
                    return

                usuarios[pedido] = conn
                nombreUser = pedido
                conn.sendall(crearMensaje("register_ok","SERVER","Registro OK").encode("utf-8") + b"\n")

                print(f"[{fecha_hora()}] {pedido} se conecto desde {addr}")

            #Avisar a todos que alguien entro
            mandarATodos_tcp(crearMensaje("system","SERVER", f"{pedido} entro al chat"))

            #Leer mensajes del cliente
            for linea in archivo:
                dato = linea.strip()
                if not dato:
                    continue

                msg = leerMensaje(dato)
                if not msg:
                    continue

                tipo = msg.get("type")

                if tipo == "message":
                    #Mensaje publico
                    texto = msg.get("text")
                    print(f"[{fecha_hora()}] PUBLICO {msg.get('from')}: {texto}")
                    mandarATodos_tcp(crearMensaje("message", msg.get("from"), texto))

                elif tipo == "private":
                    #Mensaje privado
                    dest = msg.get("to")
                    texto = msg.get("text")
                    print(f"[{fecha_hora()}] PRIVADO {msg.get('from')} -> {dest}: {texto}")
                    mandarPrivado_tcp(dest, crearMensaje("private", msg.get("from"), texto, dest))
                    conn.sendall(crearMensaje("private", msg.get("from"), texto, dest).encode("utf-8") + b"\n")

                elif tipo == "disconnect":
                    #Usuario pidio desconectarse
                    break

    except Exception as e:
        print("Error en cliente:", e)

    finally:
        #Quitar usuario cuando se desconecta
        if nombreUser:
            with lock:
                if nombreUser in usuarios:
                    try:
                        usuarios[nombreUser].close()
                    except:
                        pass
                    del usuarios[nombreUser]

            print(f"[{fecha_hora()}] {nombreUser} se desconecto")
            mandarATodos_tcp(crearMensaje("system","SERVER", f"{nombreUser} salio del chat"))

#Inicia servidor TCP
def servidor_tcp():
    
    print("Servidor TCP iniciado en", HOST, PORT)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((HOST, PORT))
    s.listen()

    try:
        while True:
            conn, addr = s.accept()#Aceptar nuevo cliente
            hilo = threading.Thread(target=atenderCliente_tcp, args=(conn, addr), daemon=True)
            hilo.start()
    except KeyboardInterrupt:
        print("Servidor detenido")
    finally:
        s.close()


#Inicia servidor UDP
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
                #Registro de usuario por UDP
                nombre = msg.get("from")
                with lock:
                    if nombre in usuarios:
                        s.sendto(crearMensaje("register_fail","SERVER","Usuario repetido").encode("utf-8"), addr)
                        continue
                    if len(usuarios) >= MAX_CLIENTS:
                        s.sendto(crearMensaje("register_fail","SERVER","Servidor lleno").encode("utf-8"), addr)
                        continue
                    
                    usuarios[nombre] = addr
                    s.sendto(crearMensaje("register_ok","SERVER","ok").encode("utf-8"), addr)
                    print(f"[{fecha_hora()}] {nombre} registrado {addr}")

                    #Avisar a todos
                    for u, a in usuarios.items():
                        if u != nombre:
                            s.sendto(crearMensaje("system","SERVER", f"{nombre} entro").encode("utf-8"), a)
                continue

            if tipo == "message":
                #Enviar mensaje publico por UDP
                de = msg.get("from")
                texto = msg.get("text")
                print(f"[{fecha_hora()}] PUBLICO {de}: {texto}")
                with lock:
                    for u, a in usuarios.items():
                        s.sendto(crearMensaje("message", de, texto).encode("utf-8"), a)
                continue

            if tipo == "private":
                #Mensaje privado UDP
                de = msg.get("from")
                para = msg.get("to")
                texto = msg.get("text")
                print(f"[{fecha_hora()}] PRIVADO {de} -> {para}: {texto}")
                with lock:
                    dest = usuarios.get(para)
                    if dest:
                        s.sendto(crearMensaje("private", de, texto, para).encode("utf-8"), dest)
                    #Copia para el emisor
                    yo = usuarios.get(de)
                    if yo:
                        s.sendto(crearMensaje("private", de, texto, para).encode("utf-8"), yo)
                continue

            if tipo == "disconnect":
                #Desconexion UDP
                de = msg.get("from")
                print(f"[{fecha_hora()}] {de} se desconectó (UDP)")
                with lock:
                    if de in usuarios:
                        del usuarios[de]
                    #Avisar a todos
                    for u, a in usuarios.items():
                        s.sendto(crearMensaje("system", "SERVER", f"{de} salio del chat").encode("utf-8"), a)
                continue

    except KeyboardInterrupt:
        print("Servidor UDP detenido")
    finally:
        s.close()


#MAIN

if __name__ == "__main__":
    print("Servidor de chat. Protocolo =", PROTOCOL)

    if PROTOCOL == "TCP":
        servidor_tcp()
    else:
        servidor_udp()