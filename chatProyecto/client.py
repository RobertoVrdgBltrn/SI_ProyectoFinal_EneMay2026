# client.py
# Cliente para chat por TCP o UDP
# Cambiar PROTOCOL para elegir el protocolo de comunicacion

import socket
import threading
import sys
from utils import crear_mensaje, convertir_mensaje, actual_str

# CONFIG
SERVER_HOST = "127.0.0.1"#IP del servidor
SERVER_PORT = 12345 #Puerto del servidor
PROTOCOL = "TCP"#Cambiar a "UDP" si se quiere usar UDP

#Hilo que recibe mensajes cuando usamos TCP
def recibir_tcp(conn):
    
    try:
        f = conn.makefile("r", encoding="utf-8")#Lectura linea por linea
        for linea in f:
            linea = linea.strip()
            if linea == "":
                continue
            msg = convertir_mensaje(linea)#Convierte JSON a objeto Python
            if msg:
                mostrar(msg)#Muestra el mensaje al usuario
    except Exception as e:
        print("conexion cerrada o error:", e)
    finally:
        try:
            conn.close()#Cierra conexion TCP
        except:
            pass

#Hilo que recibe datagramas cuando usamos UDP
def recibir_udp(sock):
    
    try:
        while True:
            datos, addr = sock.recvfrom(65535)#Recibe paquete UDP
            try:
                msg = convertir_mensaje(datos.decode("utf-8"))
                if msg:
                    mostrar(msg)
            except:
                pass
    except Exception as e:
        print("udp cerrado:", e)

#Imprime mensajes de forma ordenada
def mostrar(msg):
    
    tipo = msg.get("type")
    t = msg.get("time")
    de = msg.get("from")
    txt = msg.get("text")
    para = msg.get("to")

    if tipo == "system":
        print(f"[{t}] * {txt}")#Mensaje del servidor
    elif tipo == "message":
        print(f"[{t}] {de}: {txt}")#Mensaje publico
    elif tipo == "private":
        if para:
            print(f"[{t}] [PRIV] {de} -> {para}: {txt}")#Mensaje privado
        else:
            print(f"[{t}] [PRIV] {de}: {txt}")
    elif tipo == 'register_ok':
        print(f"[{t}] {txt}")#Registro aceptado
    elif tipo == 'register_fail':
        print(f"[{t}] ERROR: {txt}")#Registro rechazado
    else:
        print(f"[{t}] {de}: {txt}")#Otros mensajes

#Envia mensajes cuando se usa TCP
def enviar_mensajes_tcp(sock, username):
    
    try:
        while True:
            texto = input()#Lo que escribe el usuario

            if texto == "/salir":
                #Avisar al servidor que cerramos
                msg = crear_mensaje("disconnect", username, "salio del chat")
                try:
                    sock.sendall(msg.encode("utf-8") + b"\n")
                except:
                    pass

                print("saliendo...")
                try:
                    sock.close()#Cierra conexion TCP
                except:
                    pass
                break

            elif texto.startswith("/priv "):
                #Mensaje privado
                partes = texto.split(" ", 2)
                if len(partes) < 3:
                    print("Formato: /priv <usuario> <mensaje>")
                    continue
                dest = partes[1]
                contenido = partes[2]
                msg = crear_mensaje("private", username, contenido, dest)
                sock.sendall(msg.encode("utf-8") + b"\n")

            else:
                #Mensaje publico
                msg = crear_mensaje("message", username, texto)
                sock.sendall(msg.encode("utf-8") + b"\n")

    except:
        pass

#Envia mensajes cuando se usa UDP
def enviar_mensajes_udp(sock, username, server_addr):
    
    try:
        while True:
            linea = input()#Mensaje que se envia
            if linea == "":
                continue

            if linea.lower() == "/salir":
                #Avisar desconexion por UDP
                msg = crear_mensaje("disconnect", username, "salio del chat")
                try:
                    sock.sendto(msg.encode("utf-8"), server_addr)
                except:
                    pass
                print("saliendo...")
                break

            if linea.startswith("/priv "):
                #Mensaje privado UDP
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
                #Mensaje publico UDP
                msg = crear_mensaje("message", username, linea)
                sock.sendto(msg.encode("utf-8"), server_addr)
    except Exception as e:
        print("error udp:", e)

#Inicio del cliente TCP
def iniciar_cliente_tcp():
    
    usuario = input("Nombre usuario: ").strip()
    if usuario == "":
        print("No pusiste nombre.")
        return

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        sock.connect((SERVER_HOST, SERVER_PORT))#Conexion al servidor
    except Exception as e:
        print("No se pudo conectar:", e)
        return

    #Registro del usuario
    sock.sendall(crear_mensaje("register", usuario).encode("utf-8") + b"\n")

    f = sock.makefile("r", encoding="utf-8")
    linea = f.readline()
    if not linea:
        print("No respondio el servidor.")
        sock.close()
        return

    r = convertir_mensaje(linea.strip())
    if r.get("type") == "register_fail":
        print("Error:", r.get("text"))
        sock.close()
        return

    print("Listo, ya puedes escribir.")

    #Hilo que recibe mensajes
    threading.Thread(
        target=recibir_tcp,
        args=(sock,),
        daemon=True
    ).start()

    #Hilo que envia mensajes
    threading.Thread(
        target=enviar_mensajes_tcp,
        args=(sock, usuario),
        daemon=True
    ).start()

    #Mantener el cliente activo
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

    #Enviar registro por UDP
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

    #Hilo que recibe mensajes UDP
    threading.Thread(
        target=recibir_udp,
        args=(sock,),
        daemon=True
    ).start()

    #Enviar mensajes desde el hilo principal
    enviar_mensajes_udp(sock, usuario, server_addr)

    sock.close()

if __name__ == "__main__":
    print("Cliente Chat. Protocolo:", PROTOCOL)
    if PROTOCOL == "TCP":
        iniciar_cliente_tcp()
    else:
        iniciar_cliente_udp()