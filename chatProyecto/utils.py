#utils.py

import json
from datetime import datetime

#Devuelve la fecha y hora actual como texto
def fecha_hora():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def crearMensaje(tipo, quien, texto="", para=None):
    """
    Crea un mensaje JSON listo para enviar por red.
    tipo = tipo de mensaje (register, message, private, etc.)
    quien = usuario que manda el mensaje
    texto = contenido principal del mensaje
    para = destinatario si el mensaje es privado
    """
    msg = {
        "type": tipo,
        "from": quien,
        "to": para,
        "text": texto,
        "time": fecha_hora()
    }
    return json.dumps(msg)

#Convierte texto JSON a un objeto de Python
def convertir_mensaje(cadena):
    try:
        return json.loads(cadena)
    except:
        return None

#Devuelve la fecha y hora actual como texto
def actual_str():
    return fecha_hora()

#Atajo para crear mensajes usando la misma funcion
def crear_mensaje(msg_type, sender, text="", target=None):
    
    return crearMensaje(msg_type, sender, text, target)

#Funcion usada por server.py para mantener compatibilidad
def leerMensaje(cadena):
    return convertir_mensaje(cadena)