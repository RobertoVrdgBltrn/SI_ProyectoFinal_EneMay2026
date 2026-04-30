import json
import os
import logging
import logging.handlers
import bcrypt
import rsa
import base64
import re
from datetime import datetime


# Fecha y hora 
def fecha_hora():
    """Devuelve la fecha y hora actual como texto."""
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def actual_str():
    return fecha_hora()


# Logging basico 
LOG_FILE = "chat.log"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.handlers.RotatingFileHandler(LOG_FILE, maxBytes=1024*1024, backupCount=5, encoding="utf-8"),
        logging.StreamHandler()
    ],
)


def log_evento(msg):
    """Escribe una linea informativa en el log."""
    logging.info(msg)


def log_error(msg):
    """Escribe una linea de error en el log."""
    logging.error(msg)


# Hasheo de contrasenas 
def hashear_password(password: str) -> str:
    """Recibe texto plano, devuelve el hash bcrypt como string."""
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode("utf-8"), salt)
    return hashed.decode("utf-8")


def verificar_password(password: str, hashed: str) -> bool:
    """Compara texto plano con el hash almacenado. Devuelve True si coinciden."""
    return bcrypt.checkpw(password.encode("utf-8"), hashed.encode("utf-8"))


# Base de datos de usuarios (archivo JSON) 
USUARIOS_FILE = "usuarios.json"


def cargar_usuarios() -> dict:
    """Carga el diccionario {usuario: hash} desde disco.
    Si el archivo no existe, devuelve un diccionario vacio."""
    if not os.path.exists(USUARIOS_FILE):
        return {}
    with open(USUARIOS_FILE, "r", encoding="utf-8") as f:
        return json.load(f)


def guardar_usuarios(usuarios: dict):
    """Guarda el diccionario {usuario: hash} en disco."""
    with open(USUARIOS_FILE, "w", encoding="utf-8") as f:
        json.dump(usuarios, f, indent=2)


# Sanitizacion y Validacion
def sanitizar_texto(texto: str) -> str:
    """Remueve caracteres de control que podrian afectar la terminal o JSON."""
    if not isinstance(texto, str):
        return ""
    texto_limpio = re.sub(r'[\x00-\x1f\x7f]', '', texto)
    return texto_limpio.strip()

def validar_mensaje(msg: dict) -> bool:
    """Valida los campos y longitudes del diccionario para evitar datos maliciosos."""
    if not isinstance(msg, dict):
        return False
        
    de = msg.get("from")
    if de is not None and (not isinstance(de, str) or len(de) > 30):
        return False
        
    para = msg.get("to")
    if para is not None and (not isinstance(para, str) or len(para) > 30):
        return False
        
    texto = msg.get("text")
    if texto is not None and (not isinstance(texto, str) or len(texto) > 2000):
        return False
        
    key = msg.get("key")
    if key is not None and (not isinstance(key, str) or len(key) > 5000):
        return False

    return True

# Mensajes JSON 
def crearMensaje(tipo, quien, texto="", para=None):
    """
    Crea un mensaje JSON listo para enviar por red.
    tipo  = tipo de mensaje (register, login, message, private, etc.)
    quien = usuario que manda el mensaje
    texto = contenido principal del mensaje
    para  = destinatario si el mensaje es privado
    """
    quien = sanitizar_texto(quien) if quien else quien
    texto = sanitizar_texto(texto) if texto else texto
    para = sanitizar_texto(para) if para else para
    
    msg = {"type": tipo, "from": quien, "to": para, "text": texto, "time": fecha_hora()}
    return json.dumps(msg)


def convertir_mensaje(cadena):
    """Convierte texto JSON a un objeto de Python. Devuelve None si falla."""
    try:
        return json.loads(cadena)
    except:
        return None


def leerMensaje(cadena):
    """Alias de convertir_mensaje, usado por server.py."""
    return convertir_mensaje(cadena)


def crear_mensaje(msg_type, sender, text="", target=None):
    """Alias de crearMensaje, usado por client.py."""
    return crearMensaje(msg_type, sender, text, target)


# Criptografia RSA 
def generar_claves_rsa():
    """Genera un par de llaves (Pública, Privada) de 1024 bits."""
    return rsa.newkeys(1024)

def encriptar_rsa(mensaje_str: str, public_key: rsa.PublicKey) -> str:
    """Encripta un string utilizando la llave publica en bloques (por tamano de llave) y devuelve Base64."""
    chunk_size = 117 # Para llave RSA de 1024 bits
    data = mensaje_str.encode("utf-8")
    encrypted_chunks = []
    for i in range(0, len(data), chunk_size):
        chunk = data[i:i+chunk_size]
        encrypted_chunks.append(rsa.encrypt(chunk, public_key))
    combined = b"".join(encrypted_chunks)
    return base64.b64encode(combined).decode("utf-8")

def desencriptar_rsa(mensaje_b64: str, private_key: rsa.PrivateKey) -> str:
    """Desencripta un mensaje Base64 utilizando la llave privada."""
    try:
        data = base64.b64decode(mensaje_b64.encode("utf-8"))
    except:
        return "" # b64 invalido
        
    chunk_size = 128 # Bloque encriptado con RSA-1024 siempre es 128 bytes
    decrypted_chunks = []
    for i in range(0, len(data), chunk_size):
        chunk = data[i:i+chunk_size]
        try:
            decrypted_chunks.append(rsa.decrypt(chunk, private_key))
        except rsa.pkcs1.DecryptionError:
            return "" # Fallo al desencriptar
    return b"".join(decrypted_chunks).decode("utf-8")
