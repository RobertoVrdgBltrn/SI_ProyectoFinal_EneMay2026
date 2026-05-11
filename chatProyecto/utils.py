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
    """Obtiene y formatea la fecha y hora actual del sistema."""
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def actual_str():
    """Alias para obtener la fecha y hora actual, utilizado para estampas de tiempo."""
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
    """Registra un mensaje informativo en el archivo de log y en la consola."""
    logging.info(msg)


def log_error(msg):
    """Registra un mensaje de error en el archivo de log y en la consola."""
    logging.error(msg)


# Hasheo de contrasenas 
def hashear_password(password: str) -> str:
    """Genera un hash seguro utilizando bcrypt para almacenar la contraseña."""
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode("utf-8"), salt)
    return hashed.decode("utf-8")


def verificar_password(password: str, hashed: str) -> bool:
    """Compara una contraseña en texto plano con su hash almacenado usando bcrypt."""
    return bcrypt.checkpw(password.encode("utf-8"), hashed.encode("utf-8"))


# Base de datos de usuarios (archivo JSON) 
USUARIOS_FILE = "usuarios.json"


def cargar_usuarios() -> dict:
    """
    Lee el archivo de base de datos JSON y carga los usuarios registrados.
    Si el archivo no existe, devuelve un diccionario vacío.
    """
    if not os.path.exists(USUARIOS_FILE):
        return {}
    with open(USUARIOS_FILE, "r", encoding="utf-8") as f:
        return json.load(f)


def guardar_usuarios(usuarios: dict):
    """Guarda el diccionario de usuarios actualizados en el archivo JSON."""
    with open(USUARIOS_FILE, "w", encoding="utf-8") as f:
        json.dump(usuarios, f, indent=2)


# Sanitizacion y Validacion
def sanitizar_texto(texto: str) -> str:
    """Limpia el texto ingresado eliminando caracteres de control que puedan causar errores en JSON o terminal."""
    if not isinstance(texto, str):
        return ""
    texto_limpio = re.sub(r'[\x00-\x1f\x7f]', '', texto)
    return texto_limpio.strip()

def validar_mensaje(msg: dict) -> bool:
    """Comprueba que la estructura y longitud de los datos del mensaje sean correctas y seguras."""
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
    Empaqueta los datos en un diccionario y los convierte a formato JSON para su envío por la red.
    Se asegura de sanitizar el texto antes de empaquetarlo.
    """
    quien = sanitizar_texto(quien) if quien else quien
    texto = sanitizar_texto(texto) if texto else texto
    para = sanitizar_texto(para) if para else para
    
    msg = {"type": tipo, "from": quien, "to": para, "text": texto, "time": fecha_hora()}
    return json.dumps(msg)


def convertir_mensaje(cadena):
    """Parsea una cadena JSON recibida y la convierte a un diccionario de Python. Retorna None si falla."""
    try:
        return json.loads(cadena)
    except:
        return None


def leerMensaje(cadena):
    """Convierte una cadena JSON a un objeto Python (Alias usado en el servidor)."""
    return convertir_mensaje(cadena)


def crear_mensaje(msg_type, sender, text="", target=None):
    """Construye un mensaje en formato JSON listo para enviar (Alias usado en el cliente)."""
    return crearMensaje(msg_type, sender, text, target)


# Criptografia RSA 
def generar_claves_rsa():
    """Crea un nuevo par de claves RSA (pública y privada) de 1024 bits para encriptación."""
    return rsa.newkeys(1024)

def encriptar_rsa(mensaje_str: str, public_key: rsa.PublicKey) -> str:
    """Cifra un texto en bloques utilizando una llave pública RSA y lo codifica en formato Base64."""
    chunk_size = 117 # Para llave RSA de 1024 bits
    data = mensaje_str.encode("utf-8")
    encrypted_chunks = []
    for i in range(0, len(data), chunk_size):
        chunk = data[i:i+chunk_size]
        encrypted_chunks.append(rsa.encrypt(chunk, public_key))
    combined = b"".join(encrypted_chunks)
    return base64.b64encode(combined).decode("utf-8")

def desencriptar_rsa(mensaje_b64: str, private_key: rsa.PrivateKey) -> str:
    """Decodifica un mensaje en Base64 y lo descifra por bloques usando una llave privada RSA."""
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
