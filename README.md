# Proyecto Chat Seguro (TCP/UDP) con Cifrado RSA

Este proyecto consiste en una aplicación de chat cliente-servidor desarrollada en Python que permite la comunicación entre múltiples usuarios utilizando los protocolos TCP y UDP. El sistema incorpora mecanismos de seguridad como cifrado RSA, autenticación de usuarios y almacenamiento seguro de contraseñas mediante bcrypt.

## Características

- **Soporte de Protocolos**: Permite utilizar TCP (confiable, cifrado y autenticado) o UDP (rápido y sin cifrado).
- **Cifrado RSA**: En modo TCP, los mensajes y credenciales se protegen mediante cifrado asimétrico RSA de 1024 bits.
- **Autenticación de Usuarios**: Sistema de registro e inicio de sesión para controlar el acceso al chat.
- **Contraseñas Seguras**: Las credenciales se almacenan utilizando hashing con bcrypt y salts.
- **Mensajería Pública**: Todos los usuarios conectados pueden comunicarse en una sala pública compartida.
- **Mensajería Privada**: Soporte para mensajes directos mediante comandos especiales.
- **Sanitización de Mensajes**: Validación y limpieza de entradas para prevenir inyección de caracteres maliciosos.
- **Registro de Eventos**: El servidor almacena eventos y errores en un archivo de logs (`chat.log`).
- **Pruebas Integradas**: El proyecto incluye pruebas unitarias para validar las funciones críticas del sistema.

---

## Requisitos

El proyecto requiere Python 3.x y las siguientes dependencias:

```bash
pip install rsa bcrypt
```

---

## Estructura del Proyecto

```text
├── server.py        # Servidor principal del sistema
├── client.py        # Cliente de línea de comandos
├── utils.py         # Funciones auxiliares compartidas
├── test_chat.py     # Pruebas unitarias
├── usuarios.json    # Base de datos local de usuarios (autogenerada)
└── chat.log         # Registro de eventos y errores
```

---

## Modo de Uso

### 1. Configurar el Protocolo

Tanto en `server.py` como en `client.py`, se debe configurar el protocolo deseado modificando la variable global:

```python
PROTOCOL = "TCP"   # o "UDP"
```

> **Importante:** El servidor y los clientes deben utilizar el mismo protocolo para poder comunicarse correctamente.

---

### 2. Iniciar el Servidor

Ejecuta el siguiente comando:

```bash
python server.py
```

El servidor generará automáticamente las claves RSA y comenzará a escuchar conexiones en el puerto `5000`.

---

### 3. Iniciar Clientes

Abre una terminal por cada cliente que desees conectar y ejecuta:

```bash
python client.py
```

En modo TCP, el sistema solicitará iniciar sesión o registrar un usuario.  
En modo UDP, únicamente se solicitará un nombre temporal para la sesión actual.

---

## Comandos Disponibles

Durante el chat, cualquier mensaje enviado será visible para todos los usuarios conectados.

También se encuentran disponibles los siguientes comandos especiales:

### Mensaje Privado

```bash
/priv <usuario> <mensaje>
```

Ejemplo:

```bash
/priv Roberto Hola, ¿qué tal?
```

Envía un mensaje directo únicamente al usuario especificado.

---

### Salir del Chat

```bash
/salir
```

Desconecta al usuario del servidor de manera segura.

---

## Seguridad Implementada

### Cifrado RSA

En modo TCP, el intercambio de llaves RSA se realiza automáticamente al establecer la conexión:

- El cliente cifra los mensajes utilizando la llave pública del servidor.
- El servidor responde utilizando la llave pública del cliente.

### Protección de Contraseñas

Las contraseñas nunca se almacenan en texto plano.  
El sistema utiliza `bcrypt` para generar hashes seguros con salts.

### Sanitización de Entradas

Todos los mensajes son procesados mediante funciones de validación para prevenir:

- Caracteres de control maliciosos
- Inyección de datos
- Entradas inválidas

---

## Testing

El proyecto incluye pruebas unitarias para validar funcionalidades críticas como:

- Integridad del cifrado RSA
- Verificación de hashes de contraseñas
- Validación de mensajes
- Manejo seguro de entradas

Para ejecutar las pruebas:

```bash
python -m unittest test_chat.py
```

---
