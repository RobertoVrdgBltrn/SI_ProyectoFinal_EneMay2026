# Proyecto Chat Seguro (TCP/UDP) con Cifrado RSA

Este es un sistema de chat asimétrico implementado en Python puro que permite enviar mensajes públicos y mensajes privados entre clientes de forma segura.

## Características

- **Soporte Protocolos**: Puedes elegir usar TCP (Confiable, Cifrado, Autenticado) o UDP (Rápido, Local, no Autenticado).
- **Cifrado Real (RSA)**: Bajo TCP, todos los paquetes están encriptados mediante pares de llaves (Pública y Privada) de 1024-bits regeneradas dinámicamente cada sesión. 
- **Salas de Chat Privadas**: Uso del comando `/priv <nombre> <mensaje>` para saltarse la sala principal.
- **Validación Segura**: Los mensajes cuentan con restricciones estrictas de longitud, caracteres no imprimibles y prevención de inyección en consola.
- **Rotación de Logs**: El servidor almacena los registros transparentes (`chat.log`) evitando fugas de memoria con un manejador rotativo (1 MB por archivo).
- **Inicio Sensato**: Tolerancia a equivocaciones durante la pantalla de "Inicio de sesión" (vuelve a pedir los datos en lugar de crashear).

## Requisitos

El proyecto utiliza dependencias mínimas requeridas. Instala los módulos faltantes:
```bash
pip install rsa bcrypt
```

## Modo de Uso

### 1. Iniciar el Servidor
```bash
python server.py
```
> **Nota**: El servidor siempre debe estar en funcionamiento antes de conectar a cualquier cliente. Puedes intercambiar el protocolo TCP a UDP modificando la variable `PROTOCOL` al tope del archivo `server.py`.

### 2. Iniciar Clientes
Abre una terminal por cada cliente que quieras conectar:
```bash
python client.py
```
Si el protocolo del cliente se empareja con la configuración del servidor, verás la opción de iniciar sesión o registrar nombre y contraseña.

### 3. Comandos de Usuario en Chat
Durante el chat, simplemente escribe lo que quieras enviar a todos los clientes (Broadcast) y presiona **Enter**. 
Alternativamente usa los comandos especiales:
* `/priv <usuario> <lista de palabras secretas>` -> Envía un mensaje directo cifrado solo al usuario destinado.
* `/salir` -> Informa limpiamente de tu desconexión y detiene tu cliente TCP instántaneamente.

## Testing Formal Integrado
Este repositorio cuenta con una suite de pruebas formales incorporada. Las pruebas validan que el sistema de cifrado RSA no altere mensajes, los hashes de credenciales coincidan, y los textos largos reboten en la validación antes de crashear la red.

Para correr los tests en tu computadora:
```bash
python -m unittest test_chat.py
```
