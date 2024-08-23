import base64
import os
import struct
import json
import socket
import logging
from typing import Tuple, Any, Optional

logger = logging.getLogger(__name__)


def generate_key() -> bytes:
    """Generate a random 32-byte key for encryption."""
    return os.urandom(32)


def encrypt(data: bytes, key: bytes) -> Tuple[bytes, bytes]:
    """
    Encrypt data using XOR cipher with provided key and a random 16-byte Initialization Vector (IV).

    Args:
        data: The data to be encrypted.
        key: The encryption key.

    Returns:
        A tuple containing the base64-encoded encrypted data (including IV) and the IV.
    """
    # Generate a random 16-byte initialization vector (IV)
    iv = os.urandom(16)
    encrypted = bytearray()
    for i in range(len(data)):
        # XOR each byte of data with corresponding bytes from key and IV
        encrypted.append(data[i] ^ key[i % len(key)] ^ iv[i % len(iv)])
    # Return base64 encoded encrypted data and IV
    return base64.b64encode(bytes(encrypted)), iv


def decrypt(data: bytes, key: bytes, iv: bytes) -> bytes:
    """
    Decrypt the given data using XOR cipher with the provided key and IV.

    Args:
        data: The base64-encoded encrypted data (including IV).
        key: The decryption key.
        iv: The initialization vector used during encryption.

    Returns:
        The decrypted data as bytes.
    """
    # Base64 decode the input
    decoded = base64.b64decode(data)
    decrypted = bytearray()
    for i in range(len(decoded)):
        # XOR each byte of encoded data with corresponding bytes from key and IV
        decrypted.append(decoded[i] ^ key[i % len(key)] ^ iv[i % len(iv)])
    return bytes(decrypted)


def pack(data: bytes) -> bytes:
    """
    Pack data with a length prefix for sending.

    Args:
        data: The data to be packed.

    Returns:
        Packed data with length prefix.
    """
    packed_data = struct.pack(">H", len(data)) + data
    logger.debug(f"Packed data: {packed_data!r}")
    return packed_data


def send(socket: socket.socket, data_dict: dict[str, Any]) -> None:
    """
    Encrypt and send data to a socket.

    Args:
        socket: The socket to send data through.
        data_dict: The dictionary containing data to be sent.
    """
    # Generate a random 32-byte binary encryption key
    key: bytes = generate_key()

    # Serialize the dictionary to a JSON string and encode it as bytes
    json_data: bytes = json.dumps(data_dict).encode("utf-8")

    # Encrypt the JSON data using the key
    encrypt_result: Tuple[bytes, bytes] = encrypt(json_data, key)

    # Concatenate the key, IV, and encrypted data
    data_to_send = key + encrypt_result[1] + encrypt_result[0]

    # Pack the data to send
    packed_data = pack(data_to_send)

    logger.debug(f"Sending data: {packed_data!r}")
    # Use sendall to ensure all data is sent
    socket.sendall(packed_data)


def receive(socket: socket.socket, max_buff_size: int = 1024) -> dict[str, Any]:
    """
    Receive and decrypt data from a socket.

    Args:
        socket: The socket to receive data from.
        max_buff_size: Maximum buffer size for receiving data chunks.

    Returns:
        Decrypted and parsed data as a Python object.
    """
    data: bytes = b""

    # Receive the length of the incoming data (waits indefinitely until data is received)
    socket.settimeout(None)
    length_prefix: bytes = socket.recv(2)

    # Raise an error if bytes object is empty, as this means socket disconnected
    if not length_prefix:
        raise ConnectionError("Connection closed by remote host")

    # Unpack the length prefix to get the total length of the message
    surplus: int = struct.unpack(">H", length_prefix)[0]

    # Receive data in chunks until we have the full message
    socket.settimeout(5)
    while surplus:
        receive_data: bytes = socket.recv(
            max_buff_size if surplus > max_buff_size else surplus
        )
        if not receive_data:
            raise ConnectionError("Connection closed by remote host")
        data += receive_data
        surplus -= len(receive_data)

    # Extract key, IV, and encrypted data
    logger.debug(f"Received data: {data!r}")
    key: bytes = data[:32]
    iv: bytes = data[32:48]
    encrypted_data: bytes = data[48:]

    # Decrypt and parse the data
    decrypted_data: bytes = decrypt(encrypted_data, key, iv)
    return json.loads(decrypted_data)
