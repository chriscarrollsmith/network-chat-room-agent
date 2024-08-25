import socket
import time
import threading
import logging
import tempfile
import shutil
import os
import json
from typing import Any, Literal, Callable, Optional
from dotenv import load_dotenv
from agent.api_caller import call_api
from utils.encryption import send, receive
from utils.file_utilities import get_file_md5, format_file_size
from utils.logger import configure_logger

# Get the Agent name from an environment variable with default "Clippy"
load_dotenv(override=True)
AGENT_USERNAME = os.environ.get("AGENT_USERNAME", "Clippy")
AGENT_PASSWORD = os.environ.get("AGENT_PASSWORD", "password")
ACCEPT_FILES = os.environ.get("ACCEPT_FILES", "false").lower() == "true"
LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO").upper()

# Configure the logger for streaming logs from multiple threads
configure_logger(LOG_LEVEL)

# Get a logger for this module
logger = logging.getLogger(__name__)


class Agent:
    """Automated agent that can be used to interact with the server for testing purposes"""

    def __init__(self, host: str, port: int):
        self.host = host
        self.port = port
        self.socket = None
        self.connected = False
        self.receive_thread = None
        self.event_handlers: dict[str, list[Callable]] = {
            "register_result": [self.handle_register_result],
            "login_result": [self.handle_login_result],
            "private_message": [self.handle_receive_message],
            "broadcast_message": [self.handle_receive_message],
            "file_request": [self.handle_file_request],
            "file_response": [self.handle_file_response],
            "peer_joined": [self.handle_peer_joined],
            "peer_left": [self.handle_peer_left],
        }
        self.temp_dir = tempfile.mkdtemp()

        # Authentication state
        self.username = AGENT_USERNAME
        self.password = AGENT_PASSWORD
        self.registered = False
        self.authed = False

        # Chat session state
        self.current_session: str = ""
        self.chat_log: list[tuple[str, str]] = []

        # File transfer state
        self._filename: str = ""
        self._filename_short: str = ""
        self._file_transfer_pending: bool = False

    # --- Connection management ---

    def _validate_connection_state(self, should_be_connected: bool = True) -> None:
        state: str = "connected" if should_be_connected else "disconnected"
        opposite_state: str = "disconnected" if should_be_connected else "connected"

        if should_be_connected != self.connected:
            raise ConnectionError(f"Expected to be {state} but was {opposite_state}.")

        if should_be_connected:
            if not self.socket:
                raise ConnectionError(
                    f"Expected socket to exist but it was {self.socket}."
                )
            if not self.receive_thread:
                raise ConnectionError(
                    f"Expected receive thread to exist but it was {self.receive_thread}."
                )

            # Wait for the thread to become alive with a 1-second timeout
            start_time: float = time.time()
            timeout: float = 5.0
            logger.debug(
                f"Waiting for receive thread to become alive (timeout: {timeout}s)..."
            )
            while not self.receive_thread.is_alive():
                if time.time() - start_time > timeout:
                    raise ConnectionError(
                        f"Receive thread failed to start within {timeout}-second timeout."
                    )
                time.sleep(0.01)
            logger.debug(f"Receive thread is alive.")
        else:
            if self.socket:
                raise ConnectionError(
                    f"Expected socket to be None but it was {self.socket}."
                )
            if self.receive_thread and self.receive_thread.is_alive():
                raise ConnectionError(
                    f"Expected receive thread to not be alive but it was."
                )

    def _connect(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.connect((self.host, self.port))
        self.connected = True
        self.receive_thread = threading.Thread(target=self._receive_loop)
        self.receive_thread.start()

        self._validate_connection_state(should_be_connected=True)

    # In the close method:
    def _close(self) -> None:
        self.connected = False
        if self.socket:
            self.socket.close()
        if self.receive_thread:
            self.receive_thread.join(
                timeout=5
            )  # Add a timeout to prevent indefinite waiting
            if self.receive_thread.is_alive():
                raise ConnectionError("Failed to stop receive thread within 5 seconds.")
        self.socket = None
        self.receive_thread = None

        # Clean up the temporary directory
        shutil.rmtree(self.temp_dir)
        logger.debug(f"Removed temporary directory: {self.temp_dir}")

        self._validate_connection_state(should_be_connected=False)

    # --- State management ---

    def append_message(self, sender: str, receiver: str, time: str, msg: str) -> None:
        sender = "You" if sender == self.username else sender
        receiver = "You" if receiver == self.username else receiver
        header = f"{sender} (To {receiver}) - {time}"
        self.chat_log.append((header, msg))

    def _reset_file_state(self) -> None:
        self._filename = ""
        self._filename_short = ""
        self._file_transfer_pending = False

    # --- Outgoing server communication ---

    def _send(self, data_dict: dict[str, Any]) -> None:
        if not self.connected or self.socket is None:
            raise ConnectionError("Lost connection to server")

        send(self.socket, data_dict)

    def authenticate(self, type: Literal["register", "login"]):
        username: str = self.username
        password: str = self.password

        if not self.connected or self.socket is None:
            raise ConnectionError("Lost connection to the server.")

        self._send({"command": type, "username": username, "password": password})

    def send_message(self, peer: str, message: str) -> None:
        try:
            self._send({"command": "chat", "peer": peer, "message": message})
            self.append_message(
                self.username, peer, time.strftime("%Y-%m-%d %H:%M:%S"), message
            )
            logger.info(f"Replied to {peer}: {message}")
        except Exception as e:
            logger.error(f"Error sending message to {peer}: {str(e)}")

    def send_file_request(self) -> None:
        filepath: str = os.path.join(self.temp_dir, "test.txt")

        self._filename = filepath
        self._filename_short = os.path.basename(filepath)
        size: int = os.path.getsize(filepath)
        size_str: str = format_file_size(size)
        md5_checksum: str = get_file_md5(filepath)

        self._send(
            {
                "command": "file_request",
                "peer": self.current_session,
                "filename": self._filename_short,
                "size": size_str,
                "md5": md5_checksum,
            }
        )

        self._file_transfer_pending = True

    def send_file_data(self, data: dict) -> tuple[int, float]:
        try:
            total_bytes: int = 0
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
                client.connect((data["ip"], 1031))
                start_time: float = time.time()

                with open(self._filename, "rb") as f:
                    while True:
                        file_data = f.read(1024)
                        if not file_data:
                            break
                        total_bytes += len(file_data)
                        client.send(file_data)

            end_time: float = time.time()
            transfer_time: float = end_time - start_time
            return total_bytes, transfer_time
        finally:
            self._reset_file_state()

    # --- Incoming server communication ---

    def _receive(self) -> dict[str, Any] | None:
        if not self.connected or self.socket is None:
            raise ConnectionError("Not connected to server")
        try:
            data: dict[str, Any] = receive(self.socket)
            logger.debug(f"Decrypted data: {data}")
            return data
        except json.JSONDecodeError:
            logger.error("Received invalid JSON data")
            return None
        except ConnectionError as e:
            logger.error(f"Connection error: {e}")
            self.close_connection()
            return None
        except Exception as e:
            logger.error(f"Receive error: {str(e)}")
            self.close_connection()
            return None

    def _receive_loop(self) -> None:
        while self.connected:
            data: dict | None = self._receive()
            if data:
                event: str = data.get("type", "unknown")
                handlers: list[Callable] = self.event_handlers.get(event, [])
                if not handlers:
                    logger.debug(f"Ignored unhandled event: {data}")
                else:
                    for handler in handlers:
                        handler(data)
            else:
                logger.warning(f"Empty message received from server.")

    def _receive_file_data(self, filename: str) -> tuple[int, float]:
        total_bytes: int = 0
        file_path = os.path.join(self.temp_dir, filename)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
            server.bind(("0.0.0.0", 1031))
            server.listen(1)
            client_socket, _ = server.accept()
            start_time: float = time.time()

            with open(file_path, "wb") as f:
                while True:
                    file_data = client_socket.recv(1024)
                    if not file_data:
                        break
                    total_bytes += len(file_data)
                    f.write(file_data)

        end_time: float = time.time()
        transfer_time: float = end_time - start_time
        return total_bytes, transfer_time

    # --- Event handlers ---

    def handle_register_result(self, data: dict) -> None:
        if data.get("response") == "ok":
            logger.info(f"Registration successful for {data.get('username')}")
        elif data.get("response") == "fail":
            if data.get("reason") == "Username already exists!":
                logger.info(f"User {data.get('username')} already registered")
            else:
                raise Exception(f"Registration failed: {data.get('reason')}")
        else:
            raise Exception("Invalid response from server.")

        self.registered = True

    def handle_login_result(self, data: dict) -> None:
        if data.get("response") == "ok":
            logger.info(f"Login successful for {data.get('username')}")
        elif data.get("response") == "fail":
            raise Exception(f"Login failed: {data.get('reason')}")
        else:
            raise Exception("Invalid response from server.")

        self.authed = True

    def handle_receive_message(self, data: dict) -> None:
        """
        Handle incoming chat messages.

        Args:
            data (dict): A dictionary containing message data.
        """
        # Extract message details from the data
        sender: str = data.get("peer", "Unknown")
        message: str = data.get("message", "")
        timestamp: str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())

        # Append the message to the chat log
        self.append_message(sender, self.username, timestamp, message)

        # Log the received message
        logger.info(f"Message received from {sender} at {timestamp}: {message}")

        # Reply to the incoming message
        reply: Optional[str] = call_api(self.chat_log)
        if reply:
            self.send_message(sender, reply)

    def handle_file_request(self, data: dict) -> None:
        peer = data.get("peer", "Unknown")
        filename = data.get("filename", "Unknown")
        size = data.get("size", "Unknown")
        logger.info(f"File request received from {peer}: {filename} ({size} bytes)")

        if ACCEPT_FILES:
            try:
                total_bytes, transfer_time = self._receive_file_data(filename)
                logger.info(
                    f"File received: {total_bytes} bytes from {peer} in {transfer_time:.2f} seconds"
                )
            except Exception as e:
                logger.error(f"Error receiving file: {str(e)}")
        else:
            self._send({"command": "file_response", "peer": peer, "response": "deny"})
            logger.info(f"Denied file transfer from {peer}")

            self.send_message(
                peer,
                f"Sorry, {peer}; you sent me a file transfer request, but I can't accept files.",
            )

    def handle_file_response(self, data: dict) -> None:
        response = data.get("response", "")
        peer = data.get("peer", "")

        if response == "accept":
            logger.info(f"File transfer accepted by {peer}")
            try:
                bytes_sent, transfer_time = self.send_file_data(data)
                logger.info(
                    f"File sent: {bytes_sent} bytes to {peer} in {transfer_time:.2f} seconds"
                )
            except:
                logger.error(f"Error sending file to {peer}")
        elif response == "deny":
            try:
                logger.info("File transfer denied by recipient")
                self._reset_file_state()
            except:
                logger.error(f"Error sending file to {peer}")
        else:
            logger.error(f"Invalid file response from {peer}: {response}")

    def handle_peer_joined(self, data: dict) -> None:
        """
        Handle the event when a new peer joins the chat.

        Args:
            data (dict): A dictionary containing the peer information.
        """
        peer = data.get("peer")
        if peer:
            logger.info(f"{peer} has joined the chat.")

    def handle_peer_left(self, data: dict) -> None:
        """
        Handle the event when a peer leaves the chat.

        Args:
            data (dict): A dictionary containing the peer information.
        """
        peer = data.get("peer")
        if peer:
            logger.info(f"{peer} has left the chat.")

            # If the current chat was with the peer who left, switch to global chat
            if self.current_session == peer:
                self.current_session = ""
                logger.info("Switched to global chat")


if __name__ == "__main__":
    import os
    from dotenv import load_dotenv

    load_dotenv()

    server_ip: str = os.environ.get("SERVER_IP", "127.0.0.1")
    server_port: int = int(os.environ.get("SERVER_PORT", 8888))

    try:
        app = Agent(server_ip, server_port)
        app._connect()

        app.authenticate("register")
        while not app.registered:
            time.sleep(1)

        app.authenticate("login")
        while not app.authed:
            time.sleep(1)

        app.send_message("", "Hello!")

        while True:
            time.sleep(1)

    finally:
        app._close()
        print("Agent closed")
