# Server implementation
import hashlib
import secrets
import socket
import time
from rsa import RSA

# nonce generator is  = secrets.token_urlsafe()


class Server:
    # Constructor for server object
    def __init__(
        self,
        header: int,
        port: int,
        format: str,
        disconnect_message: str,
        rsa: RSA,
        id=secrets.token_hex(16),
    ):
        # Length of msg in bytes
        self.header = header
        # Port for server and client to communicate on
        self.port = port
        # Format of msg
        self.format = format
        # Msg to disconnect from channel
        self.disconnect_message = disconnect_message
        # Server IP
        self.server_address = socket.gethostbyname(socket.gethostname())
        # Socket object
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # RSA object
        self.rsa = rsa
        # Server ID
        self.id = id
        # Bind server to chosen address
        address = (self.server_address, self.port)
        self.server.bind(address)

    # Open server - set max connections by 5 by default
    def open(self, max_connections=5):
        # Listen for connections - max 5 for queueing
        self.server.listen(max_connections)
        print(f"[LISTENING] Server is listening on {self.server_address}")

        while True:
            # Accept connections
            client_socket, address = self.server.accept()

            # Receive client_hello
            client_setup_request = client_socket.recv(4096).decode(self.format)

            # Print client_hello
            print(f"Client: {client_setup_request}")

            # Send server_hello to client
            client_socket.send("Server_hello, RSA public key is ".encode(self.format))
            client_socket.send(str(self.rsa.public_key).encode(self.format))
            print(self.rsa.public_key)

            # Receive client ID and generate session ID
            clientID = client_socket.recv(4096).decode(self.format)
            print(f"Client: client_hello - {clientID}")
            sessionID = secrets.token_hex(16)

            # The client ID is going to be in hex, now is the time to create the RSA signature using the client ID. Let m = (ServerID, seshID)
            # s = m^d mod n sent by server
            # Server sends (m, s) to client, verifies s^e mod n = m, If true then server is authenticated
            msg = (clientID, self.id, sessionID)
            hashed_msg = hashlib.sha256(str(msg).encode()).hexdigest()
            hashed_intmsg = int("0x" + hashed_msg, 16)
            msg_and_signature = (hashed_msg, self.rsa.decrypt(hashed_intmsg))
            print("Server: msg and signature is ", msg_and_signature)
            client_socket.send(str(msg_and_signature).encode(self.format))

            break

        # Close connection once out of the loop
        print("Closing connection...")
        client_socket.close()


if __name__ == "__main__":
    server = Server(64, 5050, "utf-8", "!DISCONNECT", RSA())
    server.open()

"cd c:/microsoft vs code/seng2250/seng2250/a3"
