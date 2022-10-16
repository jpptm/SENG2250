import secrets
import socket


class Client:
    def __init__(
        self,
        header: int,
        port: int,
        format: str,
        disconnect_message: str,
        server_address: str,
    ):
        self.header = header
        self.port = port
        self.format = format
        self.disconnect_message = disconnect_message
        self.client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # socket.gethostbyname(socket.gethostname())
        self.server_address = server_address
        self.id = self.generate_clientID()

        self.client.connect((self.server_address, self.port))

    def open(self):
        # Send setup_request hello
        self.client.send("Client_hello".encode(self.format))
        print("Client: client_hello")

        # Receive server hello
        server_hello = self.client.recv(16).decode(self.format)
        print(f"Server: {server_hello}")

        # Send client ID to server
        self.client.send(self.id.encode(self.format))
        print(f"Client: {self.id}")

        # Send disconnection message
        self.client.send(self.disconnect_message.encode(self.format))

    # TO DO: See pg.py
    def generate_clientID(self):
        return secrets.token_urlsafe()


if __name__ == "__main__":
    client = Client(
        64, 5050, "utf-8", "!DISCONNECT", socket.gethostbyname(socket.gethostname())
    )
    client.open()
