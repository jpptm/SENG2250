import hashlib
import socket
import threading
import time
import secrets


class Client:
    PRIME_MODULUS = 178011905478542266528237562450159990145232156369120674273274450314442865788737020770612695252123463079567156784778466449970650770920727857050009668388144034129745221171818506047231150039301079959358067395348717066319802262019714966524135060945913707594956514672855690606794135837542707371727429551343320695239
    GENERATOR = 174068207532402095185811980123523436538604490794561350978495831040599953488455823147851597408940950725307797094915759492368300574252438761037084473467180148876118103083043754985190983472601550494691329488083395492313850000361646482644608492304078721818959999056496097769368017749273708962006689187956744210730

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

        self.client.connect((self.server_address, self.port))

    def open(self):
        self.client_send("Client_hello")
        self.client_send(self.disconnect_message)

    # Send msg to server
    def client_send(self, msg):

        message = msg.encode(self.format)
        msg_length = len(message)
        send_length = str(msg_length).encode(self.format)
        send_length += b" " * (self.header - len(send_length))
        self.client.send(send_length)
        self.client.send(message)

        print(self.client.recv(2048).decode(self.format))
        print(self.client.recv(2048).decode(self.format))
        print(self.client.recv(2048).decode(self.format))

    def receive(self):
        return


if __name__ == "__main__":
    client = Client(64, 5050, "utf-8", "!DISCONNECT", socket.gethostbyname(socket.gethostname()))
    client.open()
