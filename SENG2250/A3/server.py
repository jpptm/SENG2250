# Server implementation
import hashlib
import socket
import time
import secrets

# nonce generator is  = secrets.token_urlsafe()


class Server:
    PRIME_MODULUS = 178011905478542266528237562450159990145232156369120674273274450314442865788737020770612695252123463079567156784778466449970650770920727857050009668388144034129745221171818506047231150039301079959358067395348717066319802262019714966524135060945913707594956514672855690606794135837542707371727429551343320695239
    GENERATOR = 174068207532402095185811980123523436538604490794561350978495831040599953488455823147851597408940950725307797094915759492368300574252438761037084473467180148876118103083043754985190983472601550494691329488083395492313850000361646482644608492304078721818959999056496097769368017749273708962006689187956744210730
    PUBLIC_KEY = 65537

    # Constructor for server object
    def __init__(
        self,
        header: int,
        port: int,
        format: str,
        disconnect_message: str,
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
            client_hello = client_socket.recv(16).decode(self.format)

            # Disconnect if the client wishes to do so
            if client_hello == self.disconnect_message.encode(self.format):
                break
            
            # Print client_hello
            print(f"Client: {client_hello}")            
            
            # Send server_hello to client
            client_socket.send("Server_hello".encode(self.format))

            # Receive client ID
            clientID = client_socket.recv(16).decode(self.format)
            print(f"Client: client id {clientID}")

        # Close connection once out of the loop
        print("Closing connection...")
        client_socket.close()

    # TO DO See pg.py
    # Generate serverID
    def generate_serverID(self):
        serverID = secrets.token_urlsafe(16)
        return serverID



if __name__ == "__main__":
    server = Server(64, 5050, "utf-8", "!DISCONNECT")
    server.open()

"cd c:/microsoft vs code/seng2250/seng2250/a3"
"""
THINGS TO DO
1 CLIENT SET UP HELLO x
2 SERVER SEND CLIENT RSA PUB KEY
3 CLIENT HELLO: ID_CLIENT
4 SERVER HELLO: ID_SERVER, SESSION_ID
5 EPHEMERAL DHE
6 CHECK SHARED KEY
7 DATA EXCHANGE
8 DISCONNECT
"""

"""
FAST MODULAR EXPONENTIATION
# Used to calculate for keys in DHE and RSA
def fme(base, exponent, n):
    if n == 1:
        return 0
    rs = 1
    while exponent > 0:
        if exponent & 1 == 1:
            rs = (rs * base) % n
        exponent = exponent >> 1
        base = (base * base) % n
    return rs
"""
