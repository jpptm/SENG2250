# Server implementation
import hashlib
import secrets
import socket

import cbc
from dhe import DiffieHellman
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
            print(f"Client: {client_setup_request}", "\n")

            # Send server_hello to client
            client_socket.send("Server_hello, RSA public key is ".encode(self.format))
            client_socket.send(str(self.rsa.public_key).encode(self.format))
            print(
                f"Server: public key sent to client {address}: {self.rsa.public_key}",
                "\n",
            )

            # Receive client ID and generate session ID
            clientID = client_socket.recv(4096).decode(self.format)
            print(f"Client: client_hello - {clientID}", "\n")
            sessionID = secrets.token_hex(16)

            # The client ID is going to be in hex, now is the time to create the RSA signature using the client ID. Let m = (ServerID, seshID)
            # s = m^d mod n sent by server
            # Server sends (m, s) to client, verifies s^e mod n = m, If true then server is authenticated
            msg = f"{clientID}/{self.id}/{sessionID}".encode(self.format)
            hashed_msg = hashlib.sha256(msg).hexdigest()
            hashed_intmsg = int("0x" + hashed_msg, 16)
            msg_and_signature = (msg, self.rsa.decrypt(hashed_intmsg))

            print("Server: msg and signature is ", msg_and_signature, "\n")
            client_socket.send(str(msg_and_signature).encode(self.format))

            # If the program has not ended by this point then the RSA signature must have matched, now initialise Diffie Hellman

            # === === === D I F F I E - H E L L M A N - E X C H A N G E === === === #

            # Generate a random number and initiate DHKE (1 < xa < p)
            dh = DiffieHellman()
            true_rng = secrets.SystemRandom()
            xa = true_rng.randint(2, dh.p - 1)

            # Generate server's public key and send it to the client
            ya = dh.calculate_pubkey(xa)
            client_socket.send(str(xa).encode(self.format))
            xb = client_socket.recv(4096).decode(self.format)

            # Calculate the shared secret key
            Kba = dh.calculate_shared_secret(ya, int(xb))
            # print("Server: shared secret key is ", Kba, "\n")

            # === === === C B C - H M A C - T E S T === === === #

            # 64 byte (64 chars) msg from server to be delivered to client
            server_msg = (
                "Man cannot grow without pain for man is both sculptor and marble"
            )
            # Generate HMAC using the Diffie-Hellman key for this session
            k_prime = hashlib.sha256(Kba.to_bytes(1024, "big")).digest()
            server_hmac = cbc.hashed_mac(server_msg, k_prime)
            # Cbc encrypt the msg
            encrypted_server_msg = cbc.encrypt(server_msg, k_prime, sessionID)

            print(
                f"Server: plaintext - {server_msg}, encrypted - {encrypted_server_msg}, hmac - {server_hmac}",
                "\n",
            )
            print(f"Server: Kprime: {k_prime}, sesionID: {sessionID}")

            # Receive and send needed messages
            server_pack = (encrypted_server_msg, server_hmac)
            client_socket.send(str(server_pack).encode(self.format))
            client_pack = client_socket.recv(4096).decode(self.format)

            # Parse data received from client
            client_pack = client_pack[1:-1].split(",")
            encrypted_client_msg = client_pack[0]
            # The [1:-1] is to remove the quotes from the string
            encrypted_client_msg = encrypted_client_msg[1:-1]
            client_hmac = client_pack[1][1:]
            client_hmac = client_hmac[1:-1]

            print(encrypted_client_msg)
            print(client_hmac)

            # Derive client hmac by decrypting client message - if the hmacs match then the message is authentic
            server_derived_client_plaintext = cbc.decrypt(
                encrypted_client_msg, k_prime, sessionID
            )
            server_derived_client_hmac = cbc.hashed_mac(
                server_derived_client_plaintext, k_prime
            )

            print(
                f"Server: derived client plaintext - {server_derived_client_plaintext}, derived client hmac - {server_derived_client_hmac}",
                "\n",
            )

            # If the hmacs match then the message is authentic
            if server_derived_client_hmac == client_hmac:
                print("Server: Client message is authentic")
            else:
                print("Server: Client message is not authentic")

            break

        # Close connection once out of the loop
        print("Closing connection...")
        client_socket.close()


if __name__ == "__main__":
    server = Server(64, 5050, "utf-8", "!DISCONNECT", RSA())
    server.open()

"cd c:/microsoft vs code/seng2250/seng2250/a3"
