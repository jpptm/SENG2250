import secrets
import socket
import sys

import util

import hashlib


class Client:
    def __init__(
        self,
        header: int,
        port: int,
        format: str,
        disconnect_message: str,
        server_address: str,
        id=secrets.token_hex(16),
    ):
        self.header = header
        self.port = port
        self.format = format
        self.disconnect_message = disconnect_message
        self.client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # socket.gethostbyname(socket.gethostname())
        self.server_address = server_address
        self.id = id

    def open(self):
        # Connect to server
        self.client.connect((self.server_address, self.port))

        # Send setup_request hello
        self.client.send("Client_setup_request".encode(self.format))
        print("Client: Client_setup_request", "\n")

        # Receive server hello
        server_hello = self.client.recv(4096).decode(self.format)
        rsa_strpubkey = self.client.recv(4096).decode(self.format)

        print(f"Server: {server_hello}", "\n")

        # Decode the public key from the server then split by comma. Entry 0 is e, entry 1 is n
        # the [1:] takes the unnecessary space char away from n
        rsa_pubkey_tuple = [e for e in rsa_strpubkey[1:-1].split(",")]
        e, n = int(rsa_pubkey_tuple[0]), int(rsa_pubkey_tuple[1][1:])
        print(f"Server public key: {rsa_pubkey_tuple}", "\n")

        # Send client ID to server
        self.client.send(self.id.encode(self.format))
        print(f"Client: client_hello - {self.id}", "\n")

        # Receive RSA signature from server
        server_rsa_msgsig = self.client.recv(4096).decode(self.format)

        # Verify the signature by transforming the msg back to tuple form and doing the maths
        msg, signature = (e for e in server_rsa_msgsig[1:-1].split(","))
        # Remove space char in the beginning of signature and b'' in msg
        msg = msg[2:-1]
        signature = signature[1:]

        # Derive the signature by doing the maths and compare to the hash of the raw msg
        sig_to_msg = util.fast_mod_exp(int(signature), e, n)
        hashed_rawmsg = hashlib.sha256(msg.encode()).hexdigest()
        hexmsg = sig_to_msg.to_bytes((sig_to_msg.bit_length() + 7) // 8, "big").hex()

        # Confirm signature integrity
        if hashed_rawmsg == hexmsg:
            print("Signature verified", "\n")
        # Force close connection if the RSA signature is not the same as the msg
        else:
            print("Signature not verified, connection not secure", "\n")
            sys.exit()

        # Initialise Diffie-Hellman key exchange if the signatures match

        # Send disconnection message
        self.client.send(self.disconnect_message.encode(self.format))


if __name__ == "__main__":
    client = Client(
        64, 5050, "utf-8", "!DISCONNECT", socket.gethostbyname(socket.gethostname())
    )
    client.open()
