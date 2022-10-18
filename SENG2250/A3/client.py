import hashlib
import secrets
import socket
import sys

import cbc
import util
from dhe import DiffieHellman


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

        # === === === D I F F I E - H E L L M A N - E X C H A N G E === === === #

        # Generate a random number and initiate DHKE (1 < xa < p)
        dh = DiffieHellman()
        true_rng = secrets.SystemRandom()
        xb = true_rng.randint(2, dh.p - 1)

        # Receive server public key and generate client's public key
        yb = dh.calculate_pubkey(xb)
        xa = self.client.recv(4096).decode(self.format)
        self.client.send(str(xb).encode(self.format))

        # Calculate shared secret key
        Kab = dh.calculate_shared_secret(yb, int(xa))
        print(f"Shared secret key: {Kab}", "\n")

        # === === === C B C - H M A C - T E S T === === === #

        print("F I R S T - M E S S A G E - E X C H A N G E", "\n")
        # 64 byte (64 chars) msg from client to be delivered to server
        client_message = (
            "Some things must first be broken, before they are truly complete"
        )
        # Use session ID as nonce
        sessionID = msg.split("/")[2]
        # Use the hashed Diffie-Hellman key as k' and generate hmac
        k_prime = hashlib.sha256(Kab.to_bytes(1024, "big")).digest()

        # Trim the key down to 192 bits for a 192 bit AES CBC key
        k_prime = k_prime[:24]

        self.msg_exhange(k_prime, client_message, sessionID)

        print("S E C O N D - M E S S A G E - E X C H A N G E", "\n")

        client_message = (
            "Ran out of quotes so here's a boring 64 byte msg from the client"
        )
        # Use session ID as nonce
        sessionID = msg.split("/")[2]
        # Use the hashed Diffie-Hellman key as k' and generate hmac
        k_prime = hashlib.sha256(Kab.to_bytes(1024, "big")).digest()

        # Trim the key down to 192 bits for a 192 bit AES CBC key
        k_prime = k_prime[:24]

        self.msg_exhange(k_prime, client_message, sessionID)

        # Send disconnection message
        self.client.send(self.disconnect_message.encode(self.format))

    def msg_exhange(self, k_prime, client_message, sessionID):
        print("k_prime_len: ", len(k_prime))
        client_hmac = cbc.hashed_mac(client_message, k_prime)

        # Cbc encrypt client msg
        encrypted_client_msg = cbc.encrypt(client_message, k_prime, sessionID)

        print(
            f"""Client: 
                      Plaintext: {client_message}
                      Encrypted: {encrypted_client_msg}
                           Hmac: {client_hmac}""",
            "\n",
        )
        print(
            f"""Client: 
                         Kprime: {k_prime }
                      SessionID: {sessionID}""",
            "\n",
        )
        # Receive cbc encrypted msg from server

        # Receive and send needed messages
        server_pack = self.client.recv(4096).decode(self.format)
        client_pack = (encrypted_client_msg, client_hmac)
        self.client.send(str(client_pack).encode(self.format))

        # Parse data received from server
        server_pack = server_pack[1:-1].split(",")
        encrypted_server_msg = server_pack[0]
        # The [1:-1] is to remove the quotes from the string
        encrypted_server_msg = encrypted_server_msg[1:-1]
        server_hmac = server_pack[1][1:]
        server_hmac = server_hmac[1:-1]

        print(
            f"""Client: 
                        Encrypted server message: {encrypted_server_msg}
                                     Server hmac: {server_hmac}"""
        )
        print(server_hmac)

        # Derive server hmac by decrypting server msg - if the hmacs match then the message is authentic
        client_derived_server_plaintext = cbc.decrypt(
            encrypted_server_msg, k_prime, sessionID
        )
        client_derived_server_hmac = cbc.hashed_mac(
            client_derived_server_plaintext, k_prime
        )

        print(
            f"""Client: 
                      Derived server plaintext: {client_derived_server_plaintext} 
                           Derived server hmac: {client_derived_server_hmac}""",
            "\n",
        )

        if client_derived_server_hmac == server_hmac:
            print("Client: Server message is authentic", "\n")
        else:
            print("Client: Server message is not authentic", "\n")
            sys.exit()
        pass


if __name__ == "__main__":
    client = Client(
        64, 5050, "utf-8", "!DISCONNECT", socket.gethostbyname(socket.gethostname())
    )
    client.open()
