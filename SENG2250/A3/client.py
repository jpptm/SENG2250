import secrets
import socket
import util


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
        print("Client: Client_setup_request")

        # Receive server hello
        server_hello = self.client.recv(4096).decode(self.format)
        rsa_strpubkey = self.client.recv(4096).decode(self.format)

        print(type(rsa_strpubkey))
        print(f"Server: {server_hello}")

        # Decode the public key from the server - take ( and ) out of the string then split by ,
        # Entry 0 is e, entry 1 is n
        rsa_pubkey_tuple = [e for e in rsa_strpubkey[1:-1].split(",")]
        e, n = int(rsa_pubkey_tuple[0]), int(rsa_pubkey_tuple[1][1:])
        print(f"Server public key: {rsa_pubkey_tuple}")
        # print("".join(str(e) for e in rsa_pubkey_tuple))

        # Send client ID to server
        self.client.send(self.id.encode(self.format))
        print(f"Client: client_hello - {self.id}")

        # Receive RSA signature from server
        server_rsa_msgsig = self.client.recv(4096).decode(self.format)

        print(f"Server: msg and signature is {server_rsa_msgsig}")

        # Verify the signature by transforming the msg back to tuple form and doing the maths
        msg, signature = (e for e in server_rsa_msgsig[1:-1].split(","))
        # Remove space char in the beginning of signature and ' in the start and end of msg
        msg = msg[1:-1]
        signature = signature[1:]
        # print(f"msg: {msg}, signature: {signature}")
        # print("typecast: ", type(signature))
        # Type cast twice and derive signature
        sig_to_msg = util.fast_mod_exp(int(signature), e, n)
        hexmsg = sig_to_msg.to_bytes((sig_to_msg.bit_length() + 7) // 8, "big").hex()
        print("Signature to msg: ", hexmsg)
        print("msg to siggggggg: ", msg)
        print(type(hexmsg))
        print(type(msg))
        if msg == hexmsg:
            print("Signature verified")
        # Send disconnection message
        self.client.send(self.disconnect_message.encode(self.format))


if __name__ == "__main__":
    client = Client(
        64, 5050, "utf-8", "!DISCONNECT", socket.gethostbyname(socket.gethostname())
    )
    client.open()
