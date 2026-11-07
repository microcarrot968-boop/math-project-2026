
import argparse
import logging
import socket
import threading

from common_3 import (
    JsonConnection,
    aes_decrypt,
    aes_encrypt,
    generate_dh_keypair,
    generate_dh_parameters,
    shared_aes_key
)


def handler(conn, message):
    with conn:
        conn.settimeout(10)
        channel = JsonConnection(conn)

        try:
            # Receive DH request from Alice
            request = channel.receive()
            logging.info("Received: %s", request)

            if request.get("opcode") != 0 or request.get("type") != "DH":
                raise ValueError("Expected DH request")

            # Generate DH parameters and keypair
            p, g = generate_dh_parameters()
            private, public = generate_dh_keypair(p, g)

            response = {
                "opcode": 1,
                "type": "DH",
                "public": public,
                "parameter": {"p": p, "g": g}
            }

            channel.send(response)
            logging.info("Sent Bob DH public key: %s", response)

            # Receive Alice's DH public key
            alice_response = channel.receive()
            logging.info("Received: %s", alice_response)

            if alice_response.get("opcode") == 3:
                logging.error(
                    "Alice reports: %s",
                    alice_response.get("error")
                )
                return

            if (
                alice_response.get("opcode") != 1
                or alice_response.get("type") != "DH"
            ):
                raise ValueError("Expected Alice DH public key")

            # Derive AES key
            key = shared_aes_key(
                alice_response["public"],
                private,
                p
            )

            # Receive and decrypt Alice's AES message
            encrypted_message = channel.receive()

            if (
                encrypted_message.get("opcode") != 2
                or encrypted_message.get("type") != "AES"
            ):
                raise ValueError("Expected AES-encrypted message")

            plaintext = aes_decrypt(
                key,
                encrypted_message["encryption"]
            )
            print("Alice plaintext:", plaintext, flush=True)

            # Encrypt and send Bob's reply
            reply = {
                "opcode": 2,
                "type": "AES",
                "encryption": aes_encrypt(key, message)
            }

            channel.send(reply)
            logging.info("Sent AES-encrypted reply: %s", reply)

        except (OSError, ConnectionError, ValueError, KeyError, TypeError) as exc:
            logging.error("Protocol III Bob failed: %s", exc)


def run(addr, port, message):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((addr, port))
        server.listen(10)

        logging.info("Bob is listening on %s:%s", addr, port)

        while True:
            conn, info = server.accept()
            logging.info("Accepted connection from %s:%s", *info)

            threading.Thread(
                target=handler,
                args=(conn, message),
                daemon=True
            ).start()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--addr", default="0.0.0.0")
    parser.add_argument("--port", required=True, type=int)
    parser.add_argument("--message", default="world")

    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO)

    try:
        run(args.addr, args.port, args.message)
    except OSError as exc:
        logging.error("Protocol III Bob failed: %s", exc)
        raise SystemExit(1)


if __name__ == "__main__":
    main()

