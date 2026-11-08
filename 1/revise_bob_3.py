
import socket
import argparse
import logging
import json
import base64
import secrets
import threading

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad


SEPARATOR = "\n"


# Check whether n is prime
def is_prime(n):
    if n < 2:
        return False

    for i in range(2, int(n ** 0.5) + 1):
        if n % i == 0:
            return False

    return True


# Find distinct prime factors of n
def factorize(n):
    factors = set()
    d = 2

    while d * d <= n:
        if n % d == 0:
            factors.add(d)
            while n % d == 0:
                n //= d
        d += 1

    if n > 1:
        factors.add(n)

    return factors


# Check whether g is a primitive root modulo p
def is_valid_generator(g, p):
    if not is_prime(p) or not (1 < g < p):
        return False

    factors = factorize(p - 1)

    for q in factors:
        if pow(g, (p - 1) // q, p) == 1:
            return False

    return True


# Generate valid DH parameters
def generate_dh_params():
    primes = [
        n for n in range(400, 501)
        if is_prime(n)
    ]

    p = secrets.choice(primes)

    generators = [
        g for g in range(2, p)
        if is_valid_generator(g, p)
    ]

    g = secrets.choice(generators)

    return p, g


# Generate DH public key
def dh_public_key(p, g, private_key):
    return pow(g, private_key, p)


# Send JSON with newline separator
def send_message(conn, message):
    data = json.dumps(message) + SEPARATOR
    conn.sendall(data.encode("ascii"))
    logging.info("[*] Sent: %s", message)


# Receive newline-delimited JSON
def recv_message(reader):
    line = reader.readline()

    if not line:
        raise ConnectionError("Connection closed")

    message = json.loads(line.decode("ascii"))
    logging.info("[*] Received: %s", message)

    return message


# AES-256-ECB encryption
def encrypt(key, message):
    padded = pad(message.encode("utf-8"), 16)
    encrypted = AES.new(key, AES.MODE_ECB).encrypt(padded)

    return base64.b64encode(encrypted).decode("ascii")


# AES-256-ECB decryption
def decrypt(key, encoded):
    encrypted = base64.b64decode(encoded, validate=True)
    decrypted = AES.new(key, AES.MODE_ECB).decrypt(encrypted)

    return unpad(decrypted, 16).decode("utf-8")


def handler(conn, addr, message):
    with conn:
        conn.settimeout(60)

        with conn.makefile("rb") as reader:
            try:
                logging.info(
                    "[*] Alice connected from %s:%s",
                    addr[0], addr[1]
                )

                # Step 1: Receive initial DH request
                request = recv_message(reader)

                if (
                    request.get("opcode") != 0
                    or request.get("type") != "DH"
                ):
                    raise ValueError("Invalid DH request")

                # Step 2: Generate Bob's DH parameters
                p, g = generate_dh_params()

                bob_private = secrets.randbelow(p - 3) + 2
                bob_public = dh_public_key(
                    p, g, bob_private
                )

                # Send Bob's public key and parameters
                response = {
                    "opcode": 1,
                    "type": "DH",
                    "public": bob_public,
                    "parameter": {
                        "p": p,
                        "g": g
                    }
                }

                send_message(conn, response)

                # Step 3: Receive Alice's public key
                alice_response = recv_message(reader)

                if alice_response.get("opcode") == 3:
                    logging.error(
                        "Alice rejected parameters: %s",
                        alice_response.get("error")
                    )
                    return

                if (
                    alice_response.get("opcode") != 1
                    or alice_response.get("type") != "DH"
                ):
                    raise ValueError("Invalid Alice public key")

                alice_public = alice_response["public"]

                if (
                    type(alice_public) is not int
                    or not (1 <= alice_public < p)
                ):
                    raise ValueError("Invalid public key value")

                # Step 4: Calculate shared secret
                shared_secret = pow(
                    alice_public, bob_private, p
                )

                # Convert to 32-byte AES key
                aes_key = (
                    shared_secret.to_bytes(2, "big") * 16
                )

                logging.info(
                    "[*] DH shared secret established"
                )

                # Step 5: Bob sends AES message FIRST
                encrypted_message = encrypt(
                    aes_key, message
                )

                bob_message = {
                    "opcode": 2,
                    "type": "AES",
                    "encryption": encrypted_message
                }

                send_message(conn, bob_message)

                # Step 6: Receive Alice's AES reply
                alice_message = recv_message(reader)

                if "encryption" not in alice_message:
                    raise ValueError(
                        "Missing encryption field"
                    )

                # Step 7: Decrypt Alice's message
                plaintext = decrypt(
                    aes_key,
                    alice_message["encryption"]
                )

                print(
                    "Alice plaintext:",
                    plaintext,
                    flush=True
                )

                logging.info(
                    "[*] Protocol III completed successfully"
                )

            except (
                OSError,
                ValueError,
                KeyError,
                TypeError,
                ConnectionError
            ) as e:
                logging.error("Protocol III failed: %s", e)


def run(addr, port, message):
    with socket.socket(
        socket.AF_INET,
        socket.SOCK_STREAM
    ) as bob:

        bob.setsockopt(
            socket.SOL_SOCKET,
            socket.SO_REUSEADDR,
            1
        )

        bob.bind((addr, port))
        bob.listen(5)

        logging.info(
            "[*] Bob is listening on %s:%s",
            addr, port
        )

        while True:
            conn, client_addr = bob.accept()

            threading.Thread(
                target=handler,
                args=(conn, client_addr, message),
                daemon=True
            ).start()


def command_line_args():
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "-a", "--addr",
        type=str,
        default="0.0.0.0"
    )

    parser.add_argument(
        "-p", "--port",
        type=int,
        required=True
    )

    parser.add_argument(
        "-m", "--message",
        type=str,
        default="hello"
    )

    parser.add_argument(
        "-l", "--log",
        type=str,
        default="INFO"
    )

    return parser.parse_args()


def main():
    args = command_line_args()
    logging.basicConfig(level=args.log)

    try:
        run(args.addr, args.port, args.message)
    except KeyboardInterrupt:
        logging.info("Bob stopped")
    except OSError as e:
        logging.error("Server failed: %s", e)


if __name__ == "__main__":
    main()

