
import argparse
import logging
import socket

from common_3 import JsonConnection, is_prime, is_generator


def run(addr, port):
    with socket.create_connection((addr, port), timeout=10) as conn:
        conn.settimeout(10)
        channel = JsonConnection(conn)

        logging.info("Alice connected to %s:%s", addr, port)

        # Step 1: Request DH key exchange
        request = {
            "opcode": 0,
            "type": "DH"
        }

        channel.send(request)
        logging.info("Sent: %s", request)

        # Step 2: Receive Bob's DH parameters
        response = channel.receive()
        logging.info("Received: %s", response)

        if response.get("opcode") != 1 or response.get("type") != "DH":
            raise ValueError("Expected DH public key response")

        p = response["parameter"]["p"]
        g = response["parameter"]["g"]

        # Step 3: Check whether p is prime
        if not (type(p) is int and 400 <= p <= 500 and is_prime(p)):
            error = {
                "opcode": 3,
                "error": "incorrect prime number"
            }

            channel.send(error)
            logging.error("Sent: %s", error)
            print("Incorrect prime number detected")
            return

        # Step 4: Check whether g is a generator
        if not is_generator(g, p):
            error = {
                "opcode": 3,
                "error": "incorrect generator"
            }

            channel.send(error)
            logging.error("Sent: %s", error)
            print("Incorrect generator detected")
            return

        # Step 5: Valid parameters
        print("DH parameters are valid.")
        print("p =", p)
        print("g =", g)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--addr", required=True)
    parser.add_argument("--port", required=True, type=int)

    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO)

    try:
        run(args.addr, args.port)
    except (OSError, ConnectionError, ValueError, KeyError, TypeError) as exc:
        logging.error("Protocol IV Alice failed: %s", exc)
        raise SystemExit(1)


if __name__ == "__main__":
    main()

