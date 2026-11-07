

import argparse
import logging
import socket
import threading

from common_3 import JsonConnection


def generate_invalid_parameters(case):
    if case == "prime":
        # 480 is not a prime number
        p = 480
        g = 2

    elif case == "generator":
        # 499 is prime, but 1 is not a generator
        p = 499
        g = 1

    else:
        raise ValueError("Unknown test case")

    return p, g


def handler(conn, case):
    with conn:
        conn.settimeout(10)
        channel = JsonConnection(conn)

        try:
            # Step 1: Receive Alice's request
            request = channel.receive()
            logging.info("Received: %s", request)

            if request.get("opcode") != 0 or request.get("type") != "DH":
                raise ValueError("Expected DH request")

            # Step 2: Generate invalid DH parameters
            p, g = generate_invalid_parameters(case)

            private = 7
            public = pow(g, private, p)

            # Step 3: Send invalid parameters
            response = {
                "opcode": 1,
                "type": "DH",
                "public": public,
                "parameter": {
                    "p": p,
                    "g": g
                }
            }

            channel.send(response)
            logging.info("Sent: %s", response)

            # Step 4: Receive Alice's error response
            error = channel.receive()
            logging.info("Received: %s", error)

            expected_error = (
                "incorrect prime number"
                if case == "prime"
                else "incorrect generator"
            )

            if (
                error.get("opcode") == 3
                and error.get("error") == expected_error
            ):
                print("Protocol IV test passed:", expected_error)
            else:
                print("Protocol IV test failed:", error)

        except (OSError, ConnectionError, ValueError, KeyError, TypeError) as exc:
            logging.error("Protocol IV Bob failed: %s", exc)


def run(addr, port, case):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((addr, port))
        server.listen(10)

        logging.info("Bob is listening on %s:%s", addr, port)
        logging.info("Test case: %s", case)

        while True:
            conn, info = server.accept()
            logging.info("Accepted connection from %s:%s", *info)

            threading.Thread(
                target=handler,
                args=(conn, case),
                daemon=True
            ).start()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--addr", default="0.0.0.0")
    parser.add_argument("--port", required=True, type=int)
    parser.add_argument(
        "--case",
        choices=["prime", "generator"],
        default="prime"
    )

    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO)

    try:
        run(args.addr, args.port, args.case)
    except OSError as exc:
        logging.error("Protocol IV Bob failed: %s", exc)
        raise SystemExit(1)


if __name__ == "__main__":
    main()

