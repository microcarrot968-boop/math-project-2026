import argparse
import logging
import socket
import threading

from common_2 import JsonConnection, aes_decrypt, aes_encrypt, decrypt_aes_key, generate_rsa_key


def handler(conn, message):
    with conn:
        conn.settimeout(10)
        channel = JsonConnection(conn)
        try:
            request = channel.receive()
            logging.info('Received: %s', request)
            if request.get('opcode') != 0 or request.get('type') != 'RSA':
                raise ValueError('Expected RSA request')

            n, e, d = generate_rsa_key()
            public_message = {'opcode': 1, 'type': 'RSA', 'public': e, 'parameter': {'n': n}}
            channel.send(public_message)
            logging.info('Sent RSA public key: %s', public_message)

            key_message = channel.receive()
            if key_message.get('opcode') != 2 or key_message.get('type') != 'RSA':
                raise ValueError('Expected RSA-encrypted AES key')
            key = decrypt_aes_key(key_message['encrypted_key'], n, d)
            logging.info('Recovered 32-byte AES key')

            encrypted_message = channel.receive()
            if encrypted_message.get('opcode') != 2 or encrypted_message.get('type') != 'AES':
                raise ValueError('Expected AES-encrypted message')
            plaintext = aes_decrypt(key, encrypted_message['encryption'])
            print('Alice plaintext:', plaintext, flush=True)

            reply = {'opcode': 2, 'type': 'AES', 'encryption': aes_encrypt(key, message)}
            channel.send(reply)
            logging.info('Sent AES-encrypted reply: %s', reply)
        except (OSError, ValueError, KeyError, TypeError) as exc:
            logging.error('Protocol II Bob failed: %s', exc)


def run(addr, port, message):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((addr, port))
        server.listen(10)
        logging.info('Bob is listening on %s:%s', addr, port)
        while True:
            conn, info = server.accept()
            logging.info('Accepted connection from %s:%s', *info)
            threading.Thread(target=handler, args=(conn, message), daemon=True).start()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-a', '--addr', default='0.0.0.0')
    parser.add_argument('-p', '--port', type=int, required=True)
    parser.add_argument('-m', '--message', default='world')
    parser.add_argument('-l', '--log', default='INFO')
    args = parser.parse_args()
    logging.basicConfig(level=args.log.upper())
    try:
        run(args.addr, args.port, args.message)
    except OSError as exc:
        logging.error('Bob server failed: %s', exc)
        raise SystemExit(1)


if __name__ == '__main__':
    main()

