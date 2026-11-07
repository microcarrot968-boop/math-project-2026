import argparse
import logging
import secrets
import socket
from common_2 import JsonConnection, aes_decrypt, aes_encrypt, encrypt_aes_key, validate_rsa_public


def run(addr, port, message):
    with socket.create_connection((addr, port), timeout=10) as conn:
        conn.settimeout(10)
        logging.info('Alice connected to %s:%s', addr, port)
        channel = JsonConnection(conn)

        request = {'opcode': 0, 'type': 'RSA'}
        channel.send(request)
        logging.info('Sent: %s', request)

        response = channel.receive()
        logging.info('Received: %s', response)
        if response.get('opcode') != 1 or response.get('type') != 'RSA':
            raise ValueError('Expected RSA public key response')
        n = response['parameter']['n']
        e = response['public']
        validate_rsa_public(n, e)
        logging.info('Received RSA public key: n=%d, e=%d', n, e)

        key = secrets.token_bytes(32)
        encrypted_key = encrypt_aes_key(key, n, e)
        key_message = {'opcode': 2, 'type': 'RSA', 'encrypted_key': encrypted_key}
        channel.send(key_message)
        logging.info('Sent RSA-encrypted AES key (32 integers)')

        encrypted_message = {'opcode': 2, 'type': 'AES', 'encryption': aes_encrypt(key, message)}
        channel.send(encrypted_message)
        logging.info('Sent AES-encrypted message: %s', encrypted_message)

        reply = channel.receive()
        logging.info('Received: %s', reply)
        if reply.get('opcode') != 2 or reply.get('type') != 'AES':
            raise ValueError('Expected AES-encrypted reply')
        plaintext = aes_decrypt(key, reply['encryption'])
        print('Bob decrypted Alice message and replied.')
        print('Bob plaintext:', plaintext)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-a', '--addr', required=True)
    parser.add_argument('-p', '--port', type=int, required=True)
    parser.add_argument('-m', '--message', default='hello')
    parser.add_argument('-l', '--log', default='INFO')
    args = parser.parse_args()
    logging.basicConfig(level=args.log.upper())
    try:
        run(args.addr, args.port, args.message)
    except (OSError, ConnectionError, ValueError, KeyError, TypeError) as exc:
        logging.error('Protocol II Alice failed: %s', exc)
        raise SystemExit(1)


if __name__ == '__main__':
    main()
