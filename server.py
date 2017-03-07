#!/usr/bin/python
# -*- coding: utf-8 -*-
import argparse
import pprint
import socket
import ssl
import crypto_handler
import conn_handler
import os
import signal
import sys

def listen(port):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.load_cert_chain('server_cert.pem', keyfile='server_key.pem')
    ctx.load_verify_locations('client_cert.pem')
    conn = ctx.wrap_socket(socket.socket(socket.AF_INET),
                           server_side=True)

    conn.bind(('localhost', port))
    conn.listen()
    return conn


def client_handler(connstream):
    while True:
        mode = str(connstream.recv(1024),'utf-8')
        if mode == 'put':
            fhash = connstream.recv(1024)
            fname = str(connstream.recv(1024),'utf-8')
            with open('server_files/' + fname + '.sha256', 'wb') as f:
                f.write(fhash)
            conn_handler.recv_data(connstream,'server_files/' + fname)
            msg = "Transfer of "+fname+" complete"
            connstream.sendall(str.encode(msg))


        if mode == 'get':
            filename = str(connstream.recv(1024),'utf-8')
            if os.path.exists('server_files/' + filename):
                connstream.sendall(str.encode("OK"))
                conn_handler.send_data(connstream,'server_files/'+filename)
                conn_handler.send_data(connstream,'server_files/'+filename+'.sha256')
            else:
                connstream.sendall(str.encode("Error: "+filename+" was not retrieved"))
        if not mode:
            break

def _valid_port(port):
    try:
        port = int(port)
    except ValueError:
        raise argparse.ArgumentTypeError('Port must be numeric')
    else:
        if (port < 1024 or port > 65536):
            raise argparse.ArgumentTypeError('Port Number out of range. Should be in the range [1024,65536]')
        return port

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='I am the server')
    parser.add_argument('port', type=_valid_port,
                        help='The port on which the server should run')

    # Parse the commandline arguments.
    args = parser.parse_args()
    try:
        sock = listen(args.port)
    except Exception as e:
        print('Failed to bind to the port: ' + str(e))
        sys.exit(1)

    try:
        (client_socket, addr) = sock.accept()
        try:
            while True:
                client_handler(client_socket)
        finally:
            client_socket.close()
    finally:
        sock.close()
