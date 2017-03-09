#!/usr/bin/env python3
import argparse
import errno
import os
import shutil
import socket
import ssl
import sys

import crypto_handler
import conn_handler


_TMP_FNAME = '.~~tmp_serv_file'


class Error(Exception):
    """Base error for the server."""


def client_handler(connstream):
    while True:
        mode = str(connstream.recv(1024),'utf-8')
        if mode == 'put':
            fhash = connstream.recv(1024)
            filename = str(connstream.recv(1024),'utf-8')
            filename = os.path.basename(filename)
            hash_filename = filename + '.sha256'
            try:
                with open(hash_filename, 'wb') as f:
                    f.write(fhash)
            except:
                try: conn_handler.recv_data(connstream, _TMP_FNAME)
                except: pass
                connstream.sendall(str.encode("Error: %s was not put" % filename))
            else:
                try:
                    conn_handler.recv_data(connstream, _TMP_FNAME)
                    shutil.move(_TMP_FNAME, filename)
                except:
                    connstream.sendall(str.encode("Error: %s was not put" % filename))
                else:
                    connstream.sendall(str.encode("Transfer of %s complete" % filename))
            finally:
                try: os.remove(_TMP_FNAME)
                except: pass
        elif mode == 'get':
            filename = str(connstream.recv(1024), 'utf-8')
            hash_filename = filename + '.sha256'

            # Check that both the requested file and its hash file exist
            # and are readable by the client.
            try:
                open(filename, 'rb').close()
                open(hash_filename, 'rb').close()
            except:
                connstream.sendall(str.encode("Error: %s was not retrieved" % filename))
            else:
                connstream.sendall(str.encode("OK"))
                conn_handler.send_data(connstream, filename)
                connstream.sendall(str.encode(open(hash_filename).read(), 'utf-8'))
        if not mode:
            break


def listen(port, server_cert, server_key, client_cert):
    """Listens on a port for clients connecting with a given cert.

    Returns an SSLSocket bound to the local port on success.
    Raises Error if listening fails.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
    ctx.verify_mode = ssl.CERT_REQUIRED
    try:
        ctx.load_cert_chain(server_cert, keyfile=server_key)
        ctx.load_verify_locations(client_cert)
        conn = ctx.wrap_socket(socket.socket(socket.AF_INET),
                               server_side=True)

        conn.bind(('', port))
        conn.listen(0)
    except Exception as e:
        raise Error('Failed to listen: %s' % str(e))
    else:
        return conn


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
    parser.add_argument('port', type=_valid_port, help='The port on which the server should run')
    parser.add_argument('cert', type=str, help='The path of the server cert (.pem)')
    parser.add_argument('key', type=str, help='The path of the server private key used to sign its cert (.pem)')
    parser.add_argument('clnt_cert', type=str, help='The path of the client cert (.pem)')

    # Parse the commandline arguments.
    args = parser.parse_args()
    try:
        sock = listen(args.port, args.cert, args.key, args.clnt_cert)
    except Error as e:
        print(str(e))
        sys.exit(1)

    try:
        while True:
            (client_socket, addr) = sock.accept()
            try:
                client_handler(client_socket)
            except Exception as e:
                print('Client connection failed: %s' % str(e))
            finally:
                client_socket.close()
    except Exception as e:
        print('Failed to accept a connection: %s' % str(e))
    finally:
        sock.close()
