import argparse
import pprint
import socket
import ssl
import cmd
import os
import readline
import signal
import sys
from cmd import Cmd
import crypto_handler
import conn_handler


class Error(Exception):
    """Base error for the class."""


class Interact(Cmd):
    """CLI for interacting with the user!!
    """

    def __init__(self, clientsocket):
        super(Interact, self).__init__()
        self.prompt = ">"
        self.doc_header = "Secure TLS Shell"
        self.ruler = "-"
        self.intro = 'Welcome to our 2-Way secure TLS shell!!'
        self.clientsocket = clientsocket

        def sigint_handler(signum, frame):
            print('\nShutting down...')
            sys.exit(0)
        signal.signal(signal.SIGINT, sigint_handler)  # Signal Interrupt Handler.

    def cmdloop(self):
        try:
            super(Interact, self).cmdloop()
        except Exception as e:
            print('Error encountered: ' + str(e))
            self.intro = ''  # Suppress intro message for re-launch.
            self.cmdloop()

    def default(self, line):
        print("Invalid command. Valid commands: ('get' 'put' 'stop'). Type 'help <cmd>' for command-specific help")

    def do_stop(self,line):
        """ Exits the shell"""
        print("Shutting down...")
        self.clientsocket.sendall(str.encode(""))
        return True

    def do_get(self,line):
        """ Gets the file from the server!!
            line:
                filename        : The filename to be retrieved.
                <encflag>       : "E" or "N", whether the file was encrypted.
                <opt password>  : Password<8 Characters> for decrypting the file.
        """
        args = line.split(" ")
        if len(args) == 2:
            #case get <filename> <encflag = N>
            filename, encflag = line.split(" ")
            if encflag!='N':
                print('Error: For 2-argument get, flag must be "N"\nUsage: "get <fname> N"')
                return
            self._get(filename)
        elif len(args) == 3:
            #case get <filename> <encflag = E> <password>
            filename, encflag, password = line.split(" ")
            if len(password) != 8:
                print('Error: Password must be 8 characters (no spaces)')
                return
            elif encflag != 'E':
                print('Error: For 3-argument get, flag must be "E"\nUsage: "get <fname> E <pword>"')
                return
            self._get(filename, encrypt=True, password=password)
        else:
            print('Usage: "get <fname> <flag> {opt_pword}"')
            return

    def _get(self, filename, encrypt=False, password=None):
        self.clientsocket.sendall(str.encode("get"))
        self.clientsocket.sendall(str.encode(filename))
        status = str(self.clientsocket.recv(1024),'utf-8')
        if status != 'OK':
            #Server Error Occured.
            print(status)
            return

        hash_filename = filename + '.sha256'
        encrypted_filename = filename + '.encrypted'

        conn_handler.recv_data(self.clientsocket, filename)
        conn_handler.recv_data(self.clientsocket, hash_filename)
        with open(hash_filename,'r') as hash_file:
            fhash = hash_file.read()
        if encrypt:
            # Client assumes the file was encrypted.
            os.rename(filename, encrypted_filename)
            if not crypto_handler.decrypt_file(
                    password, encrypted_filename, output_filename=filename):
                #File was not encrypted to begin with!!
                print("Error: decryption of %s failed, was the file encrypted?" % filename)
                os.remove(filename)
            else:
                # Verify the decrypted file's hash
                filehash = crypto_handler.hash_(filename)
                if fhash == filehash:
                    print("Retrieval of %s complete" %filename)
                else:
                    print("Error: Computed hash of %s does not match "
                            "retrieved hash" % filename)
                    os.remove(filename)
            # In all cases, delete the hash and encrypted files.
            os.remove(hash_filename)
            os.remove(encrypted_filename)
        else:
            #Client assumes no encryption was applied
            filehash = crypto_handler.hash_(filename)
            if fhash == filehash:
                print("Retrieval of %s complete " % filename)
            else:
                print("Error: Computed hash of %s does not match "
                        "retrieved hash" % filename)
            os.remove(hash_filename)

    def do_put(self,line):
        """Puts the file into the server
            filename        : The filename should be in same folder.
            encflag         : "E" or "N", whether encryption is required or not
            opt<password>   : Password<8 Characters> for encrypting the file.
        """
        args = line.split(" ")
        if len(args) == 2:
            #case put <filename> <encflag>
            filename, encflag = line.split(" ")
            if not os.path.isfile(filename):
                print("Error: %s cannot be transferred" %filename)
                return
            elif encflag!='N':
                print('Error: For 2-argument put, flag must be "N"\nUsage: "put <fname> N"')
                return

            self._put(filename)
        elif len(args) == 3:
            #case put <filename> <encflag> <password>
            filename, encflag, password = line.split(" ")
            if not os.path.isfile(filename):
                print("Error: File not found.")
                return
            elif encflag != 'E':
                print('Error: For 3-argument put, flag must be "E"\nUsage: "put <fname> E <pword>"')
                return
            elif len(password) != 8:
                print('Error: Password must be 8 characters (no spaces)')
                return

            self._put(filename, encrypt=True, password=password)
        else:
            print('Usage: "put <fname> <flag> {opt_pword}"')
            return

    def _put(self, filename, encrypt=False, password=None):
        fhash = crypto_handler.hash_(filename)
        self.clientsocket.sendall(str.encode("put"))
        self.clientsocket.sendall(str.encode(fhash))
        self.clientsocket.sendall(str.encode(filename))
        if encrypt:
            crypto_handler.encrypt_file(password, filename)
            conn_handler.send_data(self.clientsocket, filename + '.encrypted')
        else:
            conn_handler.send_data(self.clientsocket, filename)
        msg = str(self.clientsocket.recv(1024), 'utf-8')
        print(msg)


def connect(hostname, port):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.check_hostname = False
    try:
        ctx.load_cert_chain('client_cert.pem', keyfile='client_key.pem')
    except Exception as e:
        raise Error('Failed to load client key or client certification: ' +
                str(e))
    try:
        ctx.load_verify_locations('server_cert.pem')
    except Exception as e:
        raise Error('Failed to load server cert: ' + str(e))
    
    conn = ctx.wrap_socket(socket.socket(socket.AF_INET))
    try:
        conn.connect((hostname, port))
    except Exception as e:
        raise Error('Failed to connect: ' + str(e))
    else:
        return conn

def _valid_addr(addr):
    if addr == 'localhost':
        return addr
    try:
        socket.inet_aton(addr)
    except OSError as e:
        raise argparse.ArgumentTypeError('Invalid IP address')
    else:
        return addr

def _valid_port(port):
    try:
        port = int(port)
    except ValueError:
        raise argparse.ArgumentTypeError('Port must be numberic')
    else:
        if (port < 1024 or port > 65536):
            raise argparse.ArgumentTypeError('Port Number out of range. Should be in the range [1024,65536]')
        return port


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="I am the client")
    parser.add_argument('serv_addr', type=_valid_addr, help='The address at which the server is running')
    parser.add_argument('serv_port', type=_valid_port, help='The port on which the server is running')

    # Parse the commandline arguments.
    args = parser.parse_args()
    try:
        sock = connect(args.serv_addr, args.serv_port)
    except Error as e:
        print(e)
        sys.exit(1)

    try:
        console = Interact(sock)
        console.cmdloop()
    finally:
        sock.close()
        sys.exit(0)
