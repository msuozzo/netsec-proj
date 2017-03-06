import argparse
import pprint
import socket
import ssl
import cmd
import os
import signal
import sys
from cmd import Cmd
import crypto_handler
import conn_handler

class Interact(Cmd):

    """CLI for interacting with the user!!
    """

    def __init__(self,clientsocket):
        cmd.Cmd.__init__(self)
        self.prompt     = ">"
        self.doc_header = "Secure TLS Shell"
        self.ruler      = "-"
        self.intro      = 'Welcome to our 2-Way secure TLS shell!!'
        self.clientsocket = clientsocket
        signal.signal(signal.SIGINT, self.handler)# Signal Interrupt Handler.

    def handler(self, signum, frame):
        """For handling ctrl-c events
        """
        print ("Recieved Signal !! Cleaning Up Please Wait")
        self.clientsocket.close()
        exit()

    def cmdloop(self):
        try:
            Cmd.cmdloop(self)
        except Exception as e:
            print ("Wrong Syntax use help <command> to find correct usage.",e)
            self.cmdloop()

    def default(self, line):
        print ("Error: Invalid commands, valid commands are 'get' 'put' 'stop'")

    def do_stop(self,line):
        """ Exits the shell"""
        print ("Closing Socket!! Please wait")
        return True

    def do_get(self,line):
        """ Gets the file from the server!!
            line:
                filename        : The filename to be retrieved.
                <encflag>       : "E" or "N", whether the file was encrypted.
                <opt password>  : Password<8 Characters> for decrypting the file.
        """
        args = line.split(" ")
        if len(args)==2:
            #case get <filename> <encflag = N>
            filename, encflag = line.split(" ")
            if encflag!='N':
                print ("Error: Wrong Flag")
                self.cmdloop()
        elif len(args)==3:
            #case get <filename> <encflag = E> <password>
            filename, encflag, password = line.split(" ")
            if len(password)!=8:
                print ("Password is short <8 Characters>")
                self.cmdloop()
            if encflag!='E':
                print ("Wrong Flag")
                self.cmdloop()
        else:
            print ("Wrong Number of Arguments")
            self.cmdloop()
        self.clientsocket.sendall(str.encode("get"))
        self.clientsocket.sendall(str.encode(filename))
        status = str(self.clientsocket.recv(1024),'utf-8')
        if status=="OK":
            conn_handler.recv_data(self.clientsocket,'tmp_client/'+filename)
            conn_handler.recv_data(self.clientsocket,'tmp_client/'+filename+".sha256")
            hash_file = open('tmp_client/'+filename+".sha256",'r')
            fhash = hash_file.read()
            if encflag=='E':
                #Client assumes the file was encrypted.
                os.rename('tmp_client/'+filename,'tmp_client/'+filename+".encrypted")
                if not crypto_handler.decrypt_file(password, 'tmp_client/'+filename+".encrypted"):
                    #File was not encrypted to begin with!!
                    print ("Error: decryption of %s failed, was the file encrypted?"
                            %filename)
                    os.remove('tmp_client/'+filename+".sha256") # sha of file
                    os.remove('tmp_client/'+filename+".encrypted") #enc file
                    os.remove('tmp_client/'+filename)
                else:
                    #File decrypted check hash
                    filehash = crypto_handler.hash_('tmp_client/'+filename)
                    if fhash==filehash:
                        print ("retrieval of %s complete" %filename)
                    else:
                        print ("Error: Computed hash of %s does not match "
                        "retrieved hash" %filename)
                        os.remove('tmp_client/'+filename)
                    #Irrespecive of Match or not delete the hashed file.
                    os.remove('tmp_client/'+filename+".sha256")
                    os.remove('tmp_client/'+filename+".encrypted")
            else:
                #Client assumes no encryption was applied
                filehash = crypto_handler.hash_('tmp_client/'+filename)
                if fhash==filehash:
                    print ("retrieval of %s complete "%filename)
                else:
                    print ("Error: Computed hash of %s does not match "
                        "retrieved hash" %filename)
                os.remove('tmp_client/'+filename+".sha256")
        else:
            #Server Error Occured.
            print (status)

    def do_put(self,line):
        """Puts the file into the server
            filename        : The filename should be in same folder.
            encflag         : "E" or "N", whether encryption is required or not
            opt<password>   : Password<8 Characters> for encrypting the file.
        """
        args = line.split(" ")
        filename = args[0].strip()
        if len(args)==2:
            #case put <filename> <encflag>
            filename, encflag = line.split(" ")
            if not os.path.isfile(filename):
                print ("Error: %s cannot be transferred" %filename)
                self.cmdloop()
            if encflag!='N':
                print ("Wrong parameter")
                self.cmdloop()
        elif len(args)==3:
            #case put <filename> <encflag> <password>
            filename ,encflag, password = line.split(" ")
            if not os.path.isfile(filename):
                print ("Error: File not found. Should be in same folder!")
                self.cmdloop()
            if encflag!="E" or len(password)!=8:
                print ("Error: Wrong Flag/password")
                self.cmdloop()
        else:
            print ("Error: Wrong Number of Arguments!!")
            self.cmdloop()
        fhash = crypto_handler.hash_(filename)
        self.clientsocket.sendall(str.encode("put"))
        self.clientsocket.sendall(str.encode(fhash))
        self.clientsocket.sendall(str.encode(filename))
        if encflag=="N":
            conn_handler.send_data(self.clientsocket,filename)
        else:
            crypto_handler.encrypt_file(password,filename)
            conn_handler.send_data(self.clientsocket,filename+'.encrypted')
        msg = str(self.clientsocket.recv(1024),'utf-8')
        print (msg)


def connect(hostname, port):
  ctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
  ctx.verify_mode = ssl.CERT_REQUIRED
  ctx.check_hostname = False
  ctx.load_cert_chain('client_cert.pem', keyfile='client_key.pem')
  ctx.load_verify_locations('server_cert.pem')
  conn = ctx.wrap_socket(socket.socket(socket.AF_INET))

  conn.connect((hostname, port))
  #pprint.pprint(conn.getpeercert())
  return conn
  #conn.close()


def check_arguments(serv_addr,port):
  """
  Sanity-checking server arguments.
  """
  try:
      serv_addr = socket.inet_aton(serv_addr)
  except:
      print ("Invalid IP address")
      return False
  if (port <1024 or port >65536):
      print ("Port Number out of range. Should be in <1024,65536>")
      return False
  else:
      return True


if __name__ == '__main__':
  parser = argparse.ArgumentParser(description="I am the client")
  parser.add_argument('serv_addr',type=str,help='The address at which the server is running')
  parser.add_argument('serv_port', type=int,help='The port on which the server is running')

  # Parse the commandline arguments.
  args = parser.parse_args()
  if check_arguments(args.serv_addr,args.serv_port):
      socket = connect(args.serv_addr, args.serv_port)
      try:
            console = Interact(socket)
            console.cmdloop()
      finally:
            socket.close()
            sys.exit(0)
