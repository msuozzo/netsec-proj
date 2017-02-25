import argparse
import pprint
import socket
import ssl


def connect(port):
  ctx = ssl.SSLContext(ssl.PROTOCOL_TLS)
  ctx.verify_mode = ssl.CERT_REQUIRED
  ctx.load_cert_chain('server_cert.pem', keyfile='server_key.pem')
  ctx.load_verify_locations('client_cert.pem')
  conn = ctx.wrap_socket(socket.socket(socket.AF_INET), server_side=True)
  
  conn.bind(('localhost', port))
  conn.listen()
  new_conn, addr = conn.accept()
  
  pprint.pprint(new_conn.getpeercert())
  
  new_conn.close()


if __name__ == '__main__':
  parser = argparse.ArgumentParser()
  parser.add_argument(
      'port',
      help='The port on which the server should run',
      type=int)

  # Parse the commandline arguments.
  args = parser.parse_args()

  connect(args.port)
