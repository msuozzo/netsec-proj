import argparse
import pprint
import socket
import ssl


def connect(hostname, port):
  ctx = ssl.SSLContext(ssl.PROTOCOL_TLS)
  ctx.verify_mode = ssl.CERT_REQUIRED
  ctx.check_hostname = False
  ctx.load_cert_chain('client_cert.pem', keyfile='client_key.pem')
  ctx.load_verify_locations('server_cert.pem')
  conn = ctx.wrap_socket(socket.socket(socket.AF_INET))

  conn.connect((hostname, port))

  pprint.pprint(conn.getpeercert())

  conn.close()


if __name__ == '__main__':
  parser = argparse.ArgumentParser()
  parser.add_argument(
      'serv_addr',
      help='The address at which the server is running')
  parser.add_argument(
      'serv_port',
      help='The port on which the server is running',
      type=int)

  # Parse the commandline arguments.
  args = parser.parse_args()

  connect(args.serv_addr, args.serv_port)
