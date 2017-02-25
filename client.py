import pprint
import ssl
import socket

ctx = ssl.SSLContext(ssl.PROTOCOL_TLS)
ctx.verify_mode = ssl.CERT_REQUIRED
ctx.check_hostname = False
ctx.load_cert_chain('client_cert.pem', keyfile='client_key.pem')
ctx.load_verify_locations('server_cert.pem')
conn = ctx.wrap_socket(socket.socket(socket.AF_INET))

conn.connect(('localhost', 8888))

pprint.pprint(conn.getpeercert())

conn.close()
