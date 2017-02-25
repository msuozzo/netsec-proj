import pprint
import ssl
import socket

ctx = ssl.SSLContext(ssl.PROTOCOL_TLS)
ctx.verify_mode = ssl.CERT_REQUIRED
ctx.check_hostname = False
ctx.load_cert_chain('server_cert.pem', keyfile='server_key.pem')
ctx.load_verify_locations('client_cert.pem')
conn = ctx.wrap_socket(socket.socket(socket.AF_INET), server_side=True)

conn.bind(('localhost', 8888))
conn.listen()
new_conn, addr = conn.accept()

pprint.pprint(new_conn.getpeercert())

new_conn.close()
