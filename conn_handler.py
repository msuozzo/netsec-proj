import socket

def send_data(s,filename):
    with open(filename, 'rb') as r:
       data = r.read()
       # check data length in bytes and send it to client
       data_length = len(data)
       s.sendall(data_length.to_bytes(4, 'big'))
       s.sendall(data)
    #s.shutdown(socket.SHUT_RDWR)
    #s.close()

def recv_data(clientsocket,filename):
    # check expected message length
    remaining = int.from_bytes(clientsocket.recv(4), 'big')
    d = open(filename, "wb")
    while remaining:
        # until there are bytes left...
        # fetch remaining bytes or 1024 (whatever smaller)
        rbuf = clientsocket.recv(min(remaining, 1024))
        remaining -= len(rbuf)
        # write to file
        d.write(rbuf)
    d.close()
