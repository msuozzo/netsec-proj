

def send_data(sock, filename):
    """Send data from a file to the socket."""
    with open(filename, 'rb') as r:
       data = r.read()
       # check data length in bytes and send it to client
       data_length = len(data)
       sock.sendall(data_length.to_bytes(4, 'big'))
       sock.sendall(data)


def recv_data(sock, filename):
    """Receive data from the socket into a file."""
    # Get the size of the expected data.
    remaining = int.from_bytes(sock.recv(4), 'big')
    with open(filename, 'wb') as f:
        while remaining:
            # While we expect to receive more data, gather that much data (or
            # a full chunk, whichever is smaller).
            rbuf = sock.recv(min(remaining, 1024))
            remaining -= len(rbuf)
            f.write(rbuf)
