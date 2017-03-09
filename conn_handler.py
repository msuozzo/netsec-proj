"""Utils for sending and receiving data over a connection."""


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
    pieces = []
    remaining = int.from_bytes(sock.recv(4), 'big')
    while remaining:
        # While we expect to receive more data, gather that much data (or
        # a full chunk, whichever is smaller).
        buf = sock.recv(min(remaining, 1024))
        pieces.append(buf)
        remaining -= len(buf)
    data = b''.join(pieces)
    with open(filename, 'wb') as f:
        f.write(data)
