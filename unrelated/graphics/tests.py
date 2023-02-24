import socket

# Create a TCP socket
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Allow the socket to reuse the local address
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

# Bind the socket to a local address
sock.bind(("localhost", 1234))

# Listen for incoming connections
sock.listen(5)

print("Server listening on", sock.getsockname())

# Accept incoming connections and handle them
while True:
    conn, addr = sock.accept()
    print("Incoming connection from", addr)
    conn.close()
