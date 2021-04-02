import socket

local_address_bind = "127.0.0.1", 8080
bufferSize = 1024

server_message = "Hello Client"
message_bytes = str.encode(server_message)

# Create socket
UDPServerSocket = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)

# Binding
UDPServerSocket.bind(local_address_bind)
print("UDP server is listening:")

# Listen for clients
while True:
    bytesAddressPair = UDPServerSocket.recvfrom(bufferSize)

    message = bytesAddressPair[0]
    address = bytesAddressPair[1]

    clientMsg = "Client Message: {}".format(message)
    clientIP = "Client IP Address: {}".format(address)
    print(clientMsg)
    print(clientIP)

    # Sending a reply to client
    UDPServerSocket.sendto(message_bytes, address)
