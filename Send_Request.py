import socket

message = "Hello Server"
message_bytes = str.encode(message)

local_address_port = ("127.0.0.1", 8080)
dns_address_port = ("8.8.8.8", 53)
bufferSize = 1024

# Create socket
UDPClientSocket = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
UDPClientSocket.settimeout(1.0)

# Send to server and receive
UDPClientSocket.sendto(message_bytes, dns_address_port)
received_message = []
try:
    received_message = UDPClientSocket.recvfrom(bufferSize)
    msg = "Message from Server {}".format(received_message[0])
    print(msg)
except socket.timeout:
    print("Request Time Out")
