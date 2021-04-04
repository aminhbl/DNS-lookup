import socket


def main():
    message = "Hello Server"
    local_address_port = ("127.0.0.1", 8080)
    dns_address_port = ("8.8.8.8", 53)
    send_request(message, dns_address_port)


def send_request(message, address_port):
    bufferSize = 1024
    message_bytes = str.encode(message)

    # Create socket
    UDPClientSocket = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
    UDPClientSocket.settimeout(10.0)

    # Send to server and receive
    UDPClientSocket.sendto(message_bytes, address_port)
    received_message = []
    try:
        received_message = UDPClientSocket.recvfrom(bufferSize)
        # msg = "Message from Server {}".format(received_message[0].decode())
        # print(msg)
    except socket.timeout:
        print("Request Time Out")
    finally:
        UDPClientSocket.close()
    return received_message[0].hex()


if __name__ == '__main__':
    main()
