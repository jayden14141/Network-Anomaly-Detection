# code by Owen

import socket

# Gets IP address of current device
HOST = socket.gethostbyname(socket.gethostname())

def main():
    # create a socket, AF_INET = IPv4, SOCK_RAW = RAW socket
    connection = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
    # binds to a certain port
    connection.bind((HOST,9999))

    # continuously receives data from socket
    while True:
        data, addr = connection.recvfrom(65536)


main()