#!/usr/bin/env python3

from socket import AF_INET, SOCK_STREAM, socket

from http_struct import HTTPResponse


def main():
    sock = socket(AF_INET, SOCK_STREAM)
    host = "swjx.scu.edu.cn"
    port = 80
    sock.connect((host, port))
    request = b"GET http://swjx.scu.edu.cn/ HTTP/1.1\r\n \
                User-Agent: curl/7.47.0\r\n \
                Connection: Keep-Alive\r\n  \
                Host: swjx.scu.edu.cn\r\n   \
                Accept: */*\r\n\r\n"

    sock.sendall(request)

    # data = b''
    # while True:
    #     temp = sock.recv(2048)
    #     if temp:
    #         data += temp
    #     else:
    #         break

    # print(data.decode('utf-8'))

    response = HTTPResponse(sock.makefile("rb", -1))

    print(response.to_byte())


if __name__ == "__main__":
    main()
