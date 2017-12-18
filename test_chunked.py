import re
from socket import *
from http_struct import HTTPRequest, HTTPResponse

def main():
    sock = socket(AF_INET, SOCK_STREAM)
    host = 'swjx.scu.edu.cn'
    port = 80
    sock.connect((host, port))
    request = b'GET http://swjx.scu.edu.cn/ HTTP/1.1\r\nUser-Agent: curl/7.47.0\r\nConnection: Keep-Alive\r\nHost: swjx.scu.edu.cn\r\nAccept: */*\r\n\r\n'
    sock.sendall(request)
    
    # data = b''
    # while True:
    #     temp = sock.recv(2048)
    #     if temp:
    #         data += temp
    #     else:
    #         break
    
    # print(data.decode('utf-8'))
        

    response = HTTPResponse(sock.makefile('rb', -1))

    print(response.to_byte())


if __name__ == '__main__':
    main()
