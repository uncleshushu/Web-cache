#!/usr/bin/env python3
# coding: utf-8

'''
This module includes handler 
for common HTTP methods, 
as well as some classes for implementing 
an HTTP client, an HTTP server, 
an HTTP proxy or a Web cache.
'''

import re
import sys
import functools
import select
import socket
from threading import Thread

from http_struct import HTTPRequest, HTTPResponse, ProxyRequest
from db_manager import DBManager

###########################################
# exceptions
###########################################

class HandlerError(Exception):
    '''
    Base class for exceptions in this module.
    '''
    pass

class AuthFailure(HandlerError):
    '''
    Request authorization failure.
    '''
    def __init__(self, message):
        self.message = message


###########################################
# functions for common clients and servers
###########################################

def authenticate(cursor, username, password):
    '''
    Authenticate a user.
    '''
    
    pass


def client_GET(httpRequest, socket2s):
    print('Now do client GET')
    socket2s.sendall(httpRequest.to_byte())
    print('GET request sent:')
    # print(httpRequest.to_byte())


def client_POST(httpRequest, socket2s):
    print('Now do client POST')
    socket2s.sendall(httpRequest.to_byte())
    print('POST request sent')

def client_REQUEST(httpRequest, socket2s):
    print('Now do client REQUEST')
    socket2s.sendall(httpRequest.to_byte())
    print('request sent')

def server_RESPONSE(httpResponse, socket2c, recount_len=False):
    print('Now do RESPONSE')

    socket2c.sendall(httpResponse.to_byte(recount_len))
    
    print('response sent:')
    print(httpResponse.to_byte())

    print('do RESPONSE finished')



###########################################
# functions for proxy
###########################################
# def proxy_authorize(dbManager):
#     def decorator(func):
#         @functools.wraps(func)
#         def wrapper(proxyRequest, socket2s):
#             if not proxyRequest.proxy_user:
#                 raise AuthFailure('User can not be empty.')
           
#             try:
#                 is_valid = dbManager.auth_user(proxyRequest.proxy_user, proxyRequest.proxy_pass)
#                 if not is_valid:
#                     raise AuthFailure('Password incorrect.')
#             except ValueError as valueError:
#                 # user doesn't exsit
#                 raise AuthFailure(str(valueError))
#         return wrapper

#     return decorator

AUTH_FAILURE_RES = HTTPResponse()
AUTH_FAILURE_RES.firstline = 'HTTP/1.1 407 Proxy Authentication Required'
AUTH_FAILURE_RES.headers = {   
                            "Connection": "close",
                            "Proxy-Authenticate": 'Basic realm="Authentication Required"'
                        }
AUTH_FAILURE_RES.body = None    

def proxy_authorize(dbManager, proxyRequest, socket2c):
    if not proxyRequest.proxy_user:  
        AUTH_FAILURE_RES.body = b'Proxy Authentication Required.'
        print("sent 'Proxy Authentication Required' message")
        return False

    try:
        print('username provided: ', proxyRequest.proxy_user)
        print('password provided: ', proxyRequest.proxy_pass)
        is_valid = dbManager.user_auth(proxyRequest.proxy_user, proxyRequest.proxy_pass)
        if not is_valid:
            AUTH_FAILURE_RES.body = b'Incorrect Token.'
            AUTH_FAILURE_RES.headers["Proxy-Authenticate"] = 'Basic realm="Incorrect Token"'
            
            print("sent 'Unauthorized' message")
  
            return False
        else:
            return True
    
    except ValueError as valueError:
        print(valueError, file=sys.stderr)


def forward_connect(proxyRequest, socket2s):
    '''
    Connect the host specified in `httpRequest`
    '''
    default_port = 443 if proxyRequest.method == 'CONNECT' else 80

    host_port = proxyRequest.headers['Host'].rsplit(":")
    host = host_port[0]
    port = int(host_port[1]) if len(host_port) == 2 else default_port
    socket2s.connect((host, port))


FORBIDDEN_RES = HTTPResponse()
FORBIDDEN_RES.firstline = 'HTTP/1.1 403 Forbidden'
FORBIDDEN_RES.headers = {   
                            "Connection": "close"
                        }
FORBIDDEN_RES.body = b'403 Forbidden\nYou are not allowed to visit this site.\n'
def filter(proxyRequest, rules):
    isforbidden = False
    if not rules:
        isforbidden = False
        return isforbidden

    # print('rules: ')
    # print(rules)
    print('proxyRequest.path:')
    print(proxyRequest.path)
    # if proxyRequest.path.startswith("http://"):
    #     redirect_url = rules.get(proxyRequest.path)
    # else:
    #     redirect_url = rules.get("http://" + proxyRequest.headers.get('Host') + proxyRequest.path)

    redirect_host = rules.get(proxyRequest.headers.get('Host'))
    
    print('redirect_host: ', redirect_host)

    if redirect_host is None:
        # no rule for this host
        isforbidden = False
        
    elif redirect_host == '':
        # forbidden
        isforbidden = True
        print('403 Forbidden')
        
    else:
        isforbidden = False
        proxyRequest.firstline = proxyRequest.firstline.replace(proxyRequest.headers.get('Host'), redirect_host)
        proxyRequest.path = proxyRequest.path.replace(proxyRequest.headers.get('Host'), redirect_host)
        proxyRequest.headers['Host'] = redirect_host

        print('modified request message:')
        print(proxyRequest.to_byte().decode(errors='ignore'))

    return isforbidden


def proxy_REQUEST(proxyRequest, socket2s): 
    if proxyRequest.headers.get('Proxy-Authorization'):
        proxyRequest.headers.pop('Proxy-Authorization')
    if proxyRequest.headers.get('Proxy-Connection'):
        proxyRequest.header.pop('Proxy-Connection')

    client_REQUEST(proxyRequest, socket2s)
    


def proxy_CONNECT(socket2c):
    '''
    Establish a HTTPS tunnel
    specified by the given HTTPRequest instance.
    '''
    socket2c.send(b'HTTP/1.1 200 Connection Established\r\n\r\n')
    
    # logger
    print("sent tunnel established message to client")

def forward_TCP(socket_in, socket_out, max_size):
    '''
    When `socket_in` is readable,
    call this method to 
    forward some bytes to `socket_out`.
    '''

    data = socket_in.recv(max_size)

    if not data:
        # connection closed
        raise EOFError('socket {} closed'.format(socket_in.getpeername()))
    
    socket_out.sendall(data)

    # print('frowarded {} bytes data from {} to {}'.format(len(data), socket_in.getpeername(), socket_out.getpeername()))

def tunneling(socket_a, socket_b):
    conns = [socket_a, socket_b]
    while True:
        rlist, wlist, xlist = select.select(conns, [], [], 10)

        if xlist or not rlist:
            break
    
        for rsock in rlist:
            other = conns[1] if rsock is conns[0] else conns[0]
            try:  
                forward_TCP(rsock, other, 65536)
            except EOFError as eofError:
                raise eofError


def proxy_handle(socket2c, require_auth=False, use_rules=False):
    socket2c_file = socket2c.makefile('rb', -1)
    proxyRequest = ProxyRequest(socket2c_file)

    print('original request:')
    print(proxyRequest.to_byte().decode(errors='ignore'))

    if require_auth or use_rules:
        dbManager = DBManager()

    if require_auth:
        isvalid = proxy_authorize(dbManager, proxyRequest, socket2c)
        if not isvalid:
            server_RESPONSE(AUTH_FAILURE_RES, socket2c, recount_len=True)
            socket2c.close()
            return

    if use_rules:
        rules = dbManager.get_rules(proxyRequest.proxy_user)
        isforbidden = filter(proxyRequest, rules)
        if isforbidden:
            server_RESPONSE(FORBIDDEN_RES, socket2c, recount_len=True)
            socket2c.close()
            return


    socket2s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    forward_connect(proxyRequest, socket2s)
    socket2s_file = socket2s.makefile('rb', -1)

    if proxyRequest.method == 'CONNECT':
        # logger
        print('serving as an HTTPS proxy...')
        
        proxy_CONNECT(socket2c)   

        try:
            tunneling(socket2c, socket2s)
        except EOFError as eofError:
            # logger
            print(eofError)
        
    else:
        # logger
        print('serving as an HTTP proxy...')

        while True:
            try:
                proxy_REQUEST(proxyRequest, socket2s)
                httpResponse = HTTPResponse(socket2s_file)
                server_RESPONSE(httpResponse, socket2c)

                proxyRequest = ProxyRequest(socket2c_file)
                print('original request:')
                print(proxyRequest.to_byte().decode(errors='ignore'))
            except EOFError as eofError:
                # logger
                print(eofError)
                break

    socket2c.close()
    socket2s.close()      

###########################################
# functions for web-cache
###########################################

def cache_GET(httpRequest, socket2c, socket2s, db_conn):

    last_modified_date, resource = query_cache(httpRequest, db_conn)
    httpRequest.headers['If-Modified-Since'] = last_modified_date

    client_GET(httpRequest, socket2s)



###########################################
# handler functions
###########################################




###########################################
# handler classes
###########################################

class ProxyHandlerThread(Thread):
    '''
    A thread that handles proxy requests
    in blocking mode.
    '''
    def __init__(self, socket2c):
        self.socket2c = socket2c  
        
        self._socket2s_file = None
        # self._socket2s_file = self.socket2s.makefile('rb', -1)

   

        