#!/usr/bin/env python
# -*- coding: utf8 -*-
# ---------------------------------------------------------------
#
#        sock2http.py
#
#        Author        : shejingui
#        Date          : 11.01 2017
#        Comment       : sock5 to http convert program
#        Python ver    : 2.7.10
#        Last modified :
#
#
# ----------------------------------------------------------------


import argparse
import logging
import socket
import select
import struct
from SocketServer import ThreadingTCPServer


# ----------------------------------------------------------------
# SOCK2Http class and method

CMD_CONNECT = 1
CMD_BIND = 2
CMD_UDP_ASSOCIATE = 3

ADDRTYPE_IPV4 = 1
ADDRTYPE_IPV6 = 4
ADDRTYPE_HOST = 3

BUF_SIZE = 32 * 1024


def dict2str(d):
    """format dict to readable str"""
    t = []
    for k, v in d.items():
        l = []
        l.append('\t')
        l.append(k)
        l.append('\t\t:' if len(k) < 8 else '\t:')
        l.append(str(v))
        t.append(''.join(l))
    return '\n'.join(t)


def parse_header(data):
    addrtype = ord(data[0])
    dest_addr = None
    dest_port = None
    header_length = 0
    if addrtype == ADDRTYPE_IPV4:
        if len(data) >= 7:
            dest_addr = socket.inet_ntoa(data[1:5])
            dest_port = struct.unpack('>H', data[5:7])[0]
            header_length = 7
        else:
            logging.warn('header is too short')
    elif addrtype == ADDRTYPE_HOST:
        if len(data) > 2:
            addrlen = ord(data[1])
            if len(data) >= 2 + addrlen:
                dest_addr = data[2:2 + addrlen]
                dest_port = struct.unpack('>H', data[2 + addrlen:4 + addrlen])[0]
                header_length = 4 + addrlen
            else:
                logging.warn('header is too short')
        else:
            logging.warn('header is too short')
    else:
        logging.warn('unsupported addrtype %d' % addrtype)

    if dest_addr is None:
        return None
    else:
        return addrtype, dest_addr, dest_port, header_length


class SOCK2HttpHandler:

    def __init__(self, request, client_address, server):
        # self.config = server.config  # get sys configuration by sock server member
        self.config = syscfgdup()
        self.local_sock = request
        self.local_address = client_address
        self.remote_sock = None
        self.remote_address = (self.config['xip'], self.config['xport'])

        self.recvbytes = 0
        self.sendbytes = 0
        self.flag = repr(client_address)

        request.setsockopt(socket.SOL_TCP, socket.TCP_NODELAY, 1)
        logging.warning('%s connected!' % self.flag)

        # ----------------------------------------------------------------
        # STAGE_PARSE

        try:
            target = self.parse_request()
        except Exception, e:
            logging.error('{} parse socks failed:{}'.format(self.flag, e))
            logging.warning('%s break!' % self.flag)
            return
        logging.info('{} parse remote:{}'.format(self.flag, repr(target)))
        # ----------------------------------------------------------------
        # STAGE_INIT

        try:
            self.remote_sock = self.init_remote_c(target)
        except Exception, e:
            logging.error('{} init remote connection failed!{}'.format(self.flag, e))
            logging.warning('%s break!' % self.flag)
            return
        logging.info('%s init remote connection ok!' % self.flag)
        # ----------------------------------------------------------------
        # STAGE_STREAM

        try:
            self.stream_forward(self.local_sock, self.remote_sock)
        except Exception, e:
            logging.error('{} forward stream error!{}'.format(self.flag, e))

        logging.warning('{} handle finished!recvbytes:{},sendbytes:{}'.format
                        (self.flag, self.recvbytes, self.sendbytes))
        try:
            self.remote_sock.shutdown(socket.SHUT_WR)  # SHUT_RDWR
            self.remote_sock.close()
        except socket.error:
            pass

    def parse_request(self):
        stage = 0
        try:
            stage = 'INIT_SOCK_REQ'
            sockreq = self.getsockdata(stage)
            if ord(sockreq[0]) != 5:
                raise Exception('%s socks version not supported:%s' % (stage, repr(sockreq)))
            stage = 'INIT_SOCK_REQ_RESPONSE'
            self.local_sock.send(b'\x05\00')

            stage = 'INIT_SOCK_ADDR'
            sockreq = self.getsockdata(stage)
            cmd = ord(sockreq[1])
            if cmd != CMD_CONNECT:
                raise Exception('%s socks method not supported:%s' % (stage, repr(sockreq)))
            header_result = parse_header(sockreq[3:])
            if not header_result:
                raise Exception('%s header parse failed!:%s' % (stage, repr(sockreq)))
            addrtype, addr, port, length = header_result
            if addrtype == 4:
                raise Exception('%s IPV6 not supported yet!:%s' % (stage, repr(sockreq)))
            logging.debug('%s addrtype:%d host:%s port:%d len:%d' %
                          (self.flag, addrtype, addr, port, length))

            stage = 'INIT_SOCK_ADDR_RESPONSE'
            self.local_sock.send(b'\x05\x00\x00\x01\x00\x00\x00\x00\x40\x00')
            host = (addr, port)
            return host

        except socket.error, e:
            raise Exception('%s socket error:%s' % (stage, e))

    def getsockdata(self, stage):
        data = self.local_sock.recv(256)
        if not data:
            raise Exception('%s peer abort request' % stage)
        else:
            logging.debug('%s %s parse request:%s' % (self.flag, stage, repr(data)))
            return data

    def init_remote_c(self, target):
        if not self.remote_address[0]:
            sock = socket.socket()
            sock.connect(target)
            sock.setsockopt(socket.SOL_TCP, socket.TCP_NODELAY, 1)
        else:
            sock = self.create_remote_socket_proxy(self.remote_address, target)
        return sock

    def create_remote_socket_proxy(self, proxy, addr):
        httpheader = 'CONNECT '+addr[0]+':'+str(addr[1])+' HTTP/1.1\r\n\r\n'
        sock = socket.socket()
        sock.connect(proxy)
        sock.setsockopt(socket.SOL_TCP, socket.TCP_NODELAY, 1)
        sock.send(httpheader)

        data = sock.recv(1024)
        logging.debug('%s recv from proxy:%s' % (self.flag, data.rstrip()))
        words = data.split()
        if words[1] != '200':
            logging.warning('%s pass through the proxy failed:%s' % (self.flag,data.splitlines()[0]))
        return sock
    
    def stream_forward(self, sock, rsock):
        fdset = [sock, rsock]
        while True:
            r, w, e = select.select(fdset, [], [])
            if sock in r:
                data = sock.recv(BUF_SIZE)
                if not data:
                    logging.info('%s sock of uplayer soft closed!' % self.flag)
                    break
                rsock.sendall(data)
                self.sendbytes += len(data)

            if rsock in r:
                data = rsock.recv(BUF_SIZE)
                if not data:
                    logging.info('%s sock of remote closed!' % self.flag)
                    break
                sock.sendall(data)
                self.recvbytes += len(data)


class SOCKProxy(object):
    def __init__(self, config):
        listen_addr = config.get('local_address', '127.0.0.1')
        listen_port = config.get('sockport')
        self._timeout = config.get('timeout')
        self._addrs = (listen_addr, listen_port)

    def run(self):
        sock = None
        ThreadingTCPServer.daemon_threads = True
        ThreadingTCPServer.request_queue_size = 1024
        ThreadingTCPServer.allow_reuse_address = True

        try:
            sock = ThreadingTCPServer(self._addrs, SOCK2HttpHandler)
            logging.warning('-'*50)
            logging.warning('sock proxy start on:%s' % repr(self._addrs))
            sock.serve_forever()

        except Exception, e:
            logging.error('fatal error:%s' % e)
        except KeyboardInterrupt:
            logging.warning('user interrupt!')
        finally:
            if sock:
                sock.shutdown()
                sock.server_close()
                logging.warning('sock proxy stop')


def sockinit():
    cfg = syscfgdup()
    logging.warning('program configuration is:\n%s' % dict2str(cfg))
    x = SOCKProxy(cfg)
    x.run()


def set_logger(verbose):
    logging.getLogger('').handlers = []
    formatter = logging.Formatter('%(asctime)s %(levelname)-8s %(message)s',
                                  '%Y-%m-%d %H:%M:%S')

    ch = logging.StreamHandler()
    ch.setFormatter(formatter)
    logging.getLogger('').addHandler(ch)

    v_count = verbose
    if v_count >= 2:
        level = logging.DEBUG
    elif v_count == 1:
        level = logging.INFO
    else:
        level = logging.WARN
    logging.getLogger('').setLevel(level)


def loginit():
    v = syscfgget('v')
    set_logger(v)

# ----------------------------------------------------------------
_sysconfig = {}


def syscfginit(args):
    config = {}
    config['sockport'] = 0
    config['v'] = 0
    config['xip'] = 0
    config['xport'] = 0
    config['timeout'] = 3
    config['local_address'] = '0.0.0.0'
    config.update(args)

    global _sysconfig
    _sysconfig = config.copy()


def syscfgget(keys):
    return _sysconfig.get(keys)


def syscfgdup():
    return _sysconfig.copy()
# ----------------------------------------------------------------


def getargs():
    parser = argparse.ArgumentParser(description="", epilog="any suggestions,please visit http://agblog.net")
    parser.add_argument("sockport", type=int, help="the sock5 server working port")
    parser.add_argument("-x", "--http-proxy-ip", metavar="", dest="xip", default="proxy.xxx.com.cn",
                        help="the http proxy addr,default value: proxy.zte.com.cn")
    parser.add_argument("-p", "--http-proxy-port",  metavar="", dest="xport", type=int, default=80,
                        help="the http proxy port,default value: 80")
    parser.add_argument("-v", "--verbose", dest="v", action="count", default=0, help="")
    # parser.add_argument('-v', '--version', action='version', version='version 1.0')

    args = parser.parse_args()
    return vars(args)

    # print args  # type:: argparse.Namespace
    # parser.print_help()

# ----------------------------------------------------------------
# __main__


if __name__ == "__main__":
    a = getargs()
    syscfginit(a)
    loginit()
    sockinit()
