import argparse
import socket
from ipwhois import IPWhois, exceptions
from time import time
from scapy.all import sr1
from scapy.layers.inet import IP, UDP, TCP, ICMP
from scapy.layers.inet6 import IPv6, ICMPv6EchoRequest


class Traceroute:
    def __init__(self, host, timeout, port, TTL, verb, msg_type):
        self.IPv6 = ':' in host
        self.host = host
        self.timeout = timeout
        self.port = port
        self.TTL = TTL
        self.verb = verb
        types = {'tcp': self.tcp, 'udp': self.udp, 'icmp': self.icmp}
        self.execute = types[msg_type]

    def run(self):
        asn = ''
        for ttl in range(1, self.TTL):
            package = self.execute(ttl)
            start_ping = time()
            reply = sr1(package, verbose=0, retry=-3, timeout=self.timeout)
            end_ping = round((time() - start_ping) * 1000)
            if self.verb:
                if ttl == 1:
                    continue
                try:
                    asn = IPWhois(reply.src).lookup_whois()['asn']
                except exceptions.IPDefinedError as e:
                    asn = 'Not found'
            if reply is None:
                print(ttl, '*', 'timeout')
                break
            elif reply.haslayer(TCP)\
                    or (reply.type == 3 and reply.code == 3)\
                    or (reply.type == 0 and reply.code == 0)\
                    or (reply.type == 1 and reply.code == 4)\
                    or (reply.type == 129 and reply.code == 0):
                print("Done!", reply.src, end_ping, 'ms', asn)
                break
            else:
                print(ttl, reply.src, end_ping, 'ms', asn)

    def tcp(self, i):
        if self.IPv6:
            return IPv6(dst=self.host, hlim=i) / TCP(dport=self.port)
        return IP(dst=self.host, ttl=i) / TCP(dport=self.port)

    def udp(self, i):
        if self.IPv6:
            return IPv6(dst=self.host, hlim=i) / UDP(dport=self.port)
        return IP(dst=self.host, ttl=i) / UDP(dport=self.port)

    def icmp(self, i):
        if self.IPv6:
            return IPv6(dst=self.host, hlim=i) / ICMPv6EchoRequest()
        return IP(dst=self.host, ttl=i) / ICMP(type=8)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-t', dest='timeout', required=False, type=float,
                        default=2)
    parser.add_argument('-p', dest='port', type=int, default=33434,
                        required=False)
    parser.add_argument('-n', dest='TTL', type=int, default=64,
                        required=False)
    parser.add_argument('-v', dest='verb', default=False,
                        action='store_true', required=False)
    parser.add_argument('host', type=str)
    parser.add_argument(dest='msg_type', choices=['tcp', 'udp', 'icmp'])
    args = parser.parse_args()
    if ':' in args.host:
        host = args.host
    else:
        host = socket.gethostbyname(args.host)
    traceroute = Traceroute(host,
                            args.timeout,
                            args.port,
                            args.TTL,
                            args.verb,
                            args.msg_type)
    traceroute.run()
