import argparse
import socket
import socket
import re
from time import time
from scapy.all import sr1, whois
from scapy.layers.inet import IP, UDP, TCP, ICMP


class Traceroute:
    def __init__(self, host, timeout, port, TTL, verb, msg_type):
        self.host = host
        self.timeout = timeout
        self.port = port
        self.TTL = TTL
        self.verb = verb
        types = {'tcp': self.tcp, 'udp': self.udp, 'icmp': self.icmp}
        self.execute = types[msg_type]
        self.AS = re.compile(r'AS\d\d\d\d\d')

    def run(self):
        for ttl in range(1, self.TTL):
            package = self.execute(ttl)
            start_ping = time()
            reply = sr1(package, verbose=0, retry=-3, timeout=self.timeout)
            end_ping = round((time() - start_ping) * 1000)
            self.define_asn(reply.src)
            # AS = self.AS.findall(whois(reply.src).decode())
            # print(AS)
            if reply is None:
                print(ttl, '*', 'timeout')
                break
            elif reply.haslayer(TCP)\
                    or (reply.type == 3 and reply.code == 3)\
                    or (reply.type == 0 and reply.code == 0):
                print("Done!", reply.src, end_ping, 'ms')
                break
            else:
                print(ttl, reply.src, end_ping, 'ms')
        self.s.close()

    def define_asn(self, ip):
        self.s = socket.socket()
        self.s.settimeout(self.timeout)
        # self.s.connect(('whois.apnic.net', 43))
        self.s.connect(('193.0.6.135', 43))
        req = f'-V Md5.2 {ip}\n'
        self.s.recv(16384)
        self.s.send(req.encode())
        self.s.recv(16384)
        data = self.s.recv(16384)
        print(data)
        AS = self.AS.findall(data.decode())
        print(AS)
        self.s.close()

    def tcp(self, i):
        return IP(dst=self.host, ttl=i) / TCP(dport=self.port)

    def udp(self, i):
        return IP(dst=self.host, ttl=i) / UDP(dport=self.port)

    def icmp(self, i):
        return IP(dst=self.host, ttl=i) / ICMP(type=8)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-t', dest='timeout', required=False, type=float,
                        default=2)
    parser.add_argument('-p', dest='port', type=int, default=33434,
                        required=False)
    parser.add_argument('-n', dest='TTL', type=int, default=30,
                        required=False)

    parser.add_argument('-v', dest='verb', default=False,
                        action='store_true',
                        required=False)
    parser.add_argument('host', type=str)
    parser.add_argument(dest='msg_type', choices=['tcp', 'udp', 'icmp'])
    args = parser.parse_args()
    traceroute = Traceroute(socket.gethostbyname(args.host),
                            args.timeout,
                            args.port,
                            args.TTL,
                            args.verb,
                            args.msg_type)
    traceroute.run()
