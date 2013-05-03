#!/usr/bin/env python
"""
A script to test for the presence of censorship and packet filters for http websites

censortests/testfilter.py
http://sinarproject.org/

Run testfilter.py -h for a list of possible options.
"""

"""
Credits to https://forum.lowyat.net/index.php?showtopic=2794929&view=findpost&p=60057869
"""
import time
import argparse

from socket import socket, IPPROTO_TCP, TCP_NODELAY, timeout, gethostbyname, \
    getprotobyname, AF_INET, SOL_IP, SOCK_RAW, SOCK_DGRAM, IP_TTL, gethostbyaddr, error, getaddrinfo, SOL_TCP


class target:
    pass


class test:
    def test1(self, host):
        print "## Test 1: Check DNS, and IP block: Testing Same IP, different Virtual Host"
        s = socket()
        s.setsockopt(IPPROTO_TCP, TCP_NODELAY, 1)
        s.connect((host, 80))
        s.send("GET / HTTP/1.1\r\n\r\n")
        try:
            print s.recv(4096)
        except timeout:
            print "Timeout -- waited 5 seconds\n"

    def test2(self, host):
        print "## Test 2: Emulating a real web browser: Testing Same IP, actual Virtual Host, single packet"
        s = socket()
        s.setsockopt(IPPROTO_TCP, TCP_NODELAY, 1)
        s.connect((host, 80))
        s.send("GET / HTTP/1.1\r\nHost: " + host + "\r\n\r\n")
        s.settimeout(5)  # five seconds ought to be enough
        try:
            print s.recv(4096)
        except timeout:
            print "Timeout -- waited 5 seconds\n"

    def test3(self, host):
        print "## Test 3: Attempting to fragment: Testing Same IP, actual Virtual Host, fragmented packet"
        s = socket()
        s.setsockopt(IPPROTO_TCP, TCP_NODELAY, 1)
        s.connect((host, 80))
        s.send("GET / HTTP/1.1\r\n")
        # Sleep for a bit to ensure that the next packets goes through separately.
        # Not sure if we actually need it. Reducing it from 0.2 to 0.1 seconds
        time.sleep(0.1)
        s.send("Host: " + host[0:2])
        time.sleep(0.1)
        s.send(host[2:] + "\r\n\r\n")
        try:
            print s.recv(4096)
        except timeout:
            print "Timeout -- waited 5 seconds\n"


def getips(host, port=80):
    """
    See http://docs.python.org/2/library/socket.html#socket.getaddrinfo
    """
    addrs = getaddrinfo(host, port, 0, 0, SOL_TCP)
    result = []
    for addr in addrs:
        sockaddr = addr[4]
        if (addr[0] == 2):
            # We take IPv4 addresses only. IPv6 will be ignored for now
            result.append(sockaddr[0])
    return result


def testsingle(host):
    run = test()
    run.test1(host)
    run.test2(host)
    run.test3(host)


def testall(host):
    ips = getips(host)
    if len(ips) > 0:
        for i in ips:
            print "Testing %s\n" % i
            testsingle(i)


def traceroute(host):
    """
    credit: https://blogs.oracle.com/ksplice/entry/learning_by_doing_writing_your
    """

    print "## Try to trace route to target"
    dest_addr = gethostbyname(host)
    port = 33434
    max_hops = 30
    icmp = getprotobyname('icmp')
    udp = getprotobyname('udp')
    ttl = 1
    while True:
        recv_socket = socket(AF_INET, SOCK_RAW, icmp)
        send_socket = socket(AF_INET, SOCK_DGRAM, udp)
        send_socket.setsockopt(SOL_IP, IP_TTL, ttl)
        recv_socket.bind(("", port))
        send_socket.sendto("", (host, port))
        curr_addr = None
        curr_name = None
        try:
            _, curr_addr = recv_socket.recvfrom(512)
            curr_addr = curr_addr[0]
            try:
                curr_name = gethostbyaddr(curr_addr)[0]
            except error:
                curr_name = curr_addr
        except error:
            pass
        finally:
            send_socket.close()
            recv_socket.close()

        if curr_addr is not None:
            curr_host = "%s (%s)" % (curr_name, curr_addr)
        else:
            curr_host = "*"
        print "%d\t%s" % (ttl, curr_host)

        ttl += 1
        if curr_addr == dest_addr or ttl > max_hops:
            break


def main():
    parser = argparse.ArgumentParser(
        prog="testfilter.py",
        description="A script to test for the presence of censorship and packet filters for http websites")
    parser.add_argument('--host', help='Target Hostname', required=True, metavar='hostname')
    parser.add_argument('--tryall', help='Try all IPs returned by DNS lookup', metavar='1')
    parser.add_argument('--traceroute', help='Try to trace route to target host, require root access',
        metavar='1')
    arguments = parser.parse_args(namespace=target)

    if arguments.tryall is None:
        testsingle(target.host)
        if target.traceroute is not None:
            traceroute(target.host)
    else:
        testall(target.host)
        if target.traceroute is not None:
            traceroute(target.host)

if __name__ == "__main__":
    main()
