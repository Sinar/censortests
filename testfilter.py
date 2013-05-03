# Credits to https://forum.lowyat.net/index.php?showtopic=2794929&view=findpost&p=60057869
import time,argparse
from socket import socket, IPPROTO_TCP, TCP_NODELAY, timeout, getaddrinfo

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
        s.send("GET / HTTP/1.1\r\nHost: "+host+"\r\n\r\n")
        s.settimeout(5) # five seconds ought to be enough
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
        time.sleep(0.2) # Sleep for a bit to ensure that the next packets goes through separately.
        s.send("Host: "+host[0:2])
        time.sleep(0.2)
        s.send(host[2:]+"\r\n\r\n")
        try:
            print s.recv(4096)
        except timeout:
            print "Timeout -- waited 5 seconds\n"  
            
def getips(host):
    return getaddrinfo(host, 80)  
    
def testsingle(host):
    run = test()
    run.test1(host) 
    run.test2(host) 
    run.test3(host)
    
def testall(host):
    ips = getips(host)                                                  
    if len(ips) > 0:
        for i in ips:
            testsingle(i[4][0])
        
    
def main():
    parser = argparse.ArgumentParser(
        prog="testfilter.py",
        description="Scripts to test for presence of censorship and packet filters")
    parser.add_argument('--host', help='Target Hostname', required=True, metavar='hostname')
    parser.add_argument('--tryall', help='Try all IPs returned by DNS lookup', metavar='', 
        default=1)
    arguments = parser.parse_args(namespace=target)
    
    if target.tryall is None:
        testsingle(target.host) 
    else:
        testall(target.host)
        
        
if __name__ == "__main__":
    main()
