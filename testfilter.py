# Credits to https://forum.lowyat.net/index.php?showtopic=2794929&view=findpost&p=60057869
from socket import socket, IPPROTO_TCP, TCP_NODELAY, timeout
import time

host = 'ubah.tv'

print "## Test 1: Check DNS, and IP block: Testing Same IP, different Virtual Host"
s = socket()
s.setsockopt(IPPROTO_TCP, TCP_NODELAY, 1)
s.connect((host, 80))
s.send("GET / HTTP/1.1\r\n\r\n")
try:
    print s.recv(4096)
except timeout:
    print "Timeout -- waited 5 seconds\n"

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
