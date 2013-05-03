censortests
===========

Scripts to test for presence of censorship and packet filters

Requirements:
 * A python interepreter, tested on Linux

Usage:

  `python testfilter.py --host ubah.tv [--tryall] [--traceroute]`
  
where ubah.tv is your host to test against.

Add --tryall to test against all IPs attached to the hostname returned by DNS

Add --traceroute to attempt traceroute to target host, requires root access
