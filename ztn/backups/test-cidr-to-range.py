# Relies on netaddr module
# pip install netaddr

#!/usr/bin/env python
from netaddr import IPNetwork
import sys

for ip in IPNetwork(sys.argv[1]):
	print '%s' % ip
