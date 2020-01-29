# Relies on netaddr module
# pip install netaddr

import csv
import pprint
import sys

from collections import OrderedDict

from netaddr import *

iplist = OrderedDict()

csv_file = sys.argv[1]

def cidrToRange(csv_file):

	with open(csv_file, 'rU') as csvfile:

		cidrNetworks = csv.reader(csvfile, delimiter=' ', quotechar='|', dialect=csv.excel_tab)

		for address in cidrNetworks:

			addressStrings = '\n'.join(address)
			subnet = addressStrings.split(",")

			for ip in IPNetwork(subnet[0]):
				iplist[str(ip)] = ",".join(subnet)

			# Remove first and last IPs (subnet and broadcast)
			iplist.pop(str(IPNetwork(subnet[0]).network), None)
			iplist.pop(str(IPNetwork(subnet[0]).broadcast), None)

	print iplist

	csvfile.close()

	with open('ip-subnet-tags.yaml','w') as data:
		for akey, aval in iplist.iteritems():
			data.write("\""+akey+"\": "+aval+'\r\n')

cidrToRange(csv_file)
