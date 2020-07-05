import csv
from collections import OrderedDict
import requests
import xml.etree.ElementTree as ET
import os
# Pulls the applipedia list from your NGFW
# https://<panIP>/api/?type=config&action=get&xpath=/config/predefined/application&key=<APIKEY>

panIP = os.environ['panIP']
apikey = os.environ['apikey']

#
#Back-end API calls to PAN Firewall or Panorama
#
def main():

	apiurl = "https://" + panIP + "/api/?type=config&action=get&xpath=/config/predefined/application&key=" + apikey
	r = requests.get(apiurl, verify=False)

	if not r:
		print("ERROR CONNECTING TO FW " + panIP + "\r\nExiting with Error")
		return

	# saving the xml file
	with open('raw_applipedia.xml', 'wb') as f:
		f.write(r.content)

	root = ET.parse('raw_applipedia.xml').getroot()

    	# create empty list for apps
	ppslist = []
	appsdict = OrderedDict()
	apprisk = ""
	deps = ""

	for appentry in root.findall('result/application/entry'):
		ppslist = []
		apprisk = ""
		apprisk = appentry.find('risk').text
		depslist = []
		deps = appentry.find('use-applications')

		for defaultpps in appentry:
			if defaultpps.tag == "default":
				for ppsentry in defaultpps[0]:
					# PPS Entry looks like this TCP/80,443
					protocol=ppsentry.text[:3]
					ports = ppsentry.text
					ports = ports.replace(protocol+"/","")
					p=""
					for e in ports.split(","):
						p = protocol + "/" + e
						ppslist.append(p)
				break
		if deps:
			for d in deps:
				depslist.append(d.text)

		if ports != "":	appsdict[appentry.get('name')] = '[' + ','.join(depslist) + '],' + apprisk + ',[' + ','.join(ppslist) + ']'
		ports = ""

	with open('applipedia.yaml','w') as data:
		for akey, aval in appsdict.items():
			data.write("\""+akey+"\": \""+aval+'\"\r\n')

	print("DONE GENERATING APPLIPEDIA DICTIONARY YML FILE")
if __name__ == "__main__":
	# calling main function
	main()
