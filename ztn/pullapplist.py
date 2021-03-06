import csv
from collections import OrderedDict
import requests
import xml.etree.ElementTree as ET
# Pulls the applipedia list from your NGFW
# https://<panIP>/api/?type=config&action=get&xpath=/config/predefined/application&key=<APIKEY>

#apikey = "LUFRPT10b21yUG9jall3TG5GNnVYWFJOcnBsRCtidFE9a1k1c2pidWNqSklrbkpzVTZRSzhGbSs1MXFybm1FNnpFREVvbUJpTERIMHJSbU4wUWVPOEJoVVQ0ZXoxaXdYUQ=="
apikey = "LUFRPT1jeXF1Z2dEWE01YkU4OVZrekVnY2p5NUdCUFk9MnpWTXNwb21uc2diRVZrQVQvdGJlaVlmTmNPMURrMVBJMFhNQ1R4em9WTkVCSVg1NWlxSXBCV25ac0lSS0Y3SQ=="
panIP = "192.168.55.10"

#
#Back-end API calls to PAN Firewall or Panorama
#
def main():

        apiurl = "https://" + panIP + "/api/?type=config&action=get&xpath=/config/predefined/application&key=" + apikey
	r = requests.get(apiurl, verify=False)

	if not r:
		print "ERROR CONNECTING TO FW " + panIP + "\r\nExiting with Error"
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
#					print appentry.get('name') + ":" + ppsentry.text
					# PPS Entry looks like this TCP/80,443
					#print "ppsentry: " + ppsentry.text
					protocol=ppsentry.text[:3]
					#print "protocol extracted: " + protocol
					ports = ppsentry.text
					ports = ports.replace(protocol+"/","")
					#print "ports extracted: " + ports
					p=""
					for e in ports.split(","):
						p = protocol + "/" + e
						ppslist.append(p)
#						print "Applipedia Entry [" + appentry.get('name') + "]: " + p
				break
#		print apprisk
		if deps:
			for d in deps:
				depslist.append(d.text)
#			print appentry.get('name') + ' ' + ','.join(depslist)

		if ports != "":	appsdict[appentry.get('name')] = '[' + ','.join(depslist) + '],' + apprisk + ',[' + ','.join(ppslist) + ']'
#		print appsdict[appentry.get('name')]
		ports = ""
#	print appsdict

        with open('applipedia.yaml','w') as data:
                for akey, aval in appsdict.iteritems():
                        data.write("\""+akey+"\": \""+aval+'\"\r\n')

	print "DONE GENERATING APPLIPEDIA DICTIONARY YML FILE"
if __name__ == "__main__":
    # calling main function
    main()
