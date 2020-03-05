from flask import Flask, render_template, request
from flask_restful import Resource, Api
import requests
import xml.etree.ElementTree as ET

# App config
app = Flask(__name__)
app.config['SECRET_KEY'] = '7d441f20d222c27567d889f2b6175b'

api = Api(app)

#FW
#isFirewall = True
#apikey = "LUFRPT1jeXF1Z2dEWE01YkU4OVZrekVnY2p5NUdCUFk9MnpWTXNwb21uc2diRVZrQVQvdGJlaVlmTmNPMURrMVBJMFhNQ1R4em9WTkVCSVg1NWlxSXBCV25ac0lSS0Y3SQ=="
#panIP = "192.168.55.10"
#vSys = "vsys1"

#PANORAMA
isFirewall = False
apikey = "LUFRPT1UTm52RWNPWW1YbE5UbUhPMTFrcGh0ZHVmQ1E9Q2p2NWtHcnVkRjJwUGI0bW9rOGZUdU1Na0YzTUlkS1UvcTdTWC9HZ1drWnFGK1VUcGdlOEJIL0dtRE5HVHBLbQ=="
panIP = "10.70.219.54"
# For Panorama, if panShared = True, then DeviceGroup will be ignored
# and policy will be placed within the SHARED rulebase for all FWs
#deviceGroup = "All"
#panShared = False
# FUTURE: AUTO DETECTION OF DEVICE GROUP
# Step 1 - Obtain DG ID from Traffic Log (DeviceGroup Hierarchy 1)
# Step 2 - Query Panorama API to look up DG name based on ID.

#
#Back-end API calls to PAN Firewall or Panorama
#
def panAPI_addPolicy():

	context = ""
	addsvcresult = ""
        args = request.args
	DgName = ""
	# Debug print all args in JSON format to the browser
#	return args

        apiurl = "https://" + panIP.strip() + "/api/?type=config&action=set&xpath=/config/devices/entry[@name='localhost.localdomain']/"

	if isFirewall:
		apiurl += "vsys/entry[@name='" + vSys + "']/rulebase/security/rules/entry[@name='"
	else: #is Panorama, check for DeviceGroup ID
		DgName = getDgName(args['dgid'])
		if DgName != "":
			apiurl += "device-group/entry[@name='" + DgName  + "']/pre-rulebase/security/rules/entry[@name='"
		else: #Got back blank DG name, so place into SHARED Rules
			apiurl = "https://" + panIP.strip() + "/api/?type=config&action=set&xpath=/config/shared/pre-rulebase/security/rules/entry[@name='"

        apiurl += args['policyname'].strip()
        apiurl += "']&element="
	apiurl += "<description>" + args['description'] + "\nService Fingerprint: " + args['fp_service'] + "</description>"

	applist = []

        for akey, aval in args.iteritems():
		# Do not parse certain field values, already done or N/A
		if akey != "policyname" and akey!= "docid" and akey!= "description" and akey != "fp_service" and akey != "allapps" and akey != "incldeps":
			# If service is NOT application-default, then normalize value
			if akey == "service":
				if "application-default" in aval:
					# Single application, or pre-processed list changed to appdefault
					# Check if deps enabled, and if yes then add deps to list
					# note: incldeps already includes the selected application
					if 'incldeps' in args: applist = args['incldeps'].split(",")
				else:
					# Either a list of related apps OR service port (from logs)
					if "," in aval:
						# This is a list, so create list array for further processing
						# If deps selected, add to the list
						if 'incldeps' in args:
							# include all apps and deps
							# note: allapps is already deduped from HTML form
							applist = args['allapps'].split(",")
						else:
							# dont include deps, just the apps in the list
							applist = aval.split(",")
						# Change value to appdefault for all apps in list
						aval = "application-default"
					else:
						# This is a service entry (non-appdefault) so add the service
						aval.replace("(From Traffic Log)","")
						splitpp=aval.split("-")
						addsvcresult = "Add Service " + aval + ". Result: " + panAPI_addService(splitpp[0], splitpp[1])
			# Make sure source-user has a value, or do not add to query
			if (akey != "source-user") or (akey == "source-user" and aval != ""):

				apiurl += "<" + akey.strip() + ">"

				if (akey == "application"):
					print applist
					if applist:
						# application list exists, so add each member
						for a in applist: apiurl += "<member>" + a + "</member>"
					else:
						# individual application entry
						apiurl += "<member>" + aval + "</member>"
				else:
					# action and description tags do NOT have <member>
					if akey != "action" and akey!= "description": apiurl += "<member>"
					# 0.0.0.0 really means ANY
					if aval == "0.0.0.0/0": aval = "any"
					apiurl += aval
					if akey != "action" and akey!= "description": apiurl += "</member>"

				apiurl += "</" + akey.strip() + ">"

        # Add any other PAN Policy parameters here
        apiurl += "<log-start>no</log-start><log-end>yes</log-end>&key=" + apikey

        print "ADDPOLICY URL: " + apiurl

        # Create policy via PAN XML API
        addPolicyResponse = requests.get(apiurl, verify=False)
	print "ADDPOLICY RESULT: " + str(addPolicyResponse.status_code)

	if "success" in addPolicyResponse.text:
		if not applist:
#			context = "to Firewall "
#			if not isFirewall:
#				if panShared:
#					context = "to Panorama-Shared "
#				else:
#					context = "to Panorama-DG [" + deviceGroup + "]"
			r = update_ack(args["docid"],"True","Interesting: Policy Applied " + context + "with Name:" + args['policyname'].strip() + "]",",".join(applist))
		else:
			r = update_ack(args["fp_service"],"True","Interesting: Policy Applied " + context + "with Name:" + args['policyname'].strip() + "]",",".join(applist))
		return addsvcresult + "Successfully applied policy Name:" + args['policyname'].strip() + context + " with IP:" + panIP
	else:
		return addsvcresult + "Could not apply policy to " + panIP + "\n Response: \n" + addPolicyResponse.text

def panAPI_addService(svcproto, svcport):

	# https://<FWIP>/api/?type=config&action=set&xpath=/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/service/entry[@name='service-port-tcp-9999']&element=<protocol><tcp><port>9999</port></tcp></protocol><description>zippieservice</description>&key=<APIKEY>

	svcname = svcproto + "-" + svcport

	apiurl = "https://" + panIP.strip() + "/api/?type=config&action=set&xpath=/config/devices/entry[@name='localhost.localdomain']/"

	if isFirewall:
		apiurl += "vsys/entry[@name='" + vSys + "']/service/entry[@name='"
	else:
		apiurl += "device-group/entry[@name='" + deviceGroup  + "']/service/entry[@name='"

	apiurl += svcname
	apiurl += "']&element=<protocol><" + svcproto + ">"
	apiurl += "<port>" + svcport + "</port></" + svcproto + "></protocol>"
	apiurl += "<description>From Traffic Log Analysis</description>&key="
	apiurl += apikey

	print "ADDSERVICE URL: \n" + apiurl

        addServiceResponse = requests.get(apiurl, verify=False)

        print "ADDSERVICE RESULT: " + addServiceResponse.text

        if "success" in addServiceResponse.text:
                return "Successfully added service [" + svcname + "]"
        else:
                return "Could not add service to " + panIP + "\n\nResponse:\n" + addServiceResponse.text

def update_ack(docid, value, action, applist=""):
# FUTURE
# To update all docs with subnet/CIDR
#
# payload = { "query" : { "term" : { "source.subnet.keyword" : "192.168.65.0/24" } },"script" : { "source" : "ctx._source.Acknowledged = 'true';ctx['_source']['Action Log'] = 'test'" } }
# r = requests.post("http://localhost:9200/traffic.apps/_update_by_query/", json=payload)


	arsplist = ""

	print "\n\nAPPLIST: " + str(applist) + "\n\n"

	payload = {"doc" : {"Acknowledged":value,"Action Log":action} }

	if "," in applist:
		applist = applist.split(",")
		for app in applist:
			a = requests.get("http://localhost:9200/traffic.apps/_search?q=fingerprint.service:" + docid + " AND network.application:" + app + "&_source_includes=fingerprint.app", verify=False)
			print "ELASTIC QUERY: http://localhost:9200/traffic.apps/_search?q=fingerprint.service:" + docid + " AND network.application:" + app + "&_source_includes=fingerprint.app"
			print a.text
			arsplist = a.json()
        		if "error" in arsplist or str(arsplist['hits']['total']['value']) == "0": continue
			curapp = arsplist['hits']['hits'][0]['_source']['fingerprint.app']
			r = requests.post("http://localhost:9200/traffic.apps/_update/"+curapp, json=payload)
	else:
		r = requests.post("http://localhost:9200/traffic.apps/_update/"+docid, json=payload)

        print "GET APP LIST: " + str(arsplist)

	# Need to change this from 200 OK to looking at JSON response code instead
	if r.status_code == 200:
		return "Successfully updated document with Acknowledge = " + value + " with Action Log = " + action
	else:
		return "unsuccessful, please try again" + " Result: " + r.text

def get_list(fp_service):

	# retrieve from elastic the app list based on service fingerprint
	# source_includes states what field(s) we want back - just the list
	apiurl = "http://localhost:9200/traffic.appslist/_search?q=fingerprint.service:"+fp_service+"&_source_includes=network.application"
	print "GET APP LIST URL: " + apiurl

	r = requests.get(apiurl,verify=False)
	rlist = r.json()
	if "error" in rlist: return ""
	if str(rlist['hits']['total']['value']) == "0": return ""

	print "GET APP LIST: " + str(rlist)

	return rlist['hits']['hits'][0]['_source']['network.application']
	#if r.status_code == 200:
	#	return "Successfully updated document with Acknowledge = " + value + " with Action Log = " + action
	#else:
	#	return "unsuccessful, please try again" + " Result: " + r.text

def getDgName(DgID):

	# If setting is non-panorama (direct to firewall) return blank
	if isFirewall: return ""

	# Not a firewall, set to Panorama
	if DgID == "" or DgID == "0": return "Shared"

	apiurl = "https://" + panIP + "/api/?type=op&cmd=<show><dg-hierarchy></dg-hierarchy></show>"
	apiurl += "&key=" + apikey

	print "Get DGH1 Name: ID = " + DgID

        DgResponse = requests.get(apiurl, verify=False)

        if "success" in DgResponse.text:
		root = ET.fromstring(DgResponse.content)
		dgList = root.find('result').find('dg-hierarchy').findall('dg')
		for dg in dgList:
			if dg.attrib['dg_id'] == DgID:
                		print "Found Name for DGH1 ID [" + DgID + "]: Name = " + dg.attrib['name'] + "\nResponse: " + DgResponse.text
				return dg.attrib['name']
                # If not return yet, DG name not found - even if API response okay
		print "Did not find DG name for ID " + DgID + "\nResponse: " + DgResponse.text
		return "Shared"
	else:
		# No success in API
		print "Error in API Response while querying for DG ID " + DgID + " \nResponse: " + DgResponse.text
		return "Shared"
# Front-end web form and network map
#
@app.route("/")
def test():
	applist = get_list(request.args.get("fp_service"))
	dgname = getDgName(request.args.get("dgid"))
	return render_template('test.html', docid=request.args.get("docid"), appdefault=request.args.get('appdefault'), service=request.args.get('service'), srczone=request.args.get('srczone'), desired_srczone=request.args.get('desired_srczone'), dstzone=request.args.get('dstzone'), desired_dstzone=request.args.get('desired_dstzone'), srcip=request.args.get('srcip'), srcnet=request.args.get('srcnet'), desired_srctag=request.args.get('desired_srctag'), srcuser=request.args.get('srcuser'), dstip=request.args.get('dstip'), dstnet=request.args.get('dstnet'), desired_dsttag=request.args.get('desired_dsttag'), application=request.args.get('application'), apprisk=request.args.get('apprisk'),  fp_service=request.args.get('fp_service'), appdefaultpps=request.args.get('appdefaultpps'), dstport=request.args.get('dstport'), applist=applist, appdeps=request.args.get('appdeps'), dgid=request.args.get('dgid'), dgname=dgname)

@app.route("/map.html")
def map():
	return render_template('map.html')

# Front-end API endpoints for /addpolicy and /ack
# These API endpoints are called through SUBMIT of the zippy front-end form
#
class addPolicy(Resource):
    def get(self):
        return {'result': panAPI_addPolicy()}

api.add_resource(addPolicy, '/addpolicy')

class ack(Resource):
    def get(self):
	return update_ack(request.args.get('docid'),request.args.get('value'),request.args.get('action'))

api.add_resource(ack, '/ack')

class DgLookup(Resource):
    def get(self):
        return getDgName(request.args.get('dgid'))

api.add_resource(DgLookup, '/dglookup')

if __name__ == "__main__":
    app.run("0.0.0.0",port=9999,debug=True)
