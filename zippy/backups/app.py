#import panAPI
from flask import Flask, request, render_template
from flask_restful import Resource, Api
import requests

app = Flask(__name__)
api = Api(app)
apikey = "LUFRPT1vYTZUYkdtUDdrVWVTR3BnTUNvbGxNend6eDg9TXdZdU1qcVZMakVYcnFOclEyVkdya2ZYWjA2N2FNSW5QQjJGS0hENXBWZ2xvdEp6dGFETVAwWWZvT2pvNTlUNg=="
panIP = "192.168.55.10"
#
#Back-end API calls to PAN Firewall or Panorama
#
def panAPI_addPolicy():
        # Obtain arguments from incoming API request
        # Args for adding a policy include: name,descr,srczone,dstzone,srcip,dstip,user,app,action

        args = request.args
        print (args) # For debugging

        apiurl = "https://" + panIP.strip() + "/api/?type=config&action=set&xpath=/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/rulebase/security/rules/entry[@name='"
        apiurl += args['name'].strip()
        apiurl += "']&element="

        for akey, aval in args.iteritems():
                if akey != "name" : apiurl += "<" + akey.strip() + "><member>" + aval.strip() + "</member></" + akey.strip() + ">"

        # Add any other PAN Policy parameters here
        apiurl += "<service><member>application-default</member></service><option><disable-server-response-inspection>no</disable-server-response-inspection></option><negate-source>no</negate-source><negate-destination>no</negate-destination><disabled>no</disabled><log-start>no</log-start><log-end>yes</log-end>"
        apiurl += "&key=" + apikey

        print apiurl
        # Create policy via PAN XML API
        addPolicyResponse = requests.get(apiurl,verify=False)
	return addPolicyResponse.status_code
#

# Front end Web UI
@app.route("/home")
def home():
#    return render_template('home.html', status=panAPI_addPolicy())
    return render_template('home.html', status="testingthisguyout")

@app.route("/test")
def test():
    return render_template('test.html', status="testitout")

#This Front-end API service
#
class addPolicy(Resource):
    def get(self):
        return {'result': panAPI_addPolicy()}
api.add_resource(addPolicy, '/addpolicy')

if __name__ == '__main__':
     app.run(host='0.0.0.0',port=9999)
