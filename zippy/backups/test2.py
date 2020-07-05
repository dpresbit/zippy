from flask import Flask, render_template, flash, request
from wtforms import Form, TextField, TextAreaField, validators, StringField, SubmitField
from flask_restful import Resource, Api
import requests

# App config
DEBUG = True
app = Flask(__name__)
app.config.from_object(__name__)
app.config['SECRET_KEY'] = '7d441f27d441f27567d441f2b6176a'

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
        apiurl += args['policyname'].strip()
        apiurl += "']&element="

        for akey, aval in args.iteritems():
                if akey != "policyname" : apiurl += "<" + akey.strip() + "><member>" + aval.strip() + "</member></" + akey.strip() + ">"

        # Add any other PAN Policy parameters here
        apiurl += "<service><member>application-default</member></service><option><disable-server-response-inspection>no</disable-server-response-inspection></option><negate-source>no</negate-source><negate-destination>no</negate-destination><disabled>no</disabled><log-start>no</log-start><log-end>yes</log-end>"
        apiurl += "&key=" + apikey

        print apiurl
        # Create policy via PAN XML API
        addPolicyResponse = requests.get(apiurl,verify=False)
        return addPolicyResponse.status_code

class ReusableForm(Form):

#    args = request.args

#    name = TextField('policyname:', validators=[validators.required()])

    @app.route("/", methods=['GET', 'POST'])
    def hello():
        form = ReusableForm(request.form)

        print form.errors

	name = request.form['name']

        if form.validate():
            # Save the comment here.
            flash('Policy ' + request.form['policyname'] + ' created')
        else:
            flash('Error: All the form fields are required. ')
        print "ACTION = " + request.args.get('action')

#        return render_template('test.html', form=form, policyname=request.args.get('policyname'), port=request.args.get('port'), protocol=request.args.get('protocol'), srczone=request.args.get('srczone'), dstzone=request.args.get('dstzone'), srcip=request.args.get('srcip'), dstip=request.args.get('dstip'), application=request.args.get('application'))
        return render_template('test.html', form=form)

#This Front-end API service
#
class addPolicy(Resource):
    def get(self):
        return {'result': panAPI_addPolicy()}

api.add_resource(addPolicy, '/addpolicy')


if __name__ == "__main__":
    app.run("0.0.0.0",port=9999)
