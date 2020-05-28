## Welcome to zippy

DISCLAIMER:
- ZIPPY IS BEING PUBLISHED AS AN INDEPENDENT PROJECT (BY DAREN PRESBITERO) AND IS IN NO WAY ASSOCIATED WITH, ENDORSED, OR SUPPORTED BY PALO ALTO NETWORKS.
- ZIPPY IS HEREBY RELEASED TO THE PUBLIC AS UNSUPPORTED, OPEN SOURCE SOFTWARE

Special thanks to Tom Van Meter, Geoffrey Carlisle, Doug Steele, Steve Weiss, Woody Walton, Matt Isdell, George Balulis, Roman Galeone, and Jonathan Spigler. Zippy makes use of prior work by Mark Harman of [EXOsecure](https://exosecure.com/)

The Build:
The ELK docker "stack" consists of 3 images with the following image tags:
- Elasticsearch "E"
- Logstash "L"
- Kibana "K"

DEPENDENCIES:

** Linux Deps listed below, and instructions, can be found in the installdeps directory

- PIP Installer
	- pip for istalling python packages
- PIP Packages
	- flask (https://pypi.org/project/Flask/#files)
	- flask_restful (https://pypi.org/project/Flask-RESTful/#files)
	- netaddr (https://pypi.org/project/netaddr/#files)

Dependencies Note:  To install packages while offline, download the wheel files from each link above, then use:

`pip install <wheel file name> --user`

To deploy this stack (tested on Ubuntu 18.04.2 and Windows10 with 2/26 Docker)

Create a directory and place the included docker-compose.yml file and all yml and conf files inside of it.  Change the IP address within logstash.conf to your server IP, and change firewall/panorama IP and APIKEY within ztn/app.py to reflect your environment.

You will also need to install `docker-compose` as a pre-requisite.  See: https://docs.docker.com/compose/install/

Also, make sure your virtual memory is set per Elastisearch best practices:
`sysctl -w vm.max_map_count=262144`
Note: To make this setting persistent, do the following command then it will persist across reboots:
`sudo echo vm.max_map_count=262144 >> /etc/sysctl.conf`

### Starting and Operating Zippy

CD to the zippy master directory and chmod 666 esdata directory, then issue the following command:

`docker-compose up -d`

restart a single container

`docker-compose restart <container name>`

use this command to ensure the three containers comprising the "stack" are running:

`docker ps`

NOTE: If you notice a single container is exiting or not running, restart the container with docker-compose command but without the -d option so it'll show interactive messages
Connect to the Kibana portal: (replace localhost with docker server IP if not on host

`http://localhost:5601`

Attach to the shell of a container to get to the command line (you can replace batch with your favorite shell)

`docker-compose exec -u 0 elasticsearch bash`
`docker-compose exec -u 0 logstash bash`
`docker-compose exec -u 0 kibana bash`
** Detach from container using "exit" command

To stop the cluster (all containers), type

`docker-compose down -v`

** Pro-Tip:  

`docker-compose down -v && docker-compose up -d`

Data volumes will persist, so it’s possible to start the cluster again with the same data using docker-compose up`. To destroy the cluster and the data volumes, just type 

`docker-compose down -v`

### NOTE:
Once you have the ELK stack running (all three containers), go into the 'mappings' directory and do the following:
'./create_ecs_pan_mapping_ES7v2'
This command will publish data type mappings into elastic so that, say, your IP address fields show up as IPs...etc.

TROUBLESHOOTING:

Send a test message to UDP port 5550 on logstash

`echo 'test message' | nc -v -u -w 0 localhost 5550`
You can also 'cat' the sample traffic logs to simulate PANOS syslog to logstash
Be aware that there is no timestamp in the first field b/c kibana would dedup the same messages coming in, so ensure you use this command to generate a UNIQUE log

`echo $(date +"%a %b %d %T  %Y") $(cat traffic_log_hostname)`

If the netcat test is successful youll see a message:
Connection to localhost 5550 port [udp/*] succeeded!
If you don't see an output from the nc command it did not connect to the port on logstash - check that your container is up and running
TCPdump from docker host machine to check for incoming syslog from NGFW

`tcpdump -v -i any -n port 5550`
`tcpdump -v -i any -n port 5551`

to see payload of packet and save to log

`tcpdump -nnvvXSs 1514 -i any -n port 5550 > capture.log`

Traffic Generator - For linux only

`genlog <traffic|threat|dataf|.....all>`

Note on genlog.  NetCAT is used in the script and for some reason it sends two blank streams of data to logstash that result in dissect errors when viewing in kibana.  So for everyone legit log that comes in you'll see two failures.  This is only a result of using this script and the dissect failure entries in kibana can be disregarded.

#PANOS COMMANDS TO FORWARD SYSLOGS TO ELK
REPLACE 192.168.54.30 with the IP of your host running docker

set shared log-settings syslog elkstacktraffic server trafficpipe transport UDP  
set shared log-settings syslog elkstacktraffic server trafficpipe port 5550  
set shared log-settings syslog elkstacktraffic server trafficpipe format BSD  
set shared log-settings syslog elkstacktraffic server trafficpipe server 192.168.54.30  
set shared log-settings syslog elkstacktraffic server trafficpipe facility LOG_USER  
set shared log-settings syslog elkstackthreat server threatpipe transport UDP  
set shared log-settings syslog elkstackthreat server threatpipe port 5551  
set shared log-settings syslog elkstackthreat server threatpipe format BSD  
set shared log-settings syslog elkstackthreat server threatpipe server 192.168.54.30  
set shared log-settings syslog elkstackthreat server threatpipe facility LOG_USER  
set shared log-settings syslog elstackurl server urlpipe transport UDP  
set shared log-settings syslog elstackurl server urlpipe port 5552  
set shared log-settings syslog elstackurl server urlpipe format BSD  
set shared log-settings syslog elstackurl server urlpipe server 192.168.54.30  
set shared log-settings syslog elstackurl server urlpipe facility LOG_USER  
set shared log-settings syslog elkstackwf server wfpipe transport UDP  
set shared log-settings syslog elkstackwf server wfpipe port 5553  
set shared log-settings syslog elkstackwf server wfpipe format BSD  
set shared log-settings syslog elkstackwf server wfpipe server 192.168.54.30  
set shared log-settings syslog elkstackwf server wfpipe facility LOG_USER  
set shared log-settings syslog elkstackdataf server datafpipe transport UDP  
set shared log-settings syslog elkstackdataf server datafpipe port 5554  
set shared log-settings syslog elkstackdataf server datafpipe format BSD  
set shared log-settings syslog elkstackdataf server datafpipe server 192.168.54.30  
set shared log-settings syslog elkstackdataf server datafpipe facility LOG_USER  
set shared log-settings syslog elkstackuserid server useridpipe transport UDP  
set shared log-settings syslog elkstackuserid server useridpipe port 5555  
set shared log-settings syslog elkstackuserid server useridpipe format BSD  
set shared log-settings syslog elkstackuserid server useridpipe server 192.168.54.30  
set shared log-settings syslog elkstackuserid server useridpipe facility LOG_USER  
set shared log-settings syslog elkstacktunnel server tunnelpipe transport UDP  
set shared log-settings syslog elkstacktunnel server tunnelpipe port 5556  
set shared log-settings syslog elkstacktunnel server tunnelpipe format BSD  
set shared log-settings syslog elkstacktunnel server tunnelpipe server 192.168.54.30  
set shared log-settings syslog elkstacktunnel server tunnelpipe facility LOG_USER  
set shared log-settings syslog elkstacksystem server systempipe transport UDP  
set shared log-settings syslog elkstacksystem server systempipe port 5558  
set shared log-settings syslog elkstacksystem server systempipe format BSD  
set shared log-settings syslog elkstacksystem server systempipe server 192.168.54.30  
set shared log-settings syslog elkstacksystem server systempipe facility LOG_USER  
set shared log-settings syslog elkstackconfig server configpipe transport UDP  
set shared log-settings syslog elkstackconfig server configpipe port 5559  
set shared log-settings syslog elkstackconfig server configpipe format BSD  
set shared log-settings syslog elkstackconfig server configpipe server 192.168.54.30  
set shared log-settings syslog elkstackconfig server configpipe facility LOG_USER  
set shared log-settings syslog elkstackHIP server HIPpipe transport UDP  
set shared log-settings syslog elkstackHIP server HIPpipe port 5557  
set shared log-settings syslog elkstackHIP server HIPpipe format BSD  
set shared log-settings syslog elkstackHIP server HIPpipe server 192.168.54.30  
set shared log-settings syslog elkstackHIP server HIPpipe facility LOG_USER  
set shared log-settings userid match-list userid send-syslog elkstackuserid  
set shared log-settings userid match-list userid filter "All Logs"  
set shared log-settings system match-list system send-syslog elkstacksystem  
set shared log-settings system match-list system filter "All Logs"  
set shared log-settings config match-list conf send-syslog elkstackconfig  
set shared log-settings config match-list conf filter "All Logs"  
set shared log-settings hipmatch match-list HIPsyslog send-syslog elkstackHIP  
set shared log-settings hipmatch match-list HIPsyslog filter "All Logs"  

#NOTE: you must setup a logging profile Objects>log profile and set your polices to log, also set your zones to log 
set rulebase security rules "Allow All Log to ELK" log-setting "Send to ELK"
