## Welcome to zippy

DISCLAIMER:
- ZIPPY IS BEING PUBLISHED AS AN INDEPENDENT PROJECT (BY DAREN PRESBITERO) AND IS IN NO WAY ASSOCIATED WITH, ENDORSED, OR SUPPORTED BY PALO ALTO NETWORKS.
- ZIPPY IS HEREBY RELEASED TO THE PUBLIC AS UNSUPPORTED, OPEN SOURCE SOFTWARE

###The Build:

The ELK docker "stack" consists of 3 images with the following image tags:
- Elasticsearch "E"
- Logstash "L"
- Kibana "K"

The fourth container contains the Zippy application within an Alpine Linux container

To build the zippy container, use the command `docker build -t zippy:master .` from the main directory

###REQUIREMENTS AND DEPS:

** A host machine running docker and  
- curl
- nc (NetCat)

### DEPLOY THE FULL CONTAINER STACK

NOTE: Make sure you've compiled the zippy container per the above instructions.  You may also import pre-built containers for all four stacks from a saved image tar file.  This is especially useful for deploying the stack in air-gapped networks.

Deploy the tar file on the air-gapped machine

Clone this repo and customize the settings for your environment.
  
You will need install `docker-compose` as a pre-requisite so you can run this full container stack.  See: https://docs.docker.com/compose/install/

### Starting and Operating Zippy

CD to the zippy master directory and chmod 777 `esdata` directory or change owner to user:`elasticsearch`, then issue the following command:

`docker-compose up -d`

Check on Kibana by going to `http://<HostIP>:5601`

** Restart a single container

`docker-compose restart <container name>`

Use this command to ensure that the four containers comprising the "stack" are running:

`docker ps`

Verify logs are coming into elastic and seen in Kibana by going into setting/gear icon and ElasticSearch>Index Management.

You'll also have to go into Kibana under Settings and create an index pattern for each of the indices (apps, applist, peers)

Once the Kibana index pattern is created, go into the MARK INTERESTING and MARK UNINTERESTING text fields and change them to URL fields with LABEL TEMPLATE to depict whatever "icon" you wish to show.  I prefer to use ☑ (U+2611) for Interesting and ☒ (U+2612) for Uninteresting

** How to get shell access to any container

Attach to the shell of a container to get to the command line:

To stop the full stack (all containers), type

`docker-compose down -v`

** Pro-Tip:

`docker-compose down -v && docker-compose up -d`

Data volumes will persist, so it’s possible to start the cluster again with the same data using docker-compose up`. To destroy the cluster and the data volumes, just type 

`docker-compose down -v`

TROUBLESHOOTING:

`tcpdump -v -i any -n port 5550`  

to see payload of packet and save to log

`tcpdump -nnvvXSs 1514 -i any -n port 5550`

## SECURITY
To implement credentialed login access, and SSL, follow the XPACK-SECURITY documentation beginning here:   https://www.elastic.co/guide/en/elasticsearch/reference/current/get-started-built-in-users.html

## PANOS COMMANDS TO FORWARD SYSLOGS TO ELK STACK  
NOTE: Replace '192.168.54.30' with the IP of your host running docker then copy/paste these commands into your NGFW.  Some modification might be needed for Panorama imports.  Then attach the log forwarding object to the ANY/ANY policy for baselining traffic flows.

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

### NOTE: you must setup a logging profile Objects>log profile and set your polices to log, also set your zones to log 
set rulebase security rules "Allow All Log to ELK" log-setting "Send to ELK"
