curl -XPUT localhost:9200/_watcher/watch/Vulnerability_browser/_execute -H 'Content-Type: application/json' -d '{ "action_modes" : { "_all" : "force_execute" } }'
curl -XPUT localhost:9200/_watcher/watch/Exploit_browser/_execute -H 'Content-Type: application/json' -d '{ "action_modes" : { "_all" : "force_execute" } }'
sleep 5
curl -XPUT localhost:9200/_watcher/watch/Malware/_execute -H 'Content-Type: application/json' -d '{ "action_modes" : { "_all" : "force_execute" } }'
sleep 30
curl -XPUT localhost:9200/_watcher/watch/C2/_execute -H 'Content-Type: application/json' -d '{ "action_modes" : { "_all" : "force_execute" } }'
sleep 30
curl -XPUT localhost:9200/_watcher/watch/Recon/_execute -H 'Content-Type: application/json' -d '{ "action_modes" : { "_all" : "force_execute" } }'
sleep 60
curl -XPUT localhost:9200/_watcher/watch/Vulnerability_smb/_execute -H 'Content-Type: application/json' -d '{ "action_modes" : { "_all" : "force_execute" } }'
curl -XPUT localhost:9200/_watcher/watch/Exploit_smb/_execute -H 'Content-Type: application/json' -d '{ "action_modes" : { "_all" : "force_execute" } }'
sleep 5
curl -XPUT localhost:9200/_watcher/watch/Lateral/_execute -H 'Content-Type: application/json' -d '{ "action_modes" : { "_all" : "force_execute" } }'
sleep 60
curl -XPUT localhost:9200/_watcher/watch/Exfil/_execute -H 'Content-Type: application/json' -d '{ "action_modes" : { "_all" : "force_execute" } }'
