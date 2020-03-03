import requests

payload = { "query" : { "term" : { "source.subnet.keyword" : "192.168.65.0/24" } },"script" : { "source" : "ctx._source.Acknowledged = 'true';ctx['_source']['Action Log'] = 'test'" } }

r = requests.post("http://localhost:9200/traffic.apps/_update_by_query", json=payload)

print r.content
