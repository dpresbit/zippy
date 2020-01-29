# Create a new incidents index and place all mappings in there.
# Note: If fail to add because of duplicate index, ensure your WATCHER is DEACTIVATED first, then delete the index from ELASTICSEARCH>INDEX MANAGEMENT

curl -XPUT localhost:9200/_template/alerts -H 'Content-Type: application/json' -d '
{
  "index_patterns": ["alerts-*"],
  "mappings" : {
      "doc" : {
        "properties" : {
          "alert_time" : {
            "type" : "date"
          },
          "alert_uid" : {
            "type" : "text",
            "fields" : {
              "keyword" : {
                "type" : "keyword",
                "ignore_above" : 256
              }
            }
          },
          "destination" : {
            "properties" : {
              "ip" : {
                "type" : "ip"
              },
              "port" : {
                "type" : "long"
              },
              "zone" : {
                "type" : "text",
                "fields" : {
                  "keyword" : {
                    "type" : "keyword",
                    "ignore_above" : 256
                  }
                }
              }
            }
          },
          "details" : {
            "type" : "text",
            "fields" : {
              "keyword" : {
                "type" : "keyword",
                "ignore_above" : 256
              }
            }
          },
          "network" : {
            "properties" : {
              "application" : {
                "type" : "text",
                "fields" : {
                  "keyword" : {
                    "type" : "keyword",
                    "ignore_above" : 256
                  }
                }
              }
            }
          },
          "owner" : {
            "type" : "text",
            "fields" : {
              "keyword" : {
                "type" : "keyword",
                "ignore_above" : 256
              }
            }
          },
          "severity" : {
            "type" : "long"
          },
          "source" : {
            "properties" : {
              "ip" : {
                "type" : "ip"
              },
              "port" : {
                "type" : "long"
              },
              "zone" : {
                "type" : "text",
                "fields" : {
                  "keyword" : {
                    "type" : "keyword",
                    "ignore_above" : 256
                  }
                }
              }
            }
          },
          "type" : {
            "type" : "text",
            "fields" : {
              "keyword" : {
                "type" : "keyword",
                "ignore_above" : 256
              }
            }
          }
        }
      }
    }
}
'
