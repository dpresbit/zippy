import socket
UDP_IP = "127.0.0.1"
UDP_PORT = 5551
MESSAGE = "<13>Mar 13 18:46:34 mah1mgmt.XStratum.net 1,2019/03/13 18:46:34,011901000306,THREAT,file,2304,2019/03/13 18:46:34,192.168.57.16,184.25.157.49,192.168.54.253,184.25.157.49,log everything,xstratum.net\charman,,steam,vsys1,tun,untrust,tunnel.1,ethernet1/1,elk_stack,2019/03/13 18:46:34,73809,2,57608,80,51757,80,0x402000,tcp,alert,\"5d0b93d4ee913cae7910a738561f769f34b19367.txt.gz\",GZIP(52014),low-risk,low,server-to-client,1437717,0x2000000000000000,192.168.0.0-192.168.255.255,United States,0,,0,,,1,,,,,,,,0,0,0,0,0,,mah1mgmt,,,,,0,,0,,N/A,unknown,AppThreat-8122-5298,0x0,0,4294967295,,,3fdfb5d7-3a1c-41db-b3b9-16a847eb815c,0"
print "UDP target IP:", UDP_IP
print "UDP target port:", UDP_PORT
print "message:", MESSAGE
sock = socket.socket(socket.AF_INET, # Internet
                     socket.SOCK_DGRAM) # UDP
sock.sendto(MESSAGE, (UDP_IP, UDP_PORT))
