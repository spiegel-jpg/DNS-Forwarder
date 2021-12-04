import argparse
import socket
import os
import base64
from requests.api import request
from scapy.all import *
from builtins import bytes
import requests

parser = argparse.ArgumentParser(description='DNS forwarder with Domain Blocking and DOH Capabilities.')
parser.add_argument('-d', metavar = 'DST_IP', dest='dst_ip' ,help='Destination DNS server IP.')
parser.add_argument('-f', metavar='DENY_LIST_FILE', dest='deny_file', help='Files containing domains to block. Please enter entire path.')
parser.add_argument('-l', metavar='LOG_FILE', dest='log_file', help='Append-only log file. Please enter entire path.')
parser.add_argument('--doh', dest='doh', action='store_true',help='Use default upstream DoH server.')
parser.add_argument('--doh_server', metavar='DOH_SERVER', dest='doh_server', help='Use this upstream DoH server.')
args = parser.parse_args()

# Creating Server socket and binding to address and port 
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
name = socket.gethostname()
host = socket.gethostbyname(name)
print(host)
sock.bind(host, 53)

while 1:
    #Listening to the client and then receiving data, decoding the data using scapy and finding out the domain name and the type of request.
    request_data, addr = sock.recvfrom(512)
    dns_request = DNS(request_data)
    domain_name = dns_request[DNS].qd.qname.decode()[:-1]
    request_type = dns_request[DNS].qd.qtype
    file_object = open(args.deny_file, "r")
    converted_list = []
    lines = file_object.readlines()
    for line in lines:
        converted_list.append(line.strip())
    if domain_name not in converted_list:
        #Client_socket forwarding the query to the DNS resolver depending on the parameter passed, receiving back data and updating log file.
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        if args.dst_ip and (args.doh or args.doh_server):
            print('Please input correct parameters to run the program. Cannot use both, normal DNS query and DoH.')
            break
        elif args.doh and args.doh_server:
            print('Please input correct parameters to run the program. Cannot use both, default DoH upstream and user specified DoH upstream server.')
            break
        elif args.dst_ip:
            host = args.dst_ip
            port = 53
            client_socket.sendto(request_data,(host ,port))
            response_data, server = client_socket.recvfrom(1024)
            sock.sendto(response_data, addr)
            print('Response sent successfully to the client!')
            if os.path.exists(args.log_file):
                    log_file_object = open(args.log_file, "a")
                    log_file_object.write(domain_name + ' ' + str(request_type) + ' ' + 'ALLOW')
                    log_file_object.write('\n')
                    log_file_object.close()
        elif args.doh:
                    packet1 = bytes(DNS(rd = 1, qd = DNSQR(qname = domain_name, qtype = request_type)))
                    packet2 = base64.b64encode(packet1).decode().rstrip('=')
                    query = "https://8.8.8.8/dns-query?dns="+packet2 #Using 8.8.8.8 as default DoH Server
                    r = requests.get(query)
                    build1 = DNS(r.content)
                    response_pack = DNS(id=dns_request[DNS].id, qd = dns_request[DNS].qd, ar = build1[DNS].ar, an = build1[DNS].an, ra = build1[DNS].ra,
                    rd = build1[DNS].rd, qr = build1[DNS].qr, qdcount = build1[DNS].qdcount, ancount = build1[DNS].ancount, nscount = build1[DNS].nscount, rcode = build1[DNS].rcode, arcount = build1[DNS].arcount)
                    send_packet = response_pack.build()
                    sock.sendto(send_packet, addr)
                    print('Response sent successfully to the client!')
                    if os.path.exists(args.log_file):
                        log_file_object = open(args.log_file, "a")
                        log_file_object.write(domain_name + ' ' + str(request_type) + ' ' + 'ALLOW')
                        log_file_object.write('\n')
                        log_file_object.close()
        elif args.doh_server:
                    packet3 = bytes(DNS(rd = 1, qd = DNSQR(qname = domain_name, qtype = request_type)))
                    packet4 = base64.b64encode(packet3).decode().rstrip('=')
                    query = "https://" + args.doh_server +"/dns-query?dns="+packet4
                    r = requests.get(query)
                    build1 = DNS(r.content)
                    response_pack = DNS(id=dns_request[DNS].id, qd = dns_request[DNS].qd, ar = build1[DNS].ar, an = build1[DNS].an, ra = build1[DNS].ra,
                    rd = build1[DNS].rd, qr = build1[DNS].qr, qdcount = build1[DNS].qdcount, ancount = build1[DNS].ancount, nscount = build1[DNS].nscount, rcode = build1[DNS].rcode, arcount = build1[DNS].arcount)
                    send_packet = response_pack.build()
                    sock.sendto(send_packet, addr)
                    print('Response sent successfully to the client!')
                    if os.path.exists(args.log_file):
                        log_file_object = open(args.log_file, "a")
                        log_file_object.write(domain_name + ' ' + srt (request_type) + ' ' + 'ALLOW')
                        log_file_object.write('\n')
                        log_file_object.close()    
    else:
        dns_nxd_response = DNS(id = dns_request[DNS].id, qd = dns_request[DNS].qd,  ar = dns_request[DNS].ar, ra = 1, rd = 1, qr = 1, 
                qdcount = 1, ancount = 0, nscount = 0, rcode = 3, arcount = 1)
        sock.sendto(dns_nxd_response.build(), addr)  
        if os.path.exists(args.log_file):
            log_file_object = open(args.log_file, "a")
            log_file_object.write(domain_name + ' ' + str(request_type)+ ' ' + 'DENY')
            log_file_object.write('\n')
            log_file_object.close()
