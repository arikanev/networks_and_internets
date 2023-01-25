from scapy.all import *
import sys
import re

def parsePCAP(pkts):
  for pkt in pkts:
    print("Source IP: " + pkt[IP].src)
    print("Destination IP: " + pkt[IP].dst)
    print("Source port: " + str(pkt[TCP].sport))
    print("Destinations port: " + str(pkt[TCP].dport))
    print("Packet Payload: " + str(pkt[TCP].show(dump=True)))	

def parseReferer(ip, pkts):

  links = []

  for pkt in pkts:
    if str(pkt[IP].src) == str(ip):
      r = re.search('Referer: (.*)', pkt[TCP].show(dump=True))
      if r is not None:
        links.append(r.group(1).split('\\')[0])

  return links


def findOtherIPs(pkts):
  IPdict = {}
  user = 0
  for pkt in pkts:
    if pkt[IP].dst.startswith('10.3.0'):
      if pkt[IP].dst not in IPdict.values():
          IPdict.update({"User " + str(user):pkt[IP].dst})
          user+=1
  print(IPdict)
  return IPdict

def parsePCAP_mail(ip, pkts):
  for pkt in pkts:
    if str(pkt[IP].src) == str(ip):
      if pkt[TCP].dport == 143 or pkt[TCP].dport == 25:
        if type(pkt[TCP].payload) is not scapy.packet.NoPayload:
          with open(ip + 'mail.txt', 'a') as f:
            f.write(pkt[TCP].show(dump=True))

def generate_mail_files(ip_list, pkts):
  for ip in ip_list:
    print(ip)
    parsePCAP_mail(ip, pkts)

def get_referer_links(ip_list, pkts):
  links_dict = {}
  for ip in ip_list:
    links_dict.update({ip: parseReferer(ip, pkts)})
  print(links_dict)
  return links_dict

if __name__ == "__main__":
  if len(sys.argv) < 2:
    print("usage: python lab3.py [pcap]")
    sys.exit()	 
  pcap = rdpcap(sys.argv[1])
  pcap = [pkt for pkt in pcap if TCP in pkt]
  parsePCAP(pcap)
  ip_dict = findOtherIPs(pcap)
  ip_list = ip_dict.values()
  generate_mail_files(ip_list, pcap)
  get_referer_links(ip_list, pcap)


