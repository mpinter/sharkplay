import pyshark

cap=pyshark.FileCapture('hart_ip.pcap')
for i in range(1000000):
  print(cap[i])

