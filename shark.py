import pyshark
import time

#ip:port:ip:port - lexic. smaller first

class UdpFlow:

    count_threshold=3

    def __init__(self):
        self.reset()

    def reset(self):
        self.echo=[]
        self.send=[]
        self.avg_delay=0
        self.timestamp_sum=0
        self.prev_time=0

    def pushsend(self, packet):
        self.prev_time=time.time()
        self.send.append(packet)
        return 1

    def pushecho(self, packet):
        self.prev_time=time.time()
        self.echo.append(packet)
        return 1

class TcpFlow:

    def __init__(self):
        self.reset()

    def reset(self):
        self.echo=[]
        self.send=[]
        self.avg_delay=0
        self.timestamp_sum=0
        self.prev_time=0
        #init
        self.syn=False
        self.synack=False
        self.active=False
        #close
        self.fin_first=False
        self.fin_second=False
        self.closed=1

    def pushsend(self, packet):
        if (not self.check_continuity(str(packet.tcp.flags),False)):
            return False
        self.send.append(packet)
        return 1

    def pushecho(self, packet):
        if (not self.check_continuity(str(packet.tcp.flags),1)):
            return False
        self.echo.append(packet)
        return 1

    def check_continuity(self, flag, isEcho):
        if ((flag=="0x0004") or (flag=="0x004")):
            return False
        if ((flag=="0x0011") or (flag=="0x011") or (flag=="0x0001") or (flag=="0x001")):
            if (isEcho):
                self.fin_second=1
            else:
                self.fin_first=1
            #return False
        if ((self.fin_first) and (self.fin_second)):
            self.closed=1
            return False
        if (self.closed):
            if ((flag=="0x0002") or ((flag=="0x002"))):
                self.syn=1
                self.closed=False
                return 1
            else:
                return False
        elif (not self.synack):
            if ((flag=="0x0012") or (flag=="0x012")):
                self.synack=1
            return 1
        elif (not self.active):
            if ((flag=="0x0010") or (flag=="0x010") or (flag=="0x0018") or (flag=="0x018")):
                self.active=1
            return 1
        return 1

udp_map={}
tcp_map={}
capture = pyshark.LiveCapture(interface='eth0',bpf_filter='ip')

prev_time=0

#"garbage collect" for inactive UDP flows
def garbagetruck(current_stamp):
    threshold=0
    for key in list(udp_map):
        if (current_stamp-udp_map[key].prev_time>threshold):
            udp_map.pop(key,None)
            print("Killed UDP flow: "+key)
            print("#UPD_flows: "+str(len(udp_map)))

#cap=pyshark.FileCapture('hart_ip.pcap')

#####main#####

counter=0
for packet in capture.sniff_continuously(packet_count=100):
    counter+=1
    if (counter%20==0): 
        print("---still alive - "+str(counter)+", running UDP cleanup---")
        garbagetruck(time.time())
    if (hasattr(packet,"udp")):
        keysrc=packet.ip.src+':'+packet.udp.srcport
        keydst=packet.ip.dst+':'+packet.udp.dstport
        if (keysrc>keydst):
            key=keysrc+'-'+keydst
            if key not in udp_map:
                udp_map[key]=UdpFlow()
                print("New UPD flow: "+key)
                print("#UPD_flows: "+str(len(udp_map)))
            udp_map[key].pushecho(packet)
        else:
            key=keysrc+'-'+keydst
            if key not in udp_map:
                udp_map[key]=UdpFlow()
                print("New UPD flow: "+key)
                print("#UPD_flows: "+str(len(udp_map)))
            udp_map[key].pushsend(packet)
    elif (hasattr(packet,"tcp")):
        flag=str(packet.tcp.flags)
        keysrc=packet.ip.src+':'+packet.tcp.srcport
        keydst=packet.ip.dst+':'+packet.tcp.dstport
        if (keysrc>keydst):
            key=keysrc+'-'+keydst
            if key not in tcp_map:
                f=TcpFlow()
                if (f.pushecho(packet)):
                    tcp_map[key]=f
                    print("New TCP flow: "+key)
                    print("#TCP_flows: "+str(len(tcp_map)))
            else:
                if (not tcp_map[key].pushecho(packet)):
                    print("Finished TCP flow: "+key)
                    print("#TCP_flows: "+str(len(tcp_map)))
                    tcp_map.pop(key,None)
        else:
            key=keysrc+'-'+keydst
            if key not in tcp_map:
                f=TcpFlow()
                if (f.pushsend(packet)):
                    tcp_map[key]=f
                    print("New TCP flow: "+key)
            else:
                if (not tcp_map[key].pushsend(packet)):
                    print("Finished TCP flow: "+key)
                    print("#TCP_flows: "+str(len(tcp_map)))
                    tcp_map.pop(key,None)
    else:
        pass #most likely ICMP