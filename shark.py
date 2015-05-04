import pyshark

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
        self.prev_time=packet.sniff_timestamp
        self.send.append(packet)
        return 1

    def pushecho(self, packet):
        self.prev_time=packet.sniff_timestamp
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

        #todo - RST - remove from 
    def check_continuity(self, flag, isEcho):
        if ((flag=="0x0004") or (flag=="0x004")):
            print("WE GOT RESET!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
            return False
        if ((flag=="0x0011") or (flag=="0x011") or (flag=="0x0001") or (flag=="0x001")):
            print("WE GOT FIN!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
            if (isEcho):
                self.fin_second=1
            else:
                self.fin_first=1
        if ((self.fin_first) and (self.fin_second)):
            print("BOTH FINS!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
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
        #at this point active, check for closing
        return 1

udp_map={}
tcp_map={}
capture = pyshark.LiveCapture(interface='eth0',bpf_filter='ip and tcp')

prev_time=0

cap=pyshark.FileCapture('hart_ip.pcap')

#####main#####

#for packet in capture.sniff_continuously(packet_count=300000):
for i in range(116):
    packet=cap[i]
    if (hasattr(packet,"udp")):
        print("UDP")
        keysrc=packet.ip.src+packet.udp.srcport
        keydst=packet.ip.dst+packet.udp.dstport
        if (keysrc>keydst):
            key=keydst+keysrc
            if key not in udp_map:
                udp_map[key]=UdpFlow()
            udp_map[key].pushecho(packet)
            print(key)
        else:
            key=keysrc+keydst
            if key not in udp_map:
                udp_map[key]=UdpFlow()
            udp_map[key].pushsend(packet)
            print(key)
        print(len(udp_map))
    elif (hasattr(packet,"tcp")):
        print("TCP")
        print(packet)
        print(len(tcp_map))
        flag=str(packet.tcp.flags)
        if ((flag=="0x0011") or (flag=="0x011") or (flag=="0x0001") or (flag=="0x001")):
            print("FIN??!!")
        keysrc=packet.ip.src+packet.tcp.srcport
        keydst=packet.ip.dst+packet.tcp.dstport
        if (keysrc>keydst):
            key=keydst+keysrc
            if key not in tcp_map:
                f=TcpFlow()
                if (f.pushecho(packet)):
                    tcp_map[key]=f
            else:
                if (not tcp_map[key].pushecho(packet)):
                    print("SHOULD POP!!!!!!!!!!!!!!!")
                    tcp_map.pop(key,None)
        else:
            key=keysrc+keydst
            if key not in tcp_map:
                f=TcpFlow()
                if (f.pushsend(packet)):
                    tcp_map[key]=f
            else:
                if (not tcp_map[key].pushsend(packet)):
                    print("SHOULD POP!!!!!!!!!!!!!!!")
                    tcp_map.pop(key,None)
    else:
        print("Error - no tcp or udp layer on following packet:")
        print(packet)



def testfunc():
    for packet in capture.sniff_continuously(packet_count=300):
        try:
            print("=======")
            print(packet.sniff_time)
            if (prev_time==0):
                prev_time=packet.sniff_time
            else:
                prev_time=packet.sniff_time-prev_time
            print(prev_time)
            print(packet.sniff_timestamp)
            print(packet.ip.src)
            print(packet.ip.dst)
            try:
                print(packet.udp.srcport)
                print(packet.udp.dstport)
            except AttributeError:
                try:
                    print(packet.tcp.srcport)
                    print(packet.tcp.dstport)
                except AttributeError:
                    print("???!!!!!")
                    #print(dir(packet))
        except AttributeError:
            print("Error!")
        try:
            print(packet.ssh)
            print(packet)
        except AttributeError:
            pass

def testfunc2():
    try:  
        print(packet)
        if (prev_time==0):
            prev_time=packet.sniff_time
        else:
            prev_time=packet.sniff_time-prev_time
        print(prev_time)
        print(packet.sniff_timestamp)
        print(packet.ip.src)
        print(packet.ip.dst)
        try:
            print(packet.udp.srcport)
            print(packet.udp.dstport)
        except AttributeError:
            try:
                print(packet.tcp.srcport)
                print(packet.tcp.dstport)
            except AttributeError:
                print("???!!!!!")
                #print(dir(packet))
    except AttributeError:
        print("Error!")
    try:
        print(packet.ssh)
        print(packet)
    except AttributeError:
        pass