from re import VERBOSE
import scapy.all as scapy
import argparse

def scan(ip):
    return scapy.srp(scapy.Ether(dst="ff:ff:ff:ff:ff:ff")/scapy.ARP(pdst=ip),timeout=2, verbose=False)[0]

def getAllNetIps():
    gw = scapy.conf.route.route("0.0.0.0")[2]
    gw = str(gw + "/24")
    results = scan(gw)
    ips = []
    for res in results:
        ips.append(res[1].psrc)
    
    return ips


def main():
    parser = argparse.ArgumentParser(usage='arpScanner.py IP_RANGE' '\nexample: sudo python3 arpScanner.py 192.168.1.0/24')
    parser.add_argument("-t", "--target", dest="target", help="Specify target ip/ip range")
    results = scan(parser.parse_args().target)

    print("IP\t\t\tMAC")
    for res in results:
        print(res[1].psrc.ljust(15, " "), ":", res[1].hwsrc)
    #getAllNetIps()

if __name__ == "__main__":
    main()