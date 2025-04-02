import scapy.all as scapy
import argparse

def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    
    devices = []
    for element in answered_list:
        devices.append({"IP": element[1].psrc, "MAC": element[1].hwsrc})
    return devices

def print_result(devices):
    print("IP Address\t\tMAC Address")
    print("-----------------------------------------")
    for device in devices:
        print(f"{device['IP']}\t{device['MAC']}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest="target", required=True, help="Target IP range (e.g., 192.168.1.1/24)")
    args = parser.parse_args()
    
    scanned_devices = scan(args.target)
    print_result(scanned_devices)
