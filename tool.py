from scapy.all import *
from scapy.layers import http
import getopt
import sys
import pyfiglet
import  os

G = '\033[32m'
W = '\033[0m'
O = '\033[33m'


def usage():
    result = pyfiglet.figlet_format("IDS-homie")
    print(result)
    print(
        "\nThis tool retrieves a network packet from a PCAP file and converts it into an useable IDS rule for incident response, threat hunting and detection.")
    print("\nRequirements: \n- Scapy \n- Scapy-HTTP \n- Python 3.8")
    print("\nUsage:\npython3 tool.py\n")
    sys.exit(0)


def usage_begining():
    result = pyfiglet.figlet_format("IDS-homie")
    print(result)
    print(
        "\nThis tool retrieves a network packet from a PCAP file and converts it into an useable IDS rule for incident response, threat hunting and detection.")
    print("\nRequirements: \n- Scapy \n- Scapy-HTTP \n- Python 3.8")
    print("\nUsage:\npython3 tool.py\n")



def basicconvert(singlepacket, packetnr0):
    try:
        print("\n{1}----- IDS Rules For Packet Number {0}-----{2}".format(packetnr0+1, G, W))
        if IP in singlepacket:
            print("{0}----- Layer 3/4 Rules -------{1}".format(G, W))
            ipsource = singlepacket[IP].src
            ipdest = singlepacket[IP].dst
            if TCP in singlepacket:
                print("{0}----- TCP ---\n{1}".format(G, W))
                tcpsourceport = singlepacket[TCP].sport
                tcpdestport = singlepacket[TCP].dport
                print(
                    "alert tcp {3} {1} -> $HOME_NET any (msg: \"Suspicious IP {2} connecting to port {1} detected!\"; classtype:trojan-activity; sid:xxxx; rev:1;)".format(
                        tcpsourceport, tcpdestport, ipsource, ipdest))
                print(
                    "alert tcp any any -> $HOME_NET {1} (msg: \"Suspicious IP {2} connecting to port {1} detected!\";classtype:trojan-activity; sid:xxxx; rev:1;)".format(
                        ipdest, tcpdestport, ipsource))
                # Check if DNS is present in the packet
                if DNS in singlepacket:
                    print("{0}----- DNS ---\n{1}".format(G, W))
                    hostname = singlepacket[DNSQR].qname
                    if DNSRR in singlepacket:
                        hostaddr = singlepacket[DNSRR].rdata
                        print(
                            "alert udp any 53 -> $HOME_NET any (msg: \"Suspicious DNS reply for {0} with address {1} detected!\"; content:\"|00 01 00 01|\"; content:\"|00 04".format(
                                hostname, hostaddr)),
                        addrsplit = hostaddr.split('.')
                        for addr in addrsplit:
                            hexaddr = format(int(addr), '02x')
                            print("\b", hexaddr.upper())
                        print("\b|\"; distance:4; classtype:trojan-activity; sid:xxxx; rev:1;)")
                    else:
                        print(
                            "alert udp any 53 -> $HOME_NET any (msg: \"Suspicious DNS request for {0} detected!\"; content:\"|01 00 00 01 00 00 00 00 00 00|\"; depth:10; offset:2; content:\"".format(
                                hostname)),
                        dnsplit = hostname.split('.')
                        for word in dnsplit:
                            if word != '':
                                numbers = len(word)
                                hexa = format(numbers, '02x')
                                upper = hexa.upper()
                                print("\b|{0}|{1}".format(upper, word)),
                        print("\b\"; fast_pattern; nocase; distance:0;classtype:trojan-activity; sid:xxxx; rev:1;)")

                elif singlepacket.haslayer(http.HTTPRequest):
                    print("\n{0}----- Layer 7 Rules -----{1}".format(G, W))
                    print("{0}----- HTTP -----\n{1}".format(G, W))
                    httppacket = singlepacket.getlayer(http.HTTPRequest)
                    print(
                        "Host:\nalert tcp any $HTTP_PORTS -> $HOME_NET any (msg: \"Suspicious HTTP {0[Method]} request to {0[Host]} detected!\"; flow:established,to_server; content:\"Host|3a 20|{0[Host]}|0d 0a|\"; http_header;classtype:trojan-activity; sid:xxxx; rev:1;)".format(
                            httppacket.fields))
                    print(
                        "\nFilename:\nalert tcp any $HTTP_PORTS -> $HOME_NET any (msg: \"Suspicious HTTP file name \"{0[Path]}\" requested at {0[Host]}!\"; flow:established,to_server; content:\"{0[Path]}\"; http_uri;classtype:trojan-activity; sid:xxxx; rev:1;)".format(
                            httppacket.fields))
            elif UDP in singlepacket:
                print("{0}----- UDP -----\n{1}".format(G, W))
                udpsrcport = singlepacket[UDP].sport
                udpdestport = singlepacket[UDP].dport
                print(
                    "alert udp {0} {1} -> any any (msg: \"Suspicious IP {0} and port {1} detected!\";classtype:trojan-activity;sid:xxxx; rev:1;)".format(
                        ipsource, udpsrcport))
                print(
                    "alert udp any any -> {0} {1} (msg: \"Suspicious IP {2} connecting to port {1} detected!\";classtype:trojan-activity; sid:xxxx; rev:1;)".format(
                        ipdest, udpdestport, ipsource))
                # Check if DNS is present in the packet
                if DNS in singlepacket:
                    print("{0}----- DNS -----\n{1}".format(G, W))
                    hostname = singlepacket[DNSQR].qname
                    if DNSRR in singlepacket:
                        hostaddr = singlepacket[DNSRR].rdata
                        print(
                            "alert udp any 53 -> $HOME_NET any (msg: \"Suspicious DNS reply for {0} with address {1} detected!\"; content:\"|00 01 00 01|\"; content:\"|00 04".format(
                                hostname, hostaddr)),
                        addrsplit = hostaddr.split('.')
                        for addr in addrsplit:
                            hexaddr = format(int(addr), '02x')
                            print("\b", hexaddr.upper())
                        print("\b|\"; distance:4; classtype:trojan-activity; sid:xxxx; rev:1;)")
                    else:
                        print(
                            "alert udp $HOME_NET any -> any 53 (msg: \"Suspicious DNS request for {0} detected!\"; content:\"|01 00 00 01 00 00 00 00 00 00|\"; depth:10; offset:2; content:\"".format(
                                hostname)),
                        dnsplit = hostname.split('.')
                        for word in dnsplit:
                            if word != '':
                                numbers = len(word)
                                hexa = format(numbers, '02x')
                                upper = hexa.upper()
                                print("\b|{0}|{1}".format(upper, word)),
                        print("\b|00|\"; fast_pattern; nocase; distance:0;classtype:trojan-activity; sid:xxxx; rev:1;)")

            elif ICMP in singlepacket:
                print("{0}----- ICMP -----\n{1}".format(G, W))
                icmptype = singlepacket[ICMP].type
                print(
                    "alert icmp {0} any -> {1} any (msg: \"Suspicious ICMP packet from {0} to {1} with type {2}!\"; icode:0; itype:{2};classtype:trojan-activity; sid:xxxx; rev:1;)".format(
                        ipsource, ipdest, icmptype))
            # Throw error when no L4 protocols found
            else:
                print("{0}No UDP/TCP Layer 4 Protocol Found!{1}".format(O, W))
                sys.exit(1)
        # Throw error when no IP found
        else:
            print("{0}No IP Layer 3 Protocol Found!{1}".format(O, W))
            sys.exit(1)
    except Exception as e:

        print("Error: ", e)
        usage()
        pass


# Let user input pcap
try:

    usage_begining()
    file = input("Enter file name: ")

    # Check if pcap file exists
    if file:
        if os.path.isfile(file):
            packet_format = rdpcap(file)
        else:
            print("Error:", file, "doest not exist.")
            sys.exit(1)


    def display():
        countpacket = 1
        for packet in packet_format:
            # Print a summary of each packet in the pcap, together with a packetnumber
            print(str(countpacket), packet.summary())
            countpacket = countpacket + 1


    def ask_pckt_no():
        no = input("please enter the packet number: ")
        if no.isnumeric():
            rule(int(no)-1)
            add = input("Enter 'a' to add the above rules to your IDS, or enter nothing: ")
            if add == 'a':
                rule_adder()
            else:
                again()
        else:
            print("[*]enter correct packet number.!")
            ask_pckt_no()
#        again()


    def rule(no):

        _packet = packet_format[no]
        basicconvert(_packet, no)


    def again():
        no = input(
            "For generating another IDS rule enter the packet number, to add rule to IDS enter 'a', and to exit enter 'e' or enter 'd' for displaying: ")
        if no.isnumeric():
            a = int(no)-1
            rule(int(a))
            a = input("to add rule to IDS enter 'a' else nothing: ")
            if a == 'a':
                rule_adder()
            else:
                again()
        elif no == 'a':
            rule_adder()
        elif no == 'e':
            sys.exit()
        elif no == 'd':
            display()
            again()

    def rule_adder():
        rules = input("Copy paste the appropriate IDS rule from above: ")
        path = '/etc/snort/rules/test.rules'
        with open(path, "a+") as file:
            file.seek(0)
            content = file.read(30)
            if len(content) > 0:
                file.write("\n")
            file.write(rules)
            print("[*]Rule successfully written to your IDS")
        x = input("For adding another rule enter 'x' , For viewing rules for another packet enter the packet number or enter 'd' for displaying all the packets, or enter 'e' to exit: ")
        if x == 'd':
            display()
            ask_pckt_no()
        elif x.isnumeric():
            rule(int(x) - 1)
            again()
        elif x == 'x':
            rule_adder()
        elif x == 'e':
            sys.exit()




    disply = input("Enter 'd' for packets to be displayed and 'e' to exit: ")
    if disply == 'd':
        display()
        ask_pckt_no()
    elif disply == 'e':
        sys.exit()


except Exception as e:

    print("Error: ", e)
    print("\n")
    usage()
    pass

