from scapy.all import *
from scapy.layers.inet import IP
from scapy.utils import rdpcap

from subprocess import call



# new_src_ip="255.255.255.255"
# new_src_mac="00:11:22:33:44:55"



pkts_input = input("Hello, please enter your .cap file path: ")

if (pkts_input == ""):
    pkts_input = "/home/matan/Downloads/WiFi_Data_test/file1.cap"

pkts = rdpcap(str(pkts_input))

print ("------------------MENU-------------------")

pkts2 = rdpcap(
    "/home/matan/Downloads/WiFi_Data_test/file1.cap")  # could be used like this rdpcap("filename",500) fetches first 500 pkts

# sniff(iface="wifi0", prn=lambda x: x.summary())
# print (pkts[0].pdfdump())
# print (sniff(filter="802.11"))
# pkts[0].pdfdump(layer_shift=1)

print("Hello, what do u wanna do...?")
print("press '1' to get info about all the packets")
print("press '2' to get info about a specific packet")
choose = input("")


if (choose == "1"):
    print("choose what information do you wanna know about all the packets:")
    print("-1- size of all of the packets (in bytes)")
    print("-2- number of the networks")
    print("-3- number of users")
    print("-4- export to pdf files")
    print("-5- export to ps files")
    print("-6- export to text files")
    print("-7- back to the previous menu")
    internal_choose = int(input(""))

    general_statics(internal_choose)


    if (internal_choose == 1):




elif (choose == "2"):

    flag = True

    while(flag):

        specific_packet = int(input("press number of the packet [0-" + str(len(pkts)-1)+"]: "))
        if (specific_packet < 0 or specific_packet > len(pkts)-1):
            print("you have insterted a wrong number!")
        else:
            packet = pkts[specific_packet]
            flag = False

def general_statics (packets, internal_choose):

    if (internal_choose == 1): # size of all of the packets (in bytes)
        packets_size = 0
        for packet in packets:
            packets_size += len(packet)
        print("size of all packets: " + str(packets_size))
        return

    elif (internal_choose == 2): # number of the networks

        mac_addresses = set()
        for packet in packets:
            mac_addresses.add(pkt[Dot11].addr1)
        print("num of all distinct mac_addresses with Dot11 (WiFi) layer: " + str(len(mac_addresses)))

        return

    elif (internal_choose == 3): # number of users

        networks = set()




    elif (internal_choose == 4): # export to pdf files
    elif (internal_choose == 5): # export to ps files
    elif (internal_choose == 6): # export to text files
    else: # back to the previous menu










# ap_list = []
#
# def PacketHandler(pkt) :
#
#     if pkt.haslayer(Dot11):
# 	    if pkt.type == 0 and pkt.subtype == 8 :
# 		    if pkt.addr2 not in ap_list :
# 			    ap_list.append(pkt.addr2)
# # 			    print ("AP MAC: %s with SSID: %s " %(pkt.addr2, pkt.info))

# sniff(iface="mon0", prn = PacketHandler)






count = 0
dest = '/home/matan/Downloads/WiFi_Data_test/pdf_files/'
# dest2 =
aps = []


# mac_addresses = set()
# packets_size = 0

# pkts[0].pdfdump('/home/matan/Downloads/WiFi_Data_test/pdf_files/1')
# pkts[1].pdfdump('/home/matan/Downloads/WiFi_Data_test/pdf_files/1.ps')
for pkt in pkts:
    count+=1


    # temp = dest + str(count)
    # pkt.pdfdump(temp)

    # if pkt.haslayer(Dot11Elt):
    #     networks.add(pkt[Dot11Elt].info)
    #     print(ls(pkt[Dot11Elt]))
        # print(pkt[Dot11Elt].info)

    # print (pkt.summary())
    # i = hexdump(pkt[Dot11])


    # if pkt.haslayer(Dot11Beacon):
    #     print(pkt(Dot11Beacon))
    # dec = WiFi_am(pkt).iffrom()
    # print(dec)

    # packets_size += len(pkt)
    mac_addresses.add(pkt[Dot11].addr1)


    # print (pkt.command())

    # print(pkt[Dot11].exten)

    # pkt[Dot11].addr1

# set of all mac_addresses with Dot11 (WiFi) layer
# print (mac_addresses)
# num of this set
print ("num of all distinct mac_addresses with Dot11 (WiFi) layer: " + str(len(mac_addresses)))

# size of all packets



print (networks)
# num of networks
print ("num of networks: " + str(len(networks)))

# call('ls')

        # if pkt.haslayer(Dot11):
        #     print("yes1")
        #     print(pkt.type)
        #     if pkt.type == 1 and pkt.subtype == 13:
        #         print("yes2")
        #         if pkt.addr2 not in aps:
        #
        #             aps.append(pkt.addr2)
        #             print ("Found BSSID %s and SSID %s " % (pkt.addr2, pkt.info))
    # pkt.filter(lambda x: x.haslayer(Dot11) and x.type == 2, self.res)
    # pkt.filter(PacketHandler)
    # if count == 2:
    #     break






# aps = []
#
#
# # The following function is a packet handler that will check each packet as it
# # is passed by the sniffer. If the packet has an 802.11 layer and the type is 0
# # which is a management frame and subtype 0. If the AP's address is not already in
# # the aps list then add it to the list and print it.
# def PacketHandler(pkt):
#     if pkt.haslayer(Dot11):
#         if pkt.type == 0 and pkt.subtype == 8:
#             if pkt.addr2 not in aps:
#                 aps.append(pkt.addr2)
#                 print ("Found BSSID %s and SSID %s " % (pkt.addr2, pkt.info))
#
# # Begin sniffing and pass each packet to the PacketHandler function above.
# sniff(iface="mon0", prn=PacketHandler, store = 0 )
