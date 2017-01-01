import dpkt

# import ieee80211

f = open('/home/matan/Downloads/WiFi_Data_test/file1.cap')
pc = dpkt.pcap.Reader(f)

for ts, buf in pc:
   rt = dpkt.radiotap.Radiotap()
   ieee = rt.data
   print ieee.Action



# for ts, buf in pc:
#     eth = dpkt.ethernet.Ethernet(buf)
#     ip = eth.data
#     tcp = ip.data
#
# if tcp.dport == 80 and len(tcp.data) > 0:
#     http = dpkt.http.Request(tcp.data)
#     print http.uri


f.close()