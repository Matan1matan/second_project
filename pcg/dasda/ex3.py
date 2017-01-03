from scapy.all import *
import matplotlib.pyplot as plt
import networkx as nx

my_colors = 'rgbkymc'

class ex3:
    def __init__(self, path):
        self.pcap_file = rdpcap(path)

    def export(self, type, format_file):

        try:

            filename = type + '.' + format
            plt.savefig(filename, format=format_file)

            print(format_file + " created!")

        except SyntaxError:

            print("due to some error, the PDF wasn't created")

    def display_by_MAC_addresses(self):

        mac_adresses = {}  # new dictionary
        for pkt in self.pcap_file:
            mac_adresses.update({pkt[Dot11].addr1: 0})
        for pkt in self.pcap_file:
            mac_adresses[pkt[Dot11].addr1] += 1

        # MA_list = list(mac_adresses)

        MA = []
        for ma in mac_adresses:
            MA.append(mac_adresses[ma])

        # my_colors = 'rgbkymc'

        plt.bar(range(len(mac_adresses)), sorted(MA), align='center', color=my_colors)

        plt.xticks(range(len(mac_adresses)), sorted(mac_adresses.keys()))

        plt.rcParams.update({'font.size': 10})

        plt.xlabel('MAC Address')
        plt.ylabel('Count')

        # Set tick colors:
        ax = plt.gca()
        ax.tick_params(axis='x', colors='blue')
        ax.tick_params(axis='y', colors='red')
        ax.set_xticklabels(ax.xaxis.get_majorticklabels(), rotation=45)

        plt.legend()
        plt.show()

    def display_by_networks(self):

        networks = {}

        for pkt in self.pcap_file:
            if pkt.haslayer(Dot11Elt):
                try:
                    networks.update({str((pkt[Dot11Elt].info).decode("utf-8")) : 0})
                except:
                    networks.update({str(pkt[Dot11Elt].info) : 0})


        for pkt in self.pcap_file:
            if pkt.haslayer(Dot11Elt):
                try:
                    networks[str((pkt[Dot11Elt].info).decode("utf-8"))] += 1
                except:
                    networks[str(pkt[Dot11Elt].info)] += 1

        networks_list = []
        for network in networks:
            networks_list.append(networks[network])

        # my_colors = 'rgbkymc'

        plt.bar(range(len(networks)), sorted(networks_list), align='center', color=my_colors)

        plt.xticks(range(len(networks)), sorted(networks.keys()))

        plt.rcParams.update({'font.size': 10})

        plt.xlabel('Network')
        plt.ylabel('Count')

        # Set tick colors:
        ax = plt.gca()
        ax.tick_params(axis='x', colors='blue')
        ax.tick_params(axis='y', colors='red')
        ax.set_xticklabels(ax.xaxis.get_majorticklabels(), rotation=30)


        plt.legend()
        plt.show()


    def display_protocol(self):

        count = 0

        for pkt in self.pcap_file:
            print(pkt.payload.payload.name)


        protocol_map = {}
        for pkt in self.pcap_file:
            protocol_map.update({pkt.payload.payload.name: 0})

        for pkt in self.pcap_file:
            protocol_map[pkt.payload.payload.name] += 1



        print(protocol_map)

        # End of class ex3


    def display_graph(self):

        G = nx.Graph()

        edges_list = []

        for pkt in self.pcap_file:
            if hasattr(pkt.payload, 'src') and hasattr(pkt.payload,'dst'):

                edges_list.append((pkt.payload.src,pkt.payload.dst))


                # print(pkt.payload.src + " | " + pkt.payload.dst)
        plt.rcParams.update({'font.size': 10})
        G.add_edges_from(edges_list)
        nx.draw(G, with_labels=True, node_color=my_colors )
        plt.show()

def open_file():
    # filename = input('Enter file name: ')

    # need to insert 'Try&Catch'

    # return ex3('/home/matan/PycharmProjects/second_project/pcg/dasda/' + str(filename) + '.cap')
    return ex3('/home/matan/PycharmProjects/second_project/pcg/dasda/file5.cap')


def main():
    ex3_object = open_file()

    # ex3_object.display_by_MAC_addresses()
    ex3_object.display_by_networks()
    # ex3_object.display_graph()

if __name__ == '__main__':
    main()
