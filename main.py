import signal
from scapy.all import *
import numpy as np
from datetime import datetime

conf.debug_dissector = True
sys.path.insert(0, r"./.venv/lib/python3.10/site-packages")
import tableprint as tp

table_width = 30


def parsePacket(pckt):
    print(datetime.now().strftime("%H:%M:%S") ,end='    ')  # current date and time
    layer = pckt
#    print(pckt.summary())

    while layer:
        print(f"{layer.name}", end='    ')
        if layer.name == "IPv6" or layer.name == "IP":
            print(f"{layer.fields['src']} -> {layer.fields['dst']}" , end='   ')

        elif layer.name == "ARP":
            if(layer.fields['op'] == 1):
                print(f"who has {layer.fields['pdst']}? tell {layer.fields['psrc']}", end = '    ')
            else:
                print(f"reply: {layer.fields['psrc']} is at {layer.fields['hwsrc']}",
                    end='    ')

        """ elif layer.name == "DNS":
            if layer.fields['qr'] == 0: #query
                print(f" Query:{layer.fields['dnsqr'].qname.decode()}")
            else: #reply
        """

        layer = layer.payload
    print ("\n")


def welcomeMsg():
    tp.banner("Welcome To Packet Sniffer", width=20, style="fancy_grid")
    print(
        """ *****Sniffing Started***** \n    Type in ^C to stop\n **************************\n"""
    )


def printHeader():
    print(
        tp.header(
            ["Time", "Protocol Stack", "Info"],
            width=table_width,
        )
    )


def printFooter():
    print(tp.bottom(n=3, width=table_width))
    print("\n*****Sniffing Stopped*****")



def main():
    flag = True
    sniffer = AsyncSniffer(prn=parsePacket)

    def CHandler(signal, frame):
        sniffer.stop()
        nonlocal flag
        flag = False
        printFooter()

    signal.signal(signal.SIGINT, CHandler)


    welcomeMsg()
    sniffer.start()
    printHeader()

    while flag:
        time.sleep(1)


if __name__ == "__main__":
    main()
