import signal
from scapy.all import *
import numpy as np

conf.debug_dissector = True
sys.path.insert(0, r"./.venv/lib/python3.10/site-packages")
import tableprint as tp

table_width = 20


def ParseSummary(summary):
    sum_list = summary.split("/")
    #print(sum_list)
    """ row = [
        sum_list[0],
        sum_list[1],
        (sum_list[2].split())[0],
        (sum_list[2].split())[1],
        (sum_list[2].split())[3],
    ]"""
    #print(tp.row(row, width=table_width))
    print (summary)

def welcomeMsg():
    tp.banner("Welcome To Packet Sniffer", width=20, style="fancy_grid")
    print(
        """ *****Sniffing Started***** \n    Type in ^C to stop\n **************************\n"""
    )


def printHeader():
    print(
        tp.header(
            ["Data-Link", "Internet", "Transport", "Src IP", "Dest IP"],
            width=table_width,
        )
    )


def printFooter():
    print(tp.bottom(n=5, width=table_width))
    print("\n*****Sniffing Stopped*****")



def main():
    flag = True
    sniffer = AsyncSniffer(prn=lambda x: ParseSummary(x.summary()))

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
