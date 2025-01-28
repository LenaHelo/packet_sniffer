import signal
from scapy.all import *
import numpy as np

conf.debug_dissector = True
sys.path.insert(0, r"./.venv/lib/python3.10/site-packages")
import tableprint as tp


#TODO add 'install tableprint and numpy' to README
def main():
    flag= True
    def CHandler(signal, frame):
        sniffer.stop()
        nonlocal flag
        flag = False
        print("\n***Sniffing Stopped***")

    signal.signal(signal.SIGINT, CHandler)
    sniffer= AsyncSniffer(prn=lambda x:x.summary(),filter="tcp")



    tp.banner("Welcome To Packet Sniffer",width=20)
    print("***Sniffing Started*** \nType in ^C when you want to stop")
    sniffer.start()

    while flag:
        time.sleep(1)


if __name__ == "__main__":

    main()


