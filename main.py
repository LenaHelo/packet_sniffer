import signal
from scapy.all import *
from functools import partial

conf.debug_dissector = True





def main():
    flag= True

    def CHandler(signal, frame):
        sniffer.stop()
        nonlocal flag
        flag = False
        print("\n***Sniffing Stopped ***")

    signal.signal(signal.SIGINT, CHandler)

    sniffer= AsyncSniffer(prn=lambda x:x.summary(),filter="tcp")
    print("***Sniffing Started*** \nType in ^C when you want to stop")
    sniffer.start()

    while flag:
        time.sleep(1)

    print("-FIN-")

if __name__ == "__main__":

    main()


