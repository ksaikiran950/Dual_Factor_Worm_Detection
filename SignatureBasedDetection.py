from threading import Thread
from scapy.all import *
from datetime import datetime
from tkinter import END, messagebox

class SignatureBasedDetection(Thread):
    # Class-level constants (don't use double underscores unless you need name mangling)
    _flagsTCP = {
        'F': 'FIN',
        'S': 'SYN',
        'R': 'RST',
        'P': 'PSH',
        'A': 'ACK',
        'U': 'URG',
        'E': 'ECE',
        'C': 'CWR',
    }

    def __init__(self, queue, text):
        super().__init__()
        self.queue = queue
        self.text = text
        self.stopped = False
        self.malicious = 0
        self._ip_cnt_TCP = {}  # Instance-specific dictionary

    def stop(self):
        self.stopped = True

    def getMalicious(self):
        return self.malicious

    def detect_TCPflood(self, packet):
        if IP in packet and TCP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            stream = f"{src_ip}:{dst_ip}"

            # Count packets in the stream
            self._ip_cnt_TCP[stream] = self._ip_cnt_TCP.get(stream, 0) + 1
            count = self._ip_cnt_TCP[stream]

            if count > 255:
                self.malicious += 1
                msg = f"[!] Possible Flooding Attack from {src_ip} -> {dst_ip} | Count: {count}"
                print(msg)
                self.text.insert(END, msg + "\n")
            else:
                ttl = packet[IP].ttl
                msg = f"Normal traffic from {src_ip} -> {dst_ip} | Count: {count} | TTL: {ttl}"
                print(msg)
                self.text.insert(END, msg + "\n")

    def process(self, queue):
        self.malicious = 0
        while not queue.empty():
            pkt = queue.get()

            if IP in pkt:
                src = pkt[IP].src
                dst = pkt[IP].dst
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                log = f"IP Packet: {src} => {dst}, Time: {timestamp}"
                print(log)
                self.text.insert(END, log + "\n")

            if TCP in pkt:
                sport = pkt.sport
                dport = pkt.dport
                flags = pkt.sprintf('%TCP.flags%')
                flag_str = [self._flagsTCP.get(x, x) for x in flags]
                flag_msg = f"Ports: {sport} -> {dport}, Flags: {flag_str}"
                print(flag_msg)
                self.text.insert(END, flag_msg + "\n")

                self.detect_TCPflood(pkt)

        messagebox.showinfo(
            "Detection Complete",
            f"Signature-Based Malicious Packet Detection: {self.getMalicious()} malicious packets detected."
        )

    def run(self):
        print("[*] Starting Signature-Based Detection...")
        self.process(self.queue)
