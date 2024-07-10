import csv
import glob

import pyshark


def main():
    with open(".\\arp.csv", "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(
            [
                "sniff_time",
                "eth_src",
                "eth_dst",
                "opcode",
                "src_hw_mac",
                "src_proto_ipv4",
                "dst_hw_mac",
                "dst_proto_ipv4",
            ]
        )

        for pcap_file in glob.glob(".\pcapng\*.pcapng"):
            print(pcap_file)

            with pyshark.FileCapture(pcap_file) as capture:
                for p in capture:
                    if "arp" in p:
                        arp = p.arp
                        eth = p.eth
                        sniff_time = p.sniff_time.isoformat()
                        opcode = arp.get("opcode")
                        eth_src = eth.get("src")
                        src_hw_mac = arp.get("src_hw_mac")
                        src_proto_ipv4 = arp.get("src_proto_ipv4")
                        eth_dst = eth.get("dst")
                        dst_hw_mac = arp.get("dst_hw_mac")
                        dst_proto_ipv4 = arp.get("dst_proto_ipv4")

                        writer.writerow(
                            [
                                sniff_time,
                                eth_src,
                                eth_dst,
                                opcode,
                                src_hw_mac,
                                src_proto_ipv4,
                                dst_hw_mac,
                                dst_proto_ipv4,
                            ]
                        )


if __name__ == "__main__":
    main()
