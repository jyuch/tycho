import csv
import glob

import pyshark


def main():
    with open(".\\arp.csv", "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(
            [
                "sniff_time",
                "opcode",
                "src_hw_mac",
                "src_proto_ipv4",
                "dst_hw_mac",
                "dst_proto_ipv4",
            ]
        )

        for pcap_file in glob.glob(".\pcapng\*.pcapng"):
            capture = pyshark.FileCapture(pcap_file)

            for p in capture:
                if "arp" in p:
                    sniff_time = p.sniff_time.isoformat()
                    opcode = p.arp.opcode
                    src_hw_mac = p.arp.src_hw_mac
                    src_proto_ipv4 = p.arp.src_proto_ipv4
                    dst_hw_mac = p.arp.dst_hw_mac
                    dst_proto_ipv4 = p.arp.dst_proto_ipv4

                    writer.writerow(
                        [
                            sniff_time,
                            opcode,
                            src_hw_mac,
                            src_proto_ipv4,
                            dst_hw_mac,
                            dst_proto_ipv4,
                        ]
                    )


if __name__ == "__main__":
    main()
