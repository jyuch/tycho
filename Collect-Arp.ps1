$tshark = 'C:\Program Files\Wireshark\tshark.exe'
$interface = '\Device\NPF_{B09A431C-E11A-477B-9EC2-DB34F0B73B6C}'
$pcap = '.\pcapng'

while ($true) {
    $start = (Get-Date).ToString("yyyyMMddHHmmss")
    $file = "arp-${start}.pcapng"
    $out = Join-Path $pcap $file
    
    & $tshark -i $interface -w $out -a 'duration:3600' -f 'arp'
}
