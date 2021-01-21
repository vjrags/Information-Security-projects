#Ran in python 2.7 env

import dpkt, socket, sys

syn_to_synack = 3 #3times as many SYN packets

#FUNCTIONS

def tcpFlags(tcp):
    """Returns a list of the set flags in this TCP packet."""
    ret = list()

    if tcp.flags & dpkt.tcp.TH_FIN != 0:
        ret.append('FIN')
    if tcp.flags & dpkt.tcp.TH_SYN  != 0:
        ret.append('SYN')
    if tcp.flags & dpkt.tcp.TH_RST  != 0:
        ret.append('RST')
    if tcp.flags & dpkt.tcp.TH_PUSH != 0:
        ret.append('PSH')
    if tcp.flags & dpkt.tcp.TH_ACK  != 0:
        ret.append('ACK')
    if tcp.flags & dpkt.tcp.TH_URG  != 0:
        ret.append('URG')
    if tcp.flags & dpkt.tcp.TH_ECE  != 0:
        ret.append('ECE')
    if tcp.flags & dpkt.tcp.TH_CWR  != 0:
        ret.append('CWR')
    
    return ret


def compare_IPs(ip1, ip2):
    """
    logic to sort ips
    """
    return sum(map(int, ip1.split('.'))) - sum(map(int, ip2.split('.')))

# Parsing the PCAP

# Check if pcap is passed as input arg.
if len(sys.argv) <= 1:
    print ("{0}: needs a filepath to a PCAP file".format(sys.argv[0]))
    sys.exit(-1)

# Try to open the pcap file and create a pcap.Reader object.
try:
    f = open(sys.argv[1],"rb")
    pcap = dpkt.pcap.Reader(f)
except (IOError, KeyError):
    print ("Cannot open file:", sys.argv[1])
    sys.exit(-1)

# Argument for SYN:SYNACK ratio if passed (any whole number integer).
if len(sys.argv) == 3:
    try:
        syn_to_synack = float(sys.argv[2])
    except ValueError:
        print ("invalid ratio value:", sys.argv[2])
        sys.exit(-1)

# Main logic

suspects = dict() # Dictionary of suspects. suspect's IP: {# SYNs, # SYN-ACKs}
curPacket = 0     # Current packet number.

# Analyze captured packets.
for ts, buf in pcap:
    curPacket += 1

    # Ignore malformed packets
    try:
        eth = dpkt.ethernet.Ethernet(buf)
    except (dpkt.dpkt.UnpackError, IndexError):
        continue

    # Packet must include IP protocol to get TCP
    ip = eth.data
    if not ip:
        continue

    # Skip packets that are not TCP
    tcp = ip.data
    if type(tcp) != dpkt.tcp.TCP:
        continue

    # Get all of the set flags in this TCP packet
    tcpFlag = tcpFlags(tcp)

    srcIP = socket.inet_ntoa(ip.src)
    dstIP = socket.inet_ntoa(ip.dst)

    # Fingerprint possible suspects.
    if {'SYN'} == set(tcpFlag):          # A 'SYN' request.
        if srcIP not in suspects: suspects[srcIP] = {'SYN': 0, 'SYN-ACK': 0}
        suspects[srcIP]['SYN'] += 1
    elif {'SYN', 'ACK'} == set(tcpFlag): # A 'SYN-ACK' reply.
        if dstIP not in suspects: suspects[dstIP] = {'SYN': 0, 'SYN-ACK': 0}
        suspects[dstIP]['SYN-ACK'] += 1

# Prune unlikely suspects based on ratio of SYNs to SYN-ACKs.
for s in suspects.keys():
    if suspects[s]['SYN'] < (suspects[s]['SYN-ACK'] * syn_to_synack):
        del suspects[s]

# Output results.
print (curPacket,"packets analyzed")

if not suspects:
    print ('no suspicious packets detected...')

for s in sorted(suspects.keys(), cmp=compare_IPs):
    syns = suspects[s]['SYN']
    synacks = suspects[s]['SYN-ACK']

    print ("{0:15} had {1} SYNs and {2} SYN-ACKs".format(s, syns, synacks))