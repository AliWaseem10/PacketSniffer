import socket
import struct
import textwrap

# Format Text
TAB_1 = '\t - '
TAB_2 = '\t\t - '
TAB_3 = '\t\t\t - '
TAB_4 = '\t\t\t\t - '

DATA_TAB_1 = '\t   '
DATA_TAB_2 = '\t\t   '
DATA_TAB_3 = '\t\t\t   '
DATA_TAB_4 = '\t\t\t\t   '


# main loop
def main():
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    while True:
        raw_data, addr = conn.recvfrom(65536)
        dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)
        print('\n Ethernet Frame: ')
        print('Destination {}, Source {}, Protocol {}'.format(
            dest_mac, src_mac, eth_proto))

        # 8 for IPv4
        if eth_proto == 8:
            (version, header_length, ttl, proto,
             src, target, data) = ipv4_packet(data)
            print(TAB_1 + 'IPv4 Packet: ')
            print(
                TAB_2 + 'Version: {}, Header Length: {}, TTL: {}'.format(version, header_length, ttl))
            print(
                TAB_2 + 'Protocol: {}, Source: {}, Target: {}'.format(proto, src, target))

            if proto == 1:
                icmp_type, code, checksum, data = icmp_packet(data)
                print(TAB_1 + 'ICMP Packet: ')
                print(
                    TAB_2 + 'Type: {}, Code: {}, Checksum: {}'.format(icmp_type, code, checksum))
                print(TAB_2 + 'Data: ')
                print(format_multi_line(DATA_TAB_3, data))

            if proto == 6:
                (src_port, dest_port, seq, acknowledgement, offset_reserves_flags, flag_urg,
                 flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data) = tcp_segment(data)
                print(TAB_1 + 'TCP Packet: ')
                print(
                    TAB_2 + 'Source Port: {}, Destination Port: {}'.format(src_port, dest_port))
                print(
                    TAB_2 + 'Sequence: {}, Acknowledgement: {}'.format(sequence, acknowledgement))
                print(TAB_2 + 'Flags: ')
                print(TAB_3 + 'URG: {}, ACK: {}, PSH: {}, RST: {}, SYN: {}, FIN: {}'.format(
                    flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin))
                print(TAB_2 + 'Data: ')
                print(format_multi_line(DATA_TAB_3, data))

            if proto == 17:
                src_port, dest_port, size, data = udp_segment(data)
                print(TAB_1 + 'UDP Segment: ')
                print(
                    TAB_2 + 'Source Port: {}, Destination Port: {}, Length: {}'.format(src_port, dest_port, size))
            else:
                print(TAB_1 + 'Data: ')
                print(format_multi_line(DATA_TAB_2, data))
        else:
            print(TAB_1 + 'Data: ')
            print(format_multi_line(DATA_TAB_2, data))

# Unpack Ethernet Frame


def ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto), data[14:]

# Return properly formatted mac address


def get_mac_addr(bytes_addr):
    bytes_str = map('{:02x}'.format, bytes_addr)
    mac_addr = ':'.join(bytes_str).upper()
    return mac_addr

# Unpacking IPv4 packets


def ipv4_packet(data):
    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_length, ttl, proto, ipv4(src), ipv4(target), data[header_length:]

# Returns Properly Formatted IPv4 address


def ipv4(addr):
    return '.'.join(map(str, addr))

# Unpacks ICMP packet


def icmp_packets(data):
    icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
    return icmp_type, code, checksum, data[4:]

# unpacks TCP Segment


def tcp_segment(data):
    (src_port, dest_port, seq, acknowledgement,
     offset_reserves_flags) = struct.unpack('! H H L L H', data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    flad_urg = (offset_reserved_flags & 32) >> 5
    flad_ack = (offset_reserved_flags & 16) >> 4
    flad_psh = (offset_reserved_flags & 8) >> 3
    flad_rst = (offset_reserved_flags & 4) >> 2
    flad_syn = (offset_reserved_flags & 2) >> 1
    flad_fin = (offset_reserved_flags & 1)
    return src_port, dest_port, seq, acknowledgement, offset_reserves_flags, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data[offset:]

# Unpacks UDP segment


def udp_segment(data):
    src_port, dest_port, size = struct.unpack('! H H 2x H', data[:8])
    return src_port, dest_port, size, data[8:]

# Formats multi-line data


def format_multi_linee(prefix, string, size=80):
    size -= len(prefix)
    if isinstance(string, bytes):
        string = ''.json(r'\x{:02x}'.format(byte) for byte in string)
        if size % 2:
            size -= 1
    return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])


main()
