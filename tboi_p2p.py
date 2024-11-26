import os
import requests
import psutil
from scapy.all import *

steam_process_name = "steam.exe"

# "Remote play" UDP reserved ports.
# https://help.steampowered.com/en/faqs/view/2EA8-4D75-DA21-31EB
steam_reserved_ports = [27031, 27032, 27033, 27034, 27035, 27036]

# Ports in this list are currently in a queue for sniffing, 
# meaning ports not in this queue aren't meant to be handled.
queued_ports = []

# Amount of times peers count need to be the same 
# for the program to print.
peer_match_threshold = 3

def main():
    last_peer_count = -1
    same_peer_count = 0

    while True:
        packets = search_p2p()
        packets_count = len(packets)

        # Avoid spamming by only printing when data is changing.
        if packets_count == last_peer_count:
            same_peer_count += 1

            # print
            if same_peer_count == peer_match_threshold:
                print('---------------------------------------')
                if packets_count == 0:
                    print('No P2P ports were found')
                else:
                    for packet in packets:
                        print(f'{packet[IP].dst} - {get_geoip(packet[IP].dst)}')
                        
            continue
        
        print("Gathering data...")
        same_peer_count = 0
        last_peer_count = packets_count

def filter_packet(packet):
    # Ignore STUN packets.
    if is_classic_stun(packet):
        return False
    
    if packet.sport not in queued_ports:
        return False

    queued_ports.remove(packet.sport)
    return True

# A workaround with us receiving packets, 
# meaning the dst is our local address.
# Flip the dst with the src.
def process_packet(packet):
    if packet[IP].dst == get_if_addr(conf.iface):
        packet[IP].dst = packet[IP].src

# Retrieves the amount of peers found.
def search_p2p():
    peer_ports = find_peer_ports()
    peer_ports_len = len(peer_ports)
    if peer_ports_len == 0:
        return []

    queued_ports.clear()

    # Setup the sniff filter string.
    filter_query = "udp and port "
    for i, port in enumerate(peer_ports):
        queued_ports.append(port)
        filter_query += f'{port}' if i == 0 else f' or {port}'

    packets = sniff(filter = filter_query, prn = process_packet, lfilter = filter_packet, timeout = 1, count = peer_ports_len)
    if len(packets) == 0:
        return []

    return packets

def find_steam_pid():
    for proc in psutil.process_iter():
        if steam_process_name in proc.name():
            return proc.pid
    
    return -1

def find_peer_ports():
    steam_pid = find_steam_pid()
    if steam_pid == -1:
        print('Cannot find steam services.')
        return []

    peer_ports = []

    connections = psutil.net_connections()
    for con in connections:
        # Skip any processes which aren't {steam_process_name}
        if con.pid != steam_pid:
            continue
        
        # For UDP and UNIX sockets this is always going to be psutil.CONN_NONE.
        if con.status != psutil.CONN_NONE:
            continue
        
        # Ignore reserved ports.
        if con.laddr.port in steam_reserved_ports:
            continue
        
        peer_ports.append(con.laddr.port)

    return peer_ports

# Ugly implementation of finding STUN packets.
# Original idea was using magic cookie but I believe it's below RFC5389.
# https://www.rfc-editor.org/rfc/rfc5389#section-6
# https://gitlab.com/wireshark/wireshark/-/blob/master/epan/dissectors/packet-classicstun.c#L202
# Retrieves True if the packet is a Classic STUN packet, False otherwise.
def is_classic_stun(packet):
    stun_data = bytes(packet.payload)
    if len(stun_data) < 30:  # Minimum STUN header size
        return False

    # 0x0001 : Binding Request
    if stun_data[28] == 0x00 and stun_data[29] == 0x01:
        return True

    # 0x0101 : Binding Response
    if stun_data[28] == 0x01 and stun_data[29] == 0x01:
        return True

    # 0x0111 : Binding Error Response
    if stun_data[28] == 0x01 and stun_data[29] == 0x11:
        return True
    
    # 0x0002 : Shared Secret Request
    if stun_data[28] == 0x00 and stun_data[29] == 0x02:
        return True

    # 0x0102 : Shared Secret Response
    if stun_data[28] == 0x01 and stun_data[29] == 0x02:
        return True

    # 0x0112 : Shared Secret Error Response
    if stun_data[28] == 0x01 and stun_data[29] == 0x12:
        return True

    # 0x0004 : Send Request
    if stun_data[28] == 0x00 and stun_data[29] == 0x04:
        return True

    # 0x0115 : Data Indication
    if stun_data[28] == 0x01 and stun_data[29] == 0x15:
        return True

    return False

def get_geoip(ip_addr):
    # Define the API endpoint URL
    url = f'https://api.iplocation.net/?ip={ip_addr}'

    try:
        # Make a GET request to the API endpoint using requests.get()
        response = requests.get(url)

        # Check if the request was successful (status code 200)
        if response.status_code == 200:
            data = response.json()
            return data['country_name']
        else:
            print('Error:', response.status_code)
            return ""
    except:
        return ""

if __name__ == '__main__':
    main()