#!/usr/bin/env python3
import socket
import struct
from os import makedirs
from os.path import join, exists


def save_data(data: str, path: str = './packages_data', filename: str = 'data'):
    if not exists(path):
        print('Save packages data: path to save does not exist. \nIt was created')
        makedirs(path)

    with open(join(path, filename), 'w') as f:
        f.write(data)


def save_data_bytes(data: bytes, path: str = './packages_data', filename: str = 'data'):
    if not exists(path):
        print('Save packages data: path to save does not exist. \nIt was created')
        makedirs(path)

    with open(join(path, filename), 'wb') as f:
        f.write(data)


def ethernet_header(data):
    dest, src, proto = struct.unpack('6s6s2s', data)
    # dest,src = dest.decode("utf-8"), src.decode("utf-8")
    dest_mac = '-'.join(map('{:02x}'.format, dest)).upper()
    dest_src = '-'.join(map('{:02x}'.format, src)).upper()
    return dest_mac, dest_mac


def ip_header(data):
    frame = struct.unpack("!BBHHHBBH4s4s", data)
    version = frame[0]
    tos = frame[1]
    total_length = frame[2]
    identification = frame[3]
    fragment_Offset = frame[4]
    ttl = frame[5]
    protocol = frame[6]
    header_checksum = frame[7]
    source_address = socket.inet_ntoa(frame[8])
    destination_address = socket.inet_ntoa(frame[9])
    ip_h = {'Version': version,
            "Tos": tos,
            "Total Length": total_length,
            "Identification": identification,
            "Fragment": fragment_Offset,
            "TTL": ttl,
            "Protocol": protocol,
            "Header CheckSum": header_checksum,
            "Source Address": source_address,
            "Destination Address": destination_address}
    return ip_h


def udp_header(data):
    frame = struct.unpack("!HHHH", data)
    source_port = frame[0]
    destination_port = frame[1]
    datagram_length = frame[2]
    checksum = frame[3]

    udp_h = {"Source port": source_port,
             "Destination port": destination_port,
             "Datagram Length": datagram_length,
             "CheckSum": checksum,
             }

    return udp_h


def next_asn(data):

    type_asn = data[0]
    lenght = data[1]
    
    # print('type', hex(type_asn))
    # print('lenght', lenght)

    if hex(type_asn) == '0x30':
        return data[2:lenght + 2], data[lenght + 2:]
    if hex(type_asn) == '0x2':
        return str(data[2:lenght + 2])[2:-1], data[lenght + 2:]
    if hex(type_asn) == '0x05':
        return None, data[lenght + 2:]
    if hex(type_asn) == '0xa0':
        return 'GetRequest', data[2:lenght + 2]
    if hex(type_asn) == '0xa1':
        return 'GetNextRequest', data[2:lenght + 2]
    if hex(type_asn) == '0xa2':
        return 'GetResponse', data[2:lenght + 2]
    if hex(type_asn) == '0xa3':
        return 'SetRequest', data[2:lenght + 2]
    return data[2:lenght + 2], data[lenght + 2:]


def snmp_pars(data):

    snmp_message, _ = next_asn(data)
    version, data = next_asn(snmp_message)
    community_string, data = next_asn(data)
    pdu_type, pdu_data = next_asn(data)
    request_id, pdu_data = next_asn(pdu_data)
    error, pdu_data = next_asn(pdu_data)
    error_index, pdu_data = next_asn(pdu_data)
    var_bind_data, _ = next_asn(pdu_data)
    var_bind_data, _ = next_asn(pdu_data)

    info = f'SNMP version: {1}\n'
    info += f'Community string: {community_string}\n'
    info += f'PDU type: {pdu_type}\n'
    # print(info)

    return info


def pars_session(sess_data):
    
    for filename, packages in sess_data.items():
        data = str()
        # data = bytes()  # just for bytes without parsing
        for pack in packages:
            data += snmp_pars(pack) + ('#' * 39) + '\n'
            # data += pack  # just for bytes without parsing
        save_data(data, filename=filename)
        # save_data_bytes(data, filename=filename)  # just for bytes without parsing


socket_protocol = socket.htons(3)
sniff = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket_protocol)

session_data = {}
max_size = 18
curr_size = 0

while True:
    raw_data = sniff.recvfrom(65565)[0]
    dets_mac, src_mac = ethernet_header(raw_data[:14])
    ip_head = ip_header(raw_data[14:34])
    # UDP - 17
    if ip_head["Protocol"] is 17:   # 6 - TCP
        udp_head = udp_header(raw_data[34:42])
        if udp_head["Destination port"] not in [161, 162]:
            continue
	
        info = f'src_ip: {ip_head["Source Address"]}\n'
        info += f'dest_ip: {ip_head["Destination Address"]}\n'
        info += f'src_port: {udp_head["Source port"]}\n'
        info += f'dest_port: {udp_head["Destination port"]}\n'
        print('#' * 39)
        print(info)
        
        if info in session_data:
            session_data[info].append(raw_data[42:])
        else:
            session_data[info] = [raw_data[42:], ]

        print(snmp_pars(raw_data[42:]))

        curr_size += 1
        if curr_size == max_size:
            pars_session(session_data)
            session_data = {}
            curr_size = 0
        

