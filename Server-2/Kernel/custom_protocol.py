from scapy.packet import Packet, bind_layers
from scapy.fields import ByteField, ShortField
from scapy.layers.inet import UDP, IP

class RIP(Packet):
    name = "RIP"
    fields_desc = [
        ByteField("command", 1),
        ByteField("version", 2),
        ShortField("routing_domain", 0)
    ]

class L2TP(Packet):
    name = "L2TP"
    fields_desc = [
        ShortField("length", 0),
        ShortField("tunnel_id", 0),
        ShortField("session_id", 0)
    ]

class PPTP(Packet):
    name = "PPTP"
    fields_desc = [
        ShortField("message_type", 1),
        ShortField("magic_cookie", 0x1a2b3c4d),
        ShortField("control_message_type", 0)
    ]

class SNMP(Packet):
    name = "SNMP"
    fields_desc = [
        ByteField("version", 0),
        ByteField("community", 0),
        ByteField("pdu_type", 0)
    ]

class ISIS(Packet):
    name = "ISIS"
    fields_desc = [
        ByteField("pdu_type", 0),
        ByteField("version", 1),
        ShortField("length", 0)
    ]

class LLDP(Packet):
    name = "LLDP"
    fields_desc = [
        ByteField("tlv_type", 0),
        ByteField("tlv_length", 0)
    ]

class IGMP(Packet):
    name = "IGMP"
    fields_desc = [
        ByteField("type", 0x11),  # Default to Membership Query
        ByteField("max_resp_time", 0),
        ShortField("checksum", 0),
        ShortField("group_address", 0)
    ]

# Bind these protocols to IP/UDP where appropriate
bind_layers(UDP, RIP, dport=520)
bind_layers(IP, L2TP, proto=115)
bind_layers(IP, PPTP, proto=47)
bind_layers(UDP, SNMP, dport=161)
bind_layers(IP, ISIS, proto=124)
bind_layers(UDP, LLDP, dport=646)
bind_layers(IP, IGMP, proto=2)
