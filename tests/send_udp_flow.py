import socket
import struct
import time

def send_test_netflow_v5():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    
    # NetFlow v5 Header
    # version=5, count=1, sys_uptime=1000, unix_secs=int(time.time()), unix_nsecs=0, seq=42, engine_type=1, engine_id=1, sampling=1
    header = struct.pack("!HHIIIIBBH", 5, 1, 1000, int(time.time()), 0, 42, 1, 1, 1)
    
    # 1 Record
    src_ip = struct.unpack("!I", socket.inet_aton("192.168.1.100"))[0]
    dst_ip = struct.unpack("!I", socket.inet_aton("1.1.1.1"))[0]
    nh_ip = struct.unpack("!I", socket.inet_aton("10.0.0.1"))[0]
    
    rec = struct.pack("!IIIHHIIIIHHBBBBHHBBH",
        src_ip, dst_ip, nh_ip,
        1, 2, # in_if, out_if
        50, # packets
        50000, # bytes
        100, 200, # first, last switched
        45000, 53, # src_port, dst_port (DNS)
        0, 0, # pad1, tcp_flags
        17, # protocol (UDP)
        0, # tos
        64516, 13335, # src_as, dst_as (Cloudflare)
        24, 32, # masks
        0 # pad2
    )
    
    payload = header + rec
    sock.sendto(payload, ("127.0.0.1", 2055))
    print(f"Sent {len(payload)} bytes of NetFlow v5 binary datagram to UDP 127.0.0.1:2055")
    sock.close()

if __name__ == "__main__":
    send_test_netflow_v5()
