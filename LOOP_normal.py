import time
import random
import struct
import string
from scapy.all import IP, ICMP, send

target_ip = "192.168.146.3"  # Địa chỉ IP đích

# Bắt đầu đo thời gian thực thi
start_time = time.time()
#session_duration = 30 * 60  # 30p

# hàm send từng packet theo id và type, chỉnh phần data

def send_icmp(identifier):
    current_time = int(time.time() * 1_000_000)
    timestamp = struct.pack('>Q', current_time)
    sequential_data = bytes(range(0x00, 0x30))

    payload = timestamp + sequential_data
    pkt = IP(dst=target_ip)/ICMP(id=identifier)/payload
    send(pkt, verbose=0)

print("=== Bắt đầu gửi liên tục. Nhấn Ctrl + C để dừng ===")
try:
    # lặp gửi liên tục từng luồng, chỉ dừng khi Ctrl+C
    while True:
        # dừng gửi sau 15p
        '''if time.time() - start_time > session_duration:
            print("Break.")
            break'''
        
        total = 0
        num_pkts = random.randint(70, 80)
        for i in range(num_pkts):
            delay = random.uniform(0.05, 2.0)
            time.sleep(delay)
            id = random.randrange(1, 65535)
            send_icmp(id)
            total += 1
            print(f"Đã gửi {total} gói.")

        # Đợi 5 giây để RECEIVER xử lý và lưu file trước 
        print("⏳ Đợi 5 giây...\n")
        time.sleep(5)

# Ctrl+C
except KeyboardInterrupt:
    print("\n🛑 Đã dừng chương trình theo yêu cầu.")
