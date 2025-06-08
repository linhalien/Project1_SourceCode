import time
import random
import struct
import string
from scapy.all import IP, ICMP, send

target_ip = "192.168.146.128"  # Địa chỉ IP đích

# Bắt đầu đo thời gian thực thi
start_time = time.time()
#session_duration = 30 * 60  # 30p

# random message gồm 5 kí tự
def random_message(length=5):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

# hàm chuyển message thành binary
def encode_to_binary(msg):
    return ''.join(format(ord(c), '08b') for c in msg)

# hàm send từng packet theo id và type, chỉnh phần data
def send_icmp(identifier, packet_type="data"):
    current_time = int(time.time() * 1_000_000)
    timestamp = struct.pack('>Q', current_time)

    sequential_data = bytes(range(0x00, 0x30))
    sequential_data = sequential_data[:-1] + b'\x3f'

    if packet_type == "mock":
        sequential_data = sequential_data[:-3] + b'\x3d' + sequential_data[-2:]
    elif packet_type == "end":
        sequential_data = sequential_data[:-3] + b'\x2b' + sequential_data[-2:]

    payload = timestamp + sequential_data
    pkt = IP(dst=target_ip)/ICMP(id=identifier)/payload
    send(pkt, verbose=0)

# Các thông số delay
delay_bit_1 = 1.5
delay_bit_0 = 0.5

print("=== Bắt đầu gửi liên tục. Nhấn Ctrl + C để dừng ===")
try:
    # lặp gửi liên tục từng luồng, chỉ dừng khi Ctrl+C
    while True:
        # dừng gửi sau 15p
        #if time.time() - start_time > session_duration:
            #print("Break.")
            #break
        # Bước 1: Sinh thông điệp mới
        message = random_message()
        binary_message = encode_to_binary(message)
        print(f"\nMessage: '{message}' → Binary: {binary_message}")
        
        total = 0
        # Bước 2: Gửi gói mốc
        mock_id = random.randrange(1, 65535)
        send_icmp(mock_id, packet_type="mock")
        total +=1
        print(f"[MOCK] id={mock_id} - Gửi gói mốc")

        # Bước 3: Gửi từng bit (kèm nhiễu)
        num = 0
        while num < len(binary_message):
            is_noise = random.choice([True, False])
            if is_noise:
                delay = random.uniform(0.05, 2.0)
                time.sleep(delay)
                noise_id = random.randrange(1, 65535, 2)
                send_icmp(noise_id, packet_type="data")
                total += 1
                print(f"[NOISE] id={noise_id} - Sau {delay:.2f}s")
            else:
                bit = binary_message[num]
                delay = delay_bit_1 if bit == '1' else delay_bit_0
                time.sleep(delay)
                data_id = random.randrange(0, 65534, 2)
                send_icmp(data_id, packet_type="data")
                total += 1
                print(f"[DATA] bit={bit}, id={data_id} - Sau {delay:.2f}s")
                num += 1

        # Bước 4: Gửi gói kết thúc
        delay = random.uniform(0.05, 2.0)
        time.sleep(delay)
        end_id = random.randrange(1, 65535)
        send_icmp(end_id, packet_type="end")
        total += 1
        print(f"[END] id={end_id} - Gửi gói kết thúc")
        print(f"Đã gửi tổng cộng {total} gói tin ICMP.")

        # Đợi 5 giây để RECEIVER xử lý và lưu file trước 
        print("⏳ Đợi 5 giây...\n")
        time.sleep(5)

# Ctrl+C
except KeyboardInterrupt:
    print("\n🛑 Đã dừng chương trình theo yêu cầu.")
