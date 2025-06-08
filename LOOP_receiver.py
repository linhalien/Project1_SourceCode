from scapy.all import sniff, ICMP, IP, Raw, wrpcap
import time
import threading
import subprocess
from datetime import datetime, timedelta

# Các thời điểm trong ngày (giờ phút giây)
time_list = ["03:00:00", "12:30:00", "19:00:00"]

# Ngày bắt đầu
start_day = datetime.strptime("2025-08-29", "%Y-%m-%d")
#repeat = None  # Số vòng lặp theo ngày (có thể đặt None để lặp vô hạn)

def set_system_time_linux(str_datetime):
    try:
        subprocess.run(["date", "-s", str_datetime], check=True)
        print(f"[+] Đã chỉnh thời gian hệ thống thành: {str_datetime}")
    except subprocess.CalledProcessError as e:
        print(f"[!] Lỗi khi chỉnh thời gian: {e}")

# Bắt đầu lặp
current_day = start_day
index_time = 0

# Cấu hình
delay_bit_1 = 1.5      # Độ trễ cho bit 1
delay_bit_0 = 0.5      # Độ trễ cho bit 0
threshold = (delay_bit_0 + delay_bit_1) / 2  # Ngưỡng xác định bit
source_ip = "192.168.146.129"  # IP của sender (loopback để thử nghiệm)

# Buffer để lưu gói tin
packet_buffer = []
# Thời gian tối đa chờ đợi không có gói tin (30s)
MAX_IDLE_TIME = 30  # seconds
last_packet_time = time.time()

# số thứ tự bắt đầu tên file pcap
start_counter = 1588
session_counter = start_counter

# Hàm set lại tên file pcap theo định dạng
def get_next_filename():
    global session_counter
    filename = f"covert_capture_{session_counter:03}.pcap"
    session_counter += 1
    return filename

# Hàm giải mã binary thành thông điệp
def decode_message(binary_message):
    return ''.join(
        chr(int(binary_message[i:i+8], 2)) for i in range(0, len(binary_message), 8)
        if len(binary_message[i:i+8]) == 8
    )

# Lưu thông điệp đã giải mã vào file txt
def save_decoded_message(message, timestamp):
    with open("decoded_messages.txt", "a") as file:
        file.write(f"{timestamp} - {message}\n")

# Xử lý gói tin
binary_message = ""
previous_timestamp = None
previous_id = None
decoding_started = False

def packet_handler(pkt):
    global packet_buffer, last_packet_time, binary_message, previous_id, previous_timestamp, decoding_started, current_day, index_time, time_list
    icmp_id = pkt[ICMP].id

    # Kiểm tra marker chính (byte 56 = 0x3F)
    payload = bytes(pkt[ICMP].payload)
    if len(payload) < 56 or payload[55] != 0x3F:  # Byte 56 của payload
        return
    
    # Lấy timestamp nhận thực tế từ gói ICMP
    packet_timestamp = time.time()

    # Cập nhật thời gian nhận gói tin mới nhất
    last_packet_time = time.time()

    # Bỏ qua gói trùng
    if previous_id is not None and icmp_id == previous_id:
        return

    # Kiểm tra gói mốc
    if payload[53] == 0x3d and not decoding_started:
        decoding_started = True
            
        # set giả lập timestamp
        full_time = f"{current_day.strftime('%Y-%m-%d')} {time_list[index_time]}"
        set_system_time_linux(full_time)
        print(f"[+] Xử lý chuỗi tại: {full_time}")
        # set lại thời gian bắt đầu bắt chuỗi theo giả lập
        packet_timestamp = time.time()
        pkt.time = packet_timestamp 
        # cập nhật lại theo giả lập
        last_packet_time = time.time() 

        previous_timestamp = packet_timestamp
        previous_id = icmp_id
        print(f"[MOCK] Nhận gói mốc với id={icmp_id}")
        packet_buffer.append(pkt)  # Lưu gói mốc vào buffer
        return

    # Nếu chưa bắt được gói mốc, bỏ qua
    if not decoding_started:
        return

    # Kiểm tra gói kết thúc
    if payload[53] == 0x2b:
        print(f"[END] Nhận gói kết thúc với id={icmp_id}")
        packet_buffer.append(pkt)
        last_packet_time = time.time()
        if binary_message:
            decoded_message = decode_message(binary_message)
            print(f"Decoded binary message: {binary_message}")
            print(f"Decoded message: {decoded_message}")

            # Lưu vào file .txt với timestamp nhận thực tế
            sequence_timestamp = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(packet_timestamp))
            save_decoded_message(decoded_message, sequence_timestamp)

        # Lưu buffer vào file pcap
        filename = get_next_filename()
        wrpcap(filename, packet_buffer)
        print(f"[+] Lưu {len(packet_buffer)} gói vào '{filename}'")

        index_time = (index_time+1)%len(time_list)
        if index_time == 0:
            current_day += timedelta(days=1)

        # Reset buffer, previous_id, decoding_starter, binary_message, 
        # previous_timestamp sau khi xử lý xong
        packet_buffer = []
        binary_message = ""
        previous_timestamp = None
        previous_id = None
        decoding_started = False
        return

    

    # Xử lý gói nhiễu (ID lẻ)
    if icmp_id % 2 != 0:
        print(f"[NOISE] Nhận gói nhiễu với id={icmp_id}")
        packet_buffer.append(pkt)
        last_packet_time = time.time()
        previous_timestamp = packet_timestamp
        previous_id = icmp_id
        return
        
    # Xử lý gói dữ liệu
    if previous_timestamp is not None:
        delay = packet_timestamp - previous_timestamp
        print(f"[DATA] Delay id={icmp_id}: {delay:.3f} seconds")
        if delay >= threshold:
            binary_message += '1'
        elif delay <= threshold and delay > 0.05:
            binary_message += '0'

        print(f"Current binary: {binary_message}")  # Debug

    # Lưu gói vào buffer sau khi xử lý
    previous_timestamp = packet_timestamp
    previous_id = icmp_id
    packet_buffer.append(pkt)
    last_packet_time = time.time()

# Hàm kiểm tra nếu không có gói nào trong MAX_IDLE_TIME thì ngắt
def check_idle_time():
    while True:
        time.sleep(0.5)
        if time.time() - last_packet_time > MAX_IDLE_TIME:
            print(f"🛑 Không nhận gói tin nào trong {MAX_IDLE_TIME} giây. Dừng chương trình.")
            raise SystemExit  # Ngắt chương trình


print("=== Đang bắt gói ICMP liên tục... Nhấn Ctrl + C để dừng ===")
# bắt và lưu liên tục. Lưu xong thì bắt lại ngay
try:
    iface_name = "ens33"  
    target_ip = source_ip
    # Khởi động thread để theo dõi thời gian chờ không nhận được gói tin

    '''idle_thread = threading.Thread(target=check_idle_time)
    idle_thread.daemon = True  # Chạy thread này trong nền
    idle_thread.start()'''

    sniff(
        iface = iface_name,
        filter=f"icmp and src {target_ip}",
        prn=packet_handler,
        store=False)

except KeyboardInterrupt:
    print("\n🛑 Đã dừng chương trình.")
