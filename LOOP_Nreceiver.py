from scapy.all import sniff, ICMP, wrpcap, IP
import time
import threading
import subprocess
from datetime import datetime, timedelta

# Các thời điểm trong ngày (giờ phút giây)
time_list = ["03:00:00", "12:30:00", "19:00:00"]

# Ngày bắt đầu
start_day = datetime.strptime("2025-08-19", "%Y-%m-%d")
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

packet_buffer = []
start_index = 2341
session_counter = start_index
count = 0

# Thời gian timeout
NO_PACKET_TIMEOUT = 3     # 3 giây không nhận gói → lưu file
MAX_IDLE_TIMEOUT = 30     # 30 giây không nhận gói → dừng chương trình

last_packet_time = time.time()

def get_next_filename():
    global session_counter
    filename = f"normal_capture_{session_counter:03}.pcap"
    session_counter += 1
    return filename

def packet_handler(pkt):
    global packet_buffer, last_packet_time, count, current_day, time_list, index_time

    # Kiểm tra đúng ICMP và từ IP nguồn mong muốn
    if ICMP in pkt and pkt[IP].src == target_ip:
        if len(packet_buffer) == 0:
            # set giả lập timestamp
            full_time = f"{current_day.strftime('%Y-%m-%d')} {time_list[index_time]}"
            set_system_time_linux(full_time)
            pkt.time = time.time()
            last_packet_time = time.time()
            print(f"[+] Xử lý chuỗi tại: {full_time}")
        count +=1
        print(f"Nhận gói thứ {count}.")
        packet_buffer.append(pkt)
        last_packet_time = time.time()

def check_idle_time():
    global packet_buffer, last_packet_time, count, current_day, time_list, index_time
    while True:
        # check sau mỗi 1 giây
        time.sleep(1)
        now = time.time()
        idle_time = now - last_packet_time

        # Nếu sau 3 giây không có gói nào → lưu file
        if idle_time >= NO_PACKET_TIMEOUT and packet_buffer:
            filename = get_next_filename()
            wrpcap(filename, packet_buffer)
            print(f"[+] Lưu {len(packet_buffer)} gói vào {filename}")
            count = 0
            packet_buffer = []
            index_time = (index_time+1)%len(time_list)
            if index_time == 0:
                current_day += timedelta(days=1)
            #time.sleep(2)

        # Nếu sau 30 giây không có gói nào → kết thúc
        '''if idle_time >= MAX_IDLE_TIMEOUT:
            print("🛑 Không nhận thêm gói trong 30s, kết thúc chương trình.")
            break'''

print("=== Bắt gói ICMP 'normal'... sẽ tự lưu sau 4s không nhận gói, và thoát sau 30s ===")

try:
    # Khởi động thread để theo dõi thời gian chờ không nhận được gói tin
    idle_thread = threading.Thread(target=check_idle_time)
    idle_thread.daemon = True  # Chạy thread này trong nền
    idle_thread.start()
    
    # Cấu hình
    iface_name = "ens33"  # Thay bằng tên interface của bạn
    target_ip = "192.168.146.2"

    sniff(
        iface=iface_name,
        filter=f"icmp and host {target_ip}",
        prn=packet_handler,
        #timeout=1,     # kiểm tra timeout (thoát sniff) mỗi 1 giây
        store=False
        )


except KeyboardInterrupt:
    print("\n🛑 Đã dừng chương trình theo yêu cầu.")
