import socket
import struct

# 注意：被控端要先运行并调用 EXITTHREAD() 函数
# Kali 作为监听端，等待目标反连

host = '0.0.0.0'
port = 4444

# 启动监听
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind((host, port))
server.listen(1)
print(f"[+] Listening on {host}:{port}")

client_socket, addr = server.accept()
print(f"[+] Got connection from {addr}")

# 构造并发送 exitCode（小端，DWORD）
exit_code = 0x0DEAD666
payload = struct.pack("<I", exit_code)
client_socket.sendall(payload)

print(f"[+] Sent exit code: {hex(exit_code)}")

client_socket.close()
server.close()