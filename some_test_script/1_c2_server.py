import socket

HOST = '0.0.0.0'  # 监听所有可用的网络接口，
PORT = 4444

def start_c2_server():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) # 允许重用地址
        s.bind((HOST, PORT))
        s.listen()
        print(f"C2 server listening on {HOST}:{PORT}")

        conn, addr = s.accept()
        with conn:
            print(f"Connected by {addr}")
            command = b"launch" # 发送"launch"指令
            conn.sendall(command)
            print(f"Sent command: {command.decode()}")
            # 可以选择接收客户端的响应
            # data = conn.recv(1024)
            # print(f"Received from client: {data.decode()}")

if __name__ == "__main__":
    start_c2_server()