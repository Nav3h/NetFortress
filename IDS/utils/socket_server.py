import socket
from IDS.utils.packet_processor import process_packet

def start_socket_server(detectors, host='localhost', port=9999):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen(5)
    print(f"Socket server listening on {host}:{port}")

    while True:
        client_socket, addr = server_socket.accept()
        print(f"Connection from {addr}")
        data = client_socket.recv(1024)
        if not data:
            break
        process_packet(data, detectors)
        client_socket.close()
