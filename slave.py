import socket
import struct
import numpy as np
import cv2

UDP_IP = "127.0.0.1"
UDP_PORT = 5005
CHUNK_SIZE = 4096

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1024 * 1024 * 8)  # 8 MB

sock.bind((UDP_IP, UDP_PORT))

print("Slave listening on localhost:5005")

while True:
    # Receive the 4-byte frame size
    data, _ = sock.recvfrom(4)
    frame_size = struct.unpack("!I", data)[0]

    received = bytearray()
    while len(received) < frame_size:
        packet, _ = sock.recvfrom(CHUNK_SIZE)
        received.extend(packet)

    # Decode JPEG into image
    
    img_array = np.frombuffer(received, dtype=np.uint8)
    print(img_array)
    frame = cv2.imdecode(img_array, cv2.IMREAD_COLOR)

    if frame is not None:
        cv2.imshow("UDP Camera Feed", frame)

    if cv2.waitKey(1) == 27:  # ESC exit
        break

cv2.destroyAllWindows()
