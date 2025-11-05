import socket
import struct
import numpy as np
import cv2

UDP_IP = "127.0.0.1"
UDP_PORT = 5005
MAX_PACKET = 65507  # max UDP payload

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1024 * 1024 * 8)
sock.bind((UDP_IP, UDP_PORT))

print("✅ SLAVE running: listening on localhost:", UDP_PORT)

while True:
    # Receive the 4-byte size header
    data, _ = sock.recvfrom(4)
    frame_size = struct.unpack("!I", data)[0]

    received = bytearray()
    while len(received) < frame_size:
        packet, _ = sock.recvfrom(MAX_PACKET)
        received.extend(packet)

    # Convert JPEG bytes → numpy array → image
    img_array = np.frombuffer(received, dtype=np.uint8)
    frame = cv2.imdecode(img_array, cv2.IMREAD_COLOR)

    if frame is None:
        print("❌ Frame decode failed. Skipping...")
        continue

    # Show the result
    cv2.imshow("SLAVE: Received Feed", frame)

    if cv2.waitKey(1) == 27:  # ESC exit
        break

cv2.destroyAllWindows()
