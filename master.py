import cv2
import socket
import struct

UDP_IP = "127.0.0.1"  # localhost
UDP_PORT = 5005
CHUNK_SIZE = 4096

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1024 * 1024 * 8)  # 8 MB


cap = cv2.VideoCapture(0)

if not cap.isOpened():
    print("Camera failed to open")
    exit()

while True:
    ret, frame = cap.read()
    if not ret:
        continue

    # Encode to JPEG to reduce size
    success, encoded = cv2.imencode(".jpg", frame, [cv2.IMWRITE_JPEG_QUALITY, 70])
    if not success:
        continue
    
    print(encoded)
    frame_bytes = encoded.tobytes()
    length = len(frame_bytes)


    # Send size first (4 bytes → unsigned int)
    sock.sendto(struct.pack("!I", length), (UDP_IP, UDP_PORT))

    # Send frame in chunks
    offset = 0
    while offset < length:
        sock.sendto(frame_bytes[offset : offset + CHUNK_SIZE], (UDP_IP, UDP_PORT))
        offset += CHUNK_SIZE
