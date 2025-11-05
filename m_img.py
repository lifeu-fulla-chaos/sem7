import cv2
import socket
import struct

UDP_IP = "127.0.0.1"  # localhost
UDP_PORT = 5005
CHUNK_SIZE = 4096  # safe UDP size

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 1024 * 1024 * 8)

cap = cv2.VideoCapture(0)

if not cap.isOpened():
    print("❌ Camera failed to open")
    exit()

print("✅ MASTER started: sending camera frames to UDP port", UDP_PORT)

while True:
    ret, frame = cap.read()
    if not ret:
        continue

    # Show local camera (optional but helpful)
    cv2.imshow("MASTER: Camera Feed", frame)

    # Encode frame into JPEG bytes
    success, encoded = cv2.imencode(".jpg", frame, [cv2.IMWRITE_JPEG_QUALITY, 70])
    if not success:
        continue

    frame_bytes = encoded.tobytes()
    length = len(frame_bytes)

    # Send the size first (4-byte unsigned int)
    sock.sendto(struct.pack("!I", length), (UDP_IP, UDP_PORT))

    # Send the JPEG bytes in chunks
    offset = 0
    while offset < length:
        sock.sendto(frame_bytes[offset : offset + CHUNK_SIZE], (UDP_IP, UDP_PORT))
        offset += CHUNK_SIZE

    if cv2.waitKey(1) == 27:  # ESC to quit
        break

cap.release()
cv2.destroyAllWindows()
