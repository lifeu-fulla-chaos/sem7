#!/usr/bin/env python3
"""
udp_video_lowlatency_no_local_preview.py

Same as the original script but with the local preview removed — only the received video is shown.

How to use:
 - Edit REMOTE_IP to point to the other peer's LAN IP and run on both machines.
 - Press 'q' in the *Remote* window to quit.

Dependencies:
    pip install opencv-python numpy
"""

import cv2
import numpy as np
import socket
import threading
import struct
import time

# ------------------ HARD-CODED SETTINGS ------------------
REMOTE_IP = "192.168.1.102"  # <-- set to the other machine's LAN IP
REMOTE_PORT = 5000  # remote UDP port
LOCAL_PORT = 5000  # local UDP port to bind
CAP_DEVICE = 0  # camera index (used by sender)
WIDTH = 320  # capture width (smaller = faster)
HEIGHT = 240  # capture height
JPEG_QUALITY = 45  # 0-100 (lower is smaller/faster)
MTU_PAYLOAD = 1200  # payload bytes per UDP packet (keep <1500)
FRAME_TIMEOUT = 0.20  # seconds to wait for missing chunks before dropping frame
SOCK_BUF_SIZE = 4 * 1024 * 1024  # 4 MiB socket buffers for bursty traffic
# ---------------------------------------------------------

# Packet header: frame_seq:uint32, pts:double (8), total_chunks:uint16, chunk_idx:uint16
HEADER_STRUCT = "!IdHH"
HEADER_SIZE = struct.calcsize(HEADER_STRUCT)

sock = None
running = True


# Sender: encodes frames and sends split packets
def sender_thread():
    global sock, running
    cap = cv2.VideoCapture(CAP_DEVICE, cv2.CAP_V4L2)
    cap.set(cv2.CAP_PROP_FRAME_WIDTH, WIDTH)
    cap.set(cv2.CAP_PROP_FRAME_HEIGHT, HEIGHT)

    if not cap.isOpened():
        print("Failed to open capture device", CAP_DEVICE)
        running = False
        return

    frame_seq = 1
    encode_param = [int(cv2.IMWRITE_JPEG_QUALITY), JPEG_QUALITY]

    print(f"Sender: sending to {REMOTE_IP}:{REMOTE_PORT}")

    while running:
        ret, frame = cap.read()
        if not ret:
            # small sleep so we don't spin if camera died
            time.sleep(0.01)
            continue

        # Optional: resize to target in case camera returns different size
        if frame.shape[1] != WIDTH or frame.shape[0] != HEIGHT:
            frame = cv2.resize(frame, (WIDTH, HEIGHT), interpolation=cv2.INTER_LINEAR)

        ok, buf = cv2.imencode(".jpg", frame, encode_param)
        if not ok:
            continue
        b = buf.tobytes()
        total_len = len(b)
        # compute chunking
        payload = MTU_PAYLOAD
        total_chunks = (total_len + payload - 1) // payload
        pts = time.time()

        # If encoding is too slow, we still send current frame; if network is saturated,
        # sendto will raise occasionally — we ignore and move on (dropping frames).
        for idx in range(total_chunks):
            off = idx * payload
            chunk = b[off : off + payload]
            header = struct.pack(HEADER_STRUCT, frame_seq, pts, total_chunks, idx)
            packet = header + chunk
            try:
                sock.sendto(packet, (REMOTE_IP, REMOTE_PORT))
            except Exception:
                # ignore send errors; prefer dropping to stalling
                pass

        frame_seq = (frame_seq + 1) & 0xFFFFFFFF
    cap.release()


# Receiver: reassembles frames and displays the latest complete frame only
frames = (
    {}
)  # frame_seq -> { 'pts': float, 'total': int, 'received': int, 'chunks': dict, 't': float }
frames_lock = threading.Lock()


def receiver_thread():
    global sock, running
    print(f"Receiver: listening on port {LOCAL_PORT}")
    sock.settimeout(0.02)

    while running:
        try:
            data, addr = sock.recvfrom(65536)
        except socket.timeout:
            # cleanup stale frames
            cleanup_frames()
            continue
        except Exception as e:
            print("Recv error:", e)
            break

        if len(data) <= HEADER_SIZE:
            continue
        header = data[:HEADER_SIZE]
        payload = data[HEADER_SIZE:]
        try:
            frame_seq, pts, total_chunks, chunk_idx = struct.unpack(
                HEADER_STRUCT, header
            )
        except struct.error:
            continue

        with frames_lock:
            entry = frames.get(frame_seq)
            if entry is None:
                entry = {
                    "pts": pts,
                    "total": total_chunks,
                    "received": 0,
                    "chunks": {},
                    "t": time.time(),
                }
                frames[frame_seq] = entry
            # accept chunk if not present
            if chunk_idx not in entry["chunks"]:
                entry["chunks"][chunk_idx] = payload
                entry["received"] += 1

            # if frame complete: decode and display
            if entry["received"] == entry["total"]:
                parts = [entry["chunks"].get(i, b"") for i in range(entry["total"])]
                frame_bytes = b"".join(parts)
                try:
                    arr = np.frombuffer(frame_bytes, dtype=np.uint8)
                    img = cv2.imdecode(arr, cv2.IMREAD_COLOR)
                    if img is not None:
                        # remove older frames to avoid backlog
                        for k in list(frames.keys()):
                            if k <= frame_seq:
                                frames.pop(k, None)
                        # display
                        cv2.imshow("Remote", img)
                        key = cv2.waitKey(1)
                        if key & 0xFF == ord("q"):
                            stop()
                            return
                except Exception:
                    pass
    # end while
    cv2.destroyAllWindows()


def cleanup_frames():
    """Drop frames older than FRAME_TIMEOUT to avoid reassembly backlog."""
    now = time.time()
    with frames_lock:
        stale = [fid for fid, e in frames.items() if now - e["t"] > FRAME_TIMEOUT]
        for fid in stale:
            del frames[fid]


def stop():
    global running
    running = False


def main():
    global sock, running

    # create UDP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    # increase socket buffers so bursts don't drop immediately
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, SOCK_BUF_SIZE)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, SOCK_BUF_SIZE)
    except Exception:
        pass

    # bind local port on all interfaces
    sock.bind(("", LOCAL_PORT))

    # start receiver and sender threads
    recv_t = threading.Thread(target=receiver_thread, daemon=True)
    send_t = threading.Thread(target=sender_thread, daemon=True)
    recv_t.start()
    send_t.start()

    # No local preview: main thread just keeps the program alive until stopped by
    # pressing 'q' in the Remote window or by Ctrl-C.
    try:
        while running:
            time.sleep(0.05)
    except KeyboardInterrupt:
        stop()
    finally:
        running = False
        time.sleep(0.05)
        cv2.destroyAllWindows()
        sock.close()


if __name__ == "__main__":
    print("REMOTE_IP =", REMOTE_IP)
    print("REMOTE_PORT =", REMOTE_PORT)
    print("LOCAL_PORT =", LOCAL_PORT)
    main()
