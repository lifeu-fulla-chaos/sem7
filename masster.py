#!/usr/bin/env python3
"""
udp_video_lowlatency.py

Low-latency 2-way video over UDP for same-LAN peers.
Hardcode REMOTE_IP to the other machine's LAN IP and run on both machines.

Dependencies:
    pip install opencv-python numpy

How to use:
 - Edit the hardcoded settings below so each peer's REMOTE_IP points to the other.
 - Run: python3 udp_video_lowlatency.py
 - Press 'q' in any window to quit.

Notes / tuning:
 - WIDTH/HEIGHT: smaller -> lower bandwidth and lower encode time (e.g. 320x240)
 - JPEG_QUALITY: lower -> less bytes -> lower latency, but worse image
 - MTU_PAYLOAD: set < 1500; 1200 is safe for most LANs.
 - FRAME_TIMEOUT: short timeout to drop incomplete frames quickly
 - SO_SNDBUF / SO_RCVBUF are increased for smoother bursts on busy networks
 - If you want even lower latency, use hardware h264 encode (ffmpeg/gstreamer) instead.
"""

import cv2
import numpy as np
import socket
import threading
import struct
import time

# ------------------ HARD-CODED SETTINGS ------------------
REMOTE_IP = "192.168.1.100"  # <-- set to the other machine's LAN IP
REMOTE_PORT = 5000  # remote UDP port
LOCAL_PORT = 5000  # local UDP port to bind
CAP_DEVICE = 0  # camera index
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
    cap = cv2.VideoCapture(CAP_DEVICE, cv2.CAP_ANY)
    cap.set(cv2.CAP_PROP_FRAME_WIDTH, WIDTH)
    cap.set(cv2.CAP_PROP_FRAME_HEIGHT, HEIGHT)

    if not cap.isOpened():
        print("Failed to open capture device", CAP_DEVICE)
        running = False
        return

    frame_seq = 1
    encode_param = [int(cv2.IMWRITE_JPEG_QUALITY), JPEG_QUALITY]
    last_send_time = 0.0

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
        # no sleep here to minimize added latency; capture/encode cost throttles loop
        # optional minimal throttle if you want to cap fps:
        # time.sleep(0.002)
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
    last_display_seq = 0

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

            # if frame complete: decode and display, but only if it's newer than last displayed
            if entry["received"] == entry["total"]:
                # assemble
                parts = [entry["chunks"].get(i, b"") for i in range(entry["total"])]
                frame_bytes = b"".join(parts)
                try:
                    arr = np.frombuffer(frame_bytes, dtype=np.uint8)
                    img = cv2.imdecode(arr, cv2.IMREAD_COLOR)
                    if img is not None:
                        # show immediately the newest complete frame
                        # remove older frames to avoid backlog
                        # drop older-than-current
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
    # final cleanup
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

    # local preview (show local camera in main thread)
    local_cap = cv2.VideoCapture(CAP_DEVICE, cv2.CAP_ANY)
    local_cap.set(cv2.CAP_PROP_FRAME_WIDTH, WIDTH)
    local_cap.set(cv2.CAP_PROP_FRAME_HEIGHT, HEIGHT)
    if not local_cap.isOpened():
        print("Warning: cannot open capture device for local preview.")

    try:
        while running:
            if local_cap.isOpened():
                ret, frame = local_cap.read()
                if ret:
                    cv2.imshow("Local", frame)
                    if cv2.waitKey(1) & 0xFF == ord("q"):
                        stop()
                        break
                else:
                    time.sleep(0.01)
            else:
                time.sleep(0.05)
    except KeyboardInterrupt:
        stop()
    finally:
        running = False
        local_cap.release()
        time.sleep(0.05)
        cv2.destroyAllWindows()
        sock.close()


if __name__ == "__main__":
    print("REMOTE_IP =", REMOTE_IP)
    print("REMOTE_PORT =", REMOTE_PORT)
    print("LOCAL_PORT =", LOCAL_PORT)
    main()
