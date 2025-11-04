import wave
import time
import sounddevice as sd
import cv2
import numpy as np
import logging
from network import NetworkManager
from lorenz_system import LorenzSystem

# from encryption import encrypt_audio, decrypt_audio  # optional

HOST = "0.0.0.0"
PORT_UDP = 4000
SEND_UDP = 4001
PORT_VIDEO = 5000
SEND_VIDEO = 5001


class AudioHandler:
    def __init__(self, sys: LorenzSystem, recv_host):
        self.sys = sys
        # Audio
        self.udpSendManager = NetworkManager(
            HOST, PORT_UDP, "udp", (recv_host, SEND_UDP)
        )
        self.udpRecvManager = NetworkManager(HOST, SEND_UDP, "udp", None)
        # Video
        self.udpSendVideo = NetworkManager(
            HOST, PORT_VIDEO, "udp", (recv_host, SEND_VIDEO)
        )
        self.udpRecvVideo = NetworkManager(HOST, SEND_VIDEO, "udp", None)

    def send_audio_from_mic_realtime(
        self, duration=10, samplerate=44100, channels=1, chunk_size=8192, fps=20
    ):
        logging.info(f"Streaming mic audio and webcam video for {duration} seconds...")

        # --- Audio setup ---
        stream = sd.InputStream(
            samplerate=samplerate,
            channels=channels,
            dtype="int16",
            blocksize=chunk_size,
        )
        stream.start()

        # --- Video setup ---
        cap = cv2.VideoCapture(0)
        if not cap.isOpened():
            logging.warning("Could not open webcam.")

        start_time = time.time()
        chunk_index = 0
        frame_index = 0
        next_video_time = 0

        while time.time() - start_time < duration:
            # --- AUDIO CAPTURE & SEND ---
            audio, _ = stream.read(chunk_size)
            audio_bytes = audio.astype(np.dtype("<i2")).tobytes()
            header = f"{chunk_index:06d}".encode()
            iteration = f"{self.sys.iteration}".encode()

            # logging.info(f"Sending audio chunk {chunk_index}")
            self.udpSendManager.send_data(header + iteration + audio_bytes)
            chunk_index += 1

            # --- VIDEO CAPTURE & SEND ---
            current_time = time.time()
            if current_time >= next_video_time:
                ret, frame = cap.read()
                if ret:
                    _, buffer = cv2.imencode(
                        ".jpg", frame, [cv2.IMWRITE_JPEG_QUALITY, 70]
                    )
                    data = buffer.tobytes()
                    vheader = f"{frame_index:06d}".encode()
                    viteration = f"{self.sys.iteration}".encode()
                    try:
                        self.udpSendVideo.send_data(vheader + viteration + data)
                        # logging.info(f"Sent video frame {frame_index}")
                    except Exception as e:
                        logging.warning(f"Video send error: {e}")
                    frame_index += 1
                next_video_time = current_time + (1 / fps)

        stream.stop()
        stream.close()
        if cap.isOpened():
            cap.release()

        self.udpSendManager.send_data(b"EOF")
        self.udpSendVideo.send_data(b"EOF")

        logging.info("Master: finished streaming audio and video")

    def receive_audio_realtime(self, samplerate=44100, channels=1):
        logging.info("Receiving audio and video streams...")

        # --- Start audio output ---
        stream = sd.OutputStream(
            samplerate=samplerate, channels=channels, dtype="int16"
        )
        stream.start()

        cv2.namedWindow("Received Video", cv2.WINDOW_NORMAL)
        cv2.resizeWindow("Received Video", 640, 480)

        while True:
            # --- AUDIO RECEIVE ---
            data = self.udpRecvManager.receive_data()
            if data == b"EOF":
                break
            if data:
                header = int(data[:6].decode()) # type: ignore
                iteration = int(data[6:7].decode()) # type: ignore
                chunk = data[7:]
                audio_array = np.frombuffer(chunk, dtype="<i2").reshape(-1, channels)
                stream.write(audio_array)

            # --- VIDEO RECEIVE ---
            vdata = self.udpRecvVideo.receive_data()
            if vdata == b"EOF":
                break
            if vdata:
                try:
                    vheader = int(vdata[:6].decode()) # type: ignore
                    viteration = int(vdata[6:7].decode()) # type: ignore
                    jpg = vdata[7:]
                    frame = cv2.imdecode(
                        np.frombuffer(jpg, dtype=np.uint8), cv2.IMREAD_COLOR
                    )
                    if frame is not None:
                        cv2.imshow("Received Video", frame)
                        if cv2.waitKey(1) & 0xFF == ord("q"):
                            break
                except Exception as e:
                    logging.warning(f"Video decode error: {e}")

        stream.stop()
        stream.close()
        cv2.destroyAllWindows()
        logging.info("Receiver: finished audio/video playback")
