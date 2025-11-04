# ...existing code...
import wave
import time
import sounddevice as sd
import cv2
import numpy as np
import logging
from network import NetworkManager
from lorenz_system import LorenzSystem
import threading
from typing import Optional

# ...existing code...


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
        # control
        self._recv_stop = threading.Event()
        self._audio_send_thread: Optional[threading.Thread] = None
        self._video_receive_thread: Optional[threading.Thread] = None
        self._audio_receive_thread: Optional[threading.Thread] = None
        self._video_send_thread: Optional[threading.Thread] = None

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
            try:
                audio, _ = stream.read(chunk_size)
            except Exception as e:
                logging.warning("Audio read failed: %s", e)
                break

            # ensure int16
            audio_int16 = audio.astype(np.dtype("<i2"))
            audio_bytes = audio_int16.tobytes()
            header = f"{chunk_index:06d}".encode()
            iteration = f"{self.sys.iteration}".encode()

            # logging.info(f"Sending audio chunk {chunk_index}")
            try:
                self.udpSendManager.send_data(header + iteration + audio_bytes)
            except Exception as e:
                logging.warning("Audio send error: %s", e)
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
                    except Exception as e:
                        logging.warning(f"Video send error: {e}")
                    frame_index += 1
                next_video_time = current_time + (1 / fps)

        stream.stop()
        stream.close()
        if cap.isOpened():
            cap.release()

        try:
            self.udpSendManager.send_data(b"EOF")
        except Exception:
            pass
        try:
            self.udpSendVideo.send_data(b"EOF")
        except Exception:
            pass

        logging.info("Master: finished streaming audio and video")

    def _audio_receive_loop(self, samplerate=44100, channels=1):
        logging.info("Audio receive thread started")
        # start output stream in blocking mode inside this thread
        stream = sd.OutputStream(
            samplerate=samplerate, channels=channels, dtype="int16"
        )
        stream.start()
        try:
            while not self._recv_stop.is_set():
                try:
                    data = self.udpRecvManager.receive_data()
                except Exception as e:
                    logging.warning("Audio receive error: %s", e)
                    continue
                if not data:
                    continue
                if data == b"EOF":
                    logging.info("Audio EOF received")
                    self._recv_stop.set()
                    break
                # parse header/iteration
                try:
                    header = data[:6].decode()  # type: ignore
                    _iteration = int(data[6:7].decode())  # type: ignore
                    chunk = data[7:]
                except Exception as e:
                    logging.warning("Malformed audio packet: %s", e)
                    continue

                # convert bytes -> int16 array (little-endian)
                try:
                    audio_array = np.frombuffer(chunk, dtype="<i2")  # type: ignore
                except Exception as e:
                    logging.warning("Failed to convert audio bytes: %s", e)
                    continue

                if audio_array.size == 0:
                    logging.debug("Empty audio chunk received, skipping")
                    continue

                # align to channels
                if audio_array.size % channels != 0:
                    valid_len = (audio_array.size // channels) * channels
                    if valid_len == 0:
                        logging.debug("Chunk too small after trimming, skipping")
                        continue
                    audio_array = audio_array[:valid_len]

                try:
                    audio_array = audio_array.reshape(-1, channels)
                except Exception as e:
                    logging.warning("Audio reshape failed: %s", e)
                    continue

                # write to output
                try:
                    stream.write(audio_array)
                except Exception as e:
                    logging.warning("Audio stream write failed: %s", e)
                    continue

        finally:
            stream.stop()
            stream.close()
            logging.info("Audio receive thread exiting")

    def _video_receive_loop(self, window_name="Received Video"):
        logging.info("Video receive thread started")
        cv2.namedWindow(window_name, cv2.WINDOW_NORMAL)
        try:
            while not self._recv_stop.is_set():
                try:
                    vdata = self.udpRecvVideo.receive_data()
                except Exception as e:
                    logging.warning("Video receive error: %s", e)
                    continue
                if not vdata:
                    continue
                if vdata == b"EOF":
                    logging.info("Video EOF received")
                    self._recv_stop.set()
                    break
                try:
                    vheader = int(vdata[:6].decode())  # type: ignore
                    _viteration = int(vdata[6:7].decode())  # type: ignore
                    jpg = vdata[7:]
                    frame = cv2.imdecode(
                        np.frombuffer(jpg, dtype=np.uint8), cv2.IMREAD_COLOR  # type: ignore
                    )  # type: ignore
                    if frame is not None:
                        cv2.imshow(window_name, frame)
                        if cv2.waitKey(1) & 0xFF == ord("q"):
                            self._recv_stop.set()
                            break
                except Exception as e:
                    logging.warning("Video decode error: %s", e)
                    continue
        finally:
            cv2.destroyAllWindows()
            logging.info("Video receive thread exiting")

    def receive_audio_realtime(self, samplerate=44100, channels=1):
        logging.info("Receiving audio and video streams...")
        self._recv_stop.clear()
        # start threads
        self._audio_receive_thread = threading.Thread(
            target=self._audio_receive_loop, args=(samplerate, channels), daemon=True
        )
        self._video_receive_thread = threading.Thread(
            target=self._video_receive_loop, daemon=True
        )
        self._audio_receive_thread.start()
        self._video_receive_thread.start()
        # wait until stop requested
        try:
            while not self._recv_stop.is_set():
                time.sleep(0.1)
        except KeyboardInterrupt:
            logging.info("Interrupted by user, stopping receive")
            self._recv_stop.set()
        # join threads
        self._audio_receive_thread.join()
        self._video_receive_thread.join()
        logging.info("Receiver: finished audio/video playback")
