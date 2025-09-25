import wave
import time
import sounddevice as sd
from encryption import *
import numpy as np  # type: ignore
from network import NetworkManager
import logging
from lorenz_system import LorenzSystem

HOST = "0.0.0.0"
PORT_UDP = 4000
SEND_UDP = 4001


class AudioHandler:
    def __init__(self, sys: LorenzSystem, recv_host):
        self.sys = sys
        self.udpSendManager = NetworkManager(
            HOST, PORT_UDP, "udp", (recv_host, SEND_UDP)
        )
        self.udpRecvManager = NetworkManager(HOST, SEND_UDP, "udp", None)

    def send_audio_from_mic_realtime(
        self, duration=10, samplerate=44100, channels=1, chunk_size=8192
    ):
        logging.info(f"Streaming mic audio for {duration} seconds...")
        start_time = time.time()
        stream = sd.InputStream(
            samplerate=samplerate,
            channels=channels,
            dtype="int16",
            blocksize=chunk_size,
        )
        stream.start()

        chunk_index = 0
        while time.time() - start_time < duration:
            audio, _ = stream.read(chunk_size)
            audio_bytes = audio.tobytes()

            # Encrypt
            enc_chunk, audio_nonce, auth_tag = encrypt_audio(
                chunk_index, audio_bytes, self.sys.state_history[chunk_index]  # type: ignore
            )
            header = f"{chunk_index:06d}".encode()
            iteration = f"{self.sys.iteration}".encode()
            # Send
            logging.info(
                f"Master: sending chunk {chunk_index}. size {len(enc_chunk) + len(header) + len(iteration) + len(audio_nonce) + len(auth_tag)} with iteration {self.sys.iteration}"
            )
            self.udpSendManager.send_data(
                header + iteration + audio_nonce + auth_tag + enc_chunk
            )
            chunk_index += 1

        stream.stop()
        stream.close()
        self.udpSendManager.send_data(b"EOF")
        logging.info("Master: finished streaming audio")

    def receive_audio_realtime(self, samplerate=44100, channels=1):
        logging.info("Receiving audio stream...")
        with sd.OutputStream(
            samplerate=samplerate, channels=channels, dtype="int16"
        ) as stream:
            while True:
                data = self.udpRecvManager.receive_data()
                if data is None:
                    continue
                if data == b"EOF":
                    break

                header = int(data[:6].decode())  # type: ignore
                iteration = int(data[6:7].decode())  # type: ignore
                audio_nonce = data[7:15]
                auth_tag = data[15:47]
                chunk = data[47:]
                logging.info(
                    f"Received chunk {header}, size {len(chunk) + len(audio_nonce) + len(auth_tag) + 7}, iteration {iteration}"
                )
                if iteration != self.sys.iteration and self.sys.past is not None:
                    state = self.sys.past[header] # type: ignore
                else:
                    state = self.sys.state_history[header] # type: ignore
                dec_chunk = decrypt_audio(chunk, header, audio_nonce, auth_tag, state)  # type: ignore

                audio_array = np.frombuffer(dec_chunk, dtype="<i2")  # type: ignore
                # audio_array = np.reshape(audio_array, (-1, channels))  # type: ignore
                print(audio_array[:100])
                stream.write(audio_array)
