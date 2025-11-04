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
            print("inp audio", audio[:10])
            audio_bytes = audio.astype(
                np.dtype("<i2")
            ).tobytes()  # Enforce little-endian int16

            # Encrypt
            # enc_chunk, audio_nonce, auth_tag = encrypt_audio(
            #     chunk_index, audio_bytes, self.sys.state_history[chunk_index]  # type: ignore
            # )
            header = f"{chunk_index:06d}".encode()
            iteration = f"{self.sys.iteration}".encode()
            # Send
            logging.info(
                f"Master: sending chunk {chunk_index}. size {len(audio_bytes) + len(header) + len(iteration)} with iteration {self.sys.iteration}"
            )
            # self.udpSendManager.send_data(
            #     header + iteration + audio_nonce + auth_tag + enc_chunk
            # )

            self.udpSendManager.send_data(header + iteration + audio_bytes)
            chunk_index += 1

        stream.stop()
        stream.close()
        self.udpSendManager.send_data(b"EOF")
        logging.info("Master: finished streaming audio")

    def receive_audio_realtime(self, samplerate=44100, channels=1):
        logging.info("Receiving audio stream...")
        received_chunks = []  # store all decrypted chunks
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
                # audio_nonce = data[7:15]
                # auth_tag = data[15:47]
                # chunk = data[47:]
                chunk = data[7:]
                logging.info(
                    f"Received chunk {header}, size {len(chunk) + 7}, iteration {iteration}"
                )
                if iteration != self.sys.iteration and self.sys.past is not None:
                    state = self.sys.past[header]  # type: ignore
                else:
                    state = self.sys.state_history[header]  # type: ignore
                # dec_chunk = decrypt_audio(chunk, header, audio_nonce, auth_tag, state)  # type: ignore
                audio_array = np.frombuffer(chunk, dtype="<i2")
                audio_array = np.reshape(chunk, (-1, channels))  # type: ignore
                print("dec audio", audio_array[:10])
                stream.write(audio_array)

                received_chunks.append(chunk)

                all_audio = b"".join(received_chunks)
        with wave.open("outfile.wav", "wb") as wf:
            wf.setnchannels(channels)
            wf.setsampwidth(2)  # int16 = 2 bytes
            wf.setframerate(samplerate)
            wf.writeframes(all_audio)  # type: ignore
