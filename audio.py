import time
import sounddevice as sd
from encryption import xor_encrypt, xor_decrypt
import numpy as np  # type: ignore
from network import NetworkManager

HOST = "0.0.0.0"
PORT_UDP = 4000
SEND_UDP = 4001


class AudioHandler:
    def __init__(self, sys, recv_host):
        self.sys = sys
        self.udpSendManager = NetworkManager(
            HOST, PORT_UDP, "udp", (recv_host, SEND_UDP)
        )
        self.udpRecvManager = NetworkManager(HOST, SEND_UDP, "udp", None)

    def send_audio_from_mic_realtime(
        self, duration=10, samplerate=44100, channels=1, chunk_size=8192
    ):
        print("Streaming mic audio for", duration, "seconds...")
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
            enc_chunk, _ = xor_encrypt(audio_bytes, self.sys.state_history[-1])  # type: ignore
            header = f"{chunk_index:06d}".encode()
            iteration = f"{self.sys.iteration}".encode()
            # print("encryption", self.sys.state_history[-1])
            # state = self.sys.state_history[-1].tobytes()
            # Send
            print(
                f"Master: sending chunk {chunk_index}. size {len(enc_chunk)} with iteration {self.sys.iteration}"
            )
            self.udpSendManager.send_data(header + iteration + bytes.fromhex(enc_chunk))
            # self.udpSendManager.send_data(header + iteration + enc)
            chunk_index += 1

        stream.stop()
        stream.close()
        self.udpSendManager.send_data(b"EOF")
        print("Master: finished streaming audio")

    def receive_audio_realtime(self, samplerate=44100, channels=1):
        print("Receiving audio stream...")
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
                # state = np.frombuffer(data[7:], dtype=float)  # type: ignore
                chunk = data[7:]
                while iteration > self.sys.iteration:
                    time.sleep(0.01)
                hist = self.sys.state_history[-1]
                if iteration < self.sys.iteration:
                    hist = self.sys.past
                # if np.equal(hist, state).all():
                #     print(
                #         f"Received matching state for chunk {header} iteration {iteration}"
                #     )
                # else:
                #     print(
                #         f"State mismatch! Chunk {header} Received: {state}, Expected: {hist}, Iteration: {iteration}"
                #     )
                # Decrypt
                dec_chunk, _ = xor_decrypt(chunk, hist)  # type: ignore
                seq = int(header.decode())  # type: ignore
                print(
                    f"Received chunk {seq}, size {len(dec_chunk)}, iteration {iteration}"
                )
                audio_array = np.frombuffer(dec_chunk, dtype=np.int16)  # type: ignore
                stream.write(audio_array)
