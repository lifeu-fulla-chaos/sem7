import sounddevice as sd
import numpy as np

# Parameters (must match what was used for recording/sending)
samplerate = 44100
channels = 1
dtype = "int16"  # or 'float32', etc.

with open("received_audio.raw", "rb") as f:
    audio_bytes = f.read()

audio_array = np.frombuffer(audio_bytes, dtype=dtype)
sd.play(audio_array, samplerate=samplerate)
sd.wait()
