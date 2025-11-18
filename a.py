# import cv2
# import numpy as np
# import wave
# from moviepy.video.io.ffmpeg_tools import ffmpeg_merge_video_audio

# # Parameters
# width, height = 640, 480
# fps = 30
# duration = 10  # seconds
# total_frames = fps * duration
# samplerate = 44100  # audio samples per second

# # --- Step 1: Generate random noise video ---
# video_filename = "noise_video.mp4"
# out = cv2.VideoWriter(
#     video_filename, cv2.VideoWriter_fourcc(*"mp4v"), fps, (width, height)
# )

# for _ in range(total_frames):
#     frame = np.random.randint(0, 256, (height, width, 3), dtype=np.uint8)
#     out.write(frame)
# out.release()

# # --- Step 2: Generate random noise audio ---
# audio_filename = "noise_audio.wav"
# audio = np.random.uniform(-1, 1, int(samplerate * duration))
# audio_int16 = np.int16(audio * 32767)  # convert to 16-bit PCM

# with wave.open(audio_filename, "w") as wf:
#     wf.setnchannels(1)  # mono
#     wf.setsampwidth(2)  # 16-bit samples
#     wf.setframerate(samplerate)
#     wf.writeframes(audio_int16.tobytes())

# # --- Step 3: Merge video + audio ---
# ffmpeg_merge_video_audio(
#     video_filename,
#     audio_filename,
#     "video.mp4",
# )

# print("✅ Final video saved as 'noise_with_audio.mp4'")


# import cv2

# print(cv2.getBuildInformation())

import cv2

cap = cv2.VideoCapture(0, cv2.CAP_V4L2)
print("opened:", cap.isOpened())
ret, frame = cap.read()
print("read:", bool(ret))
cap.release()
