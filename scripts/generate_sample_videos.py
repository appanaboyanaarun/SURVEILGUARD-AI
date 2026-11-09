import os
import sys
import cv2
import numpy as np

# Ensure project root on path
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

OUTPUT_DIR = os.path.join(BASE_DIR, "data", "sample_videos")
os.makedirs(OUTPUT_DIR, exist_ok=True)


def get_video_writer(filename, fps, width, height):
    """Creates a VideoWriter with fallback codecs."""
    codecs = ["mp4v", "XVID", "MJPG", "avc1"]
    for c in codecs:
        try:
            fourcc = cv2.VideoWriter_fourcc(*c)
            out = cv2.VideoWriter(filename, fourcc, fps, (width, height))
            if out.isOpened():
                return out
        except Exception:
            continue
    # Fallback to default fourcc 0
    return cv2.VideoWriter(filename, 0, fps, (width, height))


def draw_human_silhouette(frame, center_x, center_y, scale=1.0, color=(50, 50, 50)):
    """Draws a stylized human silhouette figure on a video frame."""
    cx, cy = int(center_x), int(center_y)
    
    # Head
    head_radius = int(14 * scale)
    head_center = (cx, cy - int(45 * scale))
    cv2.circle(frame, head_center, head_radius, color, -1)
    
    # Torso (Upper body)
    torso_top = (cx - int(16 * scale), cy - int(30 * scale))
    torso_bottom = (cx + int(16 * scale), cy + int(20 * scale))
    cv2.rectangle(frame, torso_top, torso_bottom, color, -1)
    
    # Legs
    leg_width = int(6 * scale)
    # Left leg
    cv2.rectangle(frame, (cx - int(12 * scale), cy + int(20 * scale)), (cx - int(12 * scale) + leg_width, cy + int(70 * scale)), color, -1)
    # Right leg
    cv2.rectangle(frame, (cx + int(6 * scale), cy + int(20 * scale)), (cx + int(6 * scale) + leg_width, cy + int(70 * scale)), color, -1)
    
    # Arms
    arm_width = int(5 * scale)
    cv2.rectangle(frame, (cx - int(22 * scale), cy - int(28 * scale)), (cx - int(17 * scale), cy + int(15 * scale)), color, -1)
    cv2.rectangle(frame, (cx + int(17 * scale), cy - int(28 * scale)), (cx + int(22 * scale), cy + int(15 * scale)), color, -1)


def generate_video_1_normal_day():
    """Generates Normal Daytime Passage video for CAM-01."""
    filename = os.path.join(OUTPUT_DIR, "cam01_main_gate_normal_day.mp4")
    width, height = 640, 480
    fps = 25
    duration_sec = 6
    total_frames = fps * duration_sec
    
    out = get_video_writer(filename, fps, width, height)
    
    for i in range(total_frames):
        frame = np.full((height, width, 3), (215, 220, 225), dtype=np.uint8)
        cv2.line(frame, (0, 360), (width, 360), (180, 185, 190), 2)
        
        cv2.rectangle(frame, (int(width * 0.6), int(height * 0.2)), (int(width * 0.95), int(height * 0.85)), (200, 200, 200), 1)
        cv2.putText(frame, "[RESTRICTED REGION]", (int(width * 0.6) + 10, int(height * 0.2) + 25), cv2.FONT_HERSHEY_SIMPLEX, 0.5, (160, 160, 160), 1)

        pos_x = 80 + int((i / float(total_frames)) * 240)
        pos_y = 280
        draw_human_silhouette(frame, pos_x, pos_y, scale=1.1, color=(60, 60, 80))

        cv2.putText(frame, "CAM-01 [MAIN GATE] | 2026-09-20 11:20:15 | DAY MODE", (15, 30), cv2.FONT_HERSHEY_SIMPLEX, 0.55, (20, 20, 20), 2)
        out.write(frame)

    out.release()
    print(f"Generated: {filename}")


def generate_video_2_night_intrusion():
    """Generates Night Intrusion video for CAM-03 (3 people entering restricted area at night)."""
    filename = os.path.join(OUTPUT_DIR, "cam03_storage_night_intrusion.mp4")
    width, height = 640, 480
    fps = 25
    duration_sec = 8
    total_frames = fps * duration_sec

    out = get_video_writer(filename, fps, width, height)

    for i in range(total_frames):
        frame = np.full((height, width, 3), (35, 30, 25), dtype=np.uint8)
        
        cv2.rectangle(frame, (50, 100), (220, 380), (45, 40, 35), -1)
        cv2.rectangle(frame, (50, 100), (220, 380), (60, 55, 50), 2)
        cv2.putText(frame, "VAULT ENTRANCE", (60, 130), cv2.FONT_HERSHEY_SIMPLEX, 0.45, (80, 75, 70), 1)

        rx1, ry1 = int(width * 0.45), int(height * 0.15)
        rx2, ry2 = int(width * 0.95), int(height * 0.85)
        cv2.rectangle(frame, (rx1, ry1), (rx2, ry2), (0, 0, 150), 2)
        cv2.putText(frame, "RESTRICTED STORAGE ZONE", (rx1 + 10, ry1 + 25), cv2.FONT_HERSHEY_SIMPLEX, 0.5, (0, 0, 220), 1)

        progress = i / float(total_frames)
        p1_x = 100 + int(progress * 320)
        p2_x = 50 + int(progress * 310)
        p3_x = 20 + int(progress * 300)

        p1_y = 260
        p2_y = 280
        p3_y = 300

        draw_human_silhouette(frame, p1_x, p1_y, scale=1.1, color=(140, 130, 120))
        draw_human_silhouette(frame, p2_x, p2_y, scale=1.0, color=(120, 110, 100))
        draw_human_silhouette(frame, p3_x, p3_y, scale=1.05, color=(130, 120, 110))

        cv2.putText(frame, "CAM-03 [STORAGE AREA] | 2026-09-20 23:42:15 | NIGHT IR", (15, 30), cv2.FONT_HERSHEY_SIMPLEX, 0.55, (0, 255, 0), 2)
        out.write(frame)

    out.release()
    print(f"Generated: {filename}")


def generate_video_3_parking_loitering():
    """Generates Loitering video for CAM-02 (2 people lingering in parking area)."""
    filename = os.path.join(OUTPUT_DIR, "cam02_parking_evening_loitering.mp4")
    width, height = 640, 480
    fps = 25
    duration_sec = 7
    total_frames = fps * duration_sec

    out = get_video_writer(filename, fps, width, height)

    for i in range(total_frames):
        frame = np.full((height, width, 3), (70, 75, 80), dtype=np.uint8)

        for px in [100, 250, 400, 550]:
            cv2.line(frame, (px, 200), (px - 50, 460), (90, 95, 100), 2)

        sin_val = np.sin(i / 15.0)
        p1_x = 300 + int(sin_val * 40)
        p2_x = 360 + int(sin_val * 30)

        draw_human_silhouette(frame, p1_x, 270, scale=1.0, color=(35, 35, 45))
        draw_human_silhouette(frame, p2_x, 280, scale=1.05, color=(40, 40, 50))

        cv2.putText(frame, "CAM-02 [PARKING AREA] | 2026-09-20 20:15:30 | EVENING", (15, 30), cv2.FONT_HERSHEY_SIMPLEX, 0.55, (220, 220, 220), 2)
        out.write(frame)

    out.release()
    print(f"Generated: {filename}")


if __name__ == "__main__":
    print("Generating synthetic surveillance test videos...")
    generate_video_1_normal_day()
    generate_video_2_night_intrusion()
    generate_video_3_parking_loitering()
    print("All sample surveillance videos generated successfully in data/sample_videos/")
