"""
Test script for the Live Suspicious Activity Detection API.

Usage:
    python test_live_detection.py [--base-url http://127.0.0.1:8000]

Tests:
    1. GET  /api/v1/live/settings           -- Fetch default settings
    2. POST /api/v1/live/settings           -- Update detection config
    3. POST /api/v1/live/detect             -- Submit a synthetic frame
    4. WebSocket /ws/live-detection          -- Connect & send a frame via WS
"""

import argparse
import asyncio
import base64
import json
import sys
import os
import io

# Force UTF-8 output on Windows
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")


# Ensure project root is on PYTHONPATH
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import requests
import numpy as np
import cv2


def make_test_frame(width: int = 640, height: int = 480) -> bytes:
    """Generate a synthetic test frame with a person-like shape drawn on it."""
    frame = np.zeros((height, width, 3), dtype=np.uint8)
    # Dark background with some noise
    frame[:] = (30, 30, 40)
    noise = np.random.randint(0, 15, frame.shape, dtype=np.uint8)
    frame = cv2.add(frame, noise)

    # Draw a simple person-like silhouette (rectangle + circle)
    # Body
    cv2.rectangle(frame, (280, 200), (360, 400), (180, 180, 180), -1)
    # Head
    cv2.circle(frame, (320, 175), 30, (200, 200, 200), -1)
    # Add some motion-like blur streak
    cv2.line(frame, (100, 300), (200, 280), (0, 0, 200), 3)
    cv2.line(frame, (450, 250), (550, 270), (0, 0, 200), 3)

    _, buf = cv2.imencode(".jpg", frame)
    return buf.tobytes()


def test_get_settings(base_url: str):
    """Test: Fetch current detection settings."""
    print("\n" + "=" * 60)
    print("TEST 1: GET /api/v1/live/settings")
    print("=" * 60)
    url = f"{base_url}/api/v1/live/settings"
    resp = requests.get(url)
    print(f"  Status: {resp.status_code}")
    if resp.status_code == 200:
        data = resp.json()
        print(f"  Sensitivity:          {data.get('sensitivity')}")
        print(f"  Motion Threshold:     {data.get('motion_threshold')}")
        print(f"  Person Count Thresh:  {data.get('person_count_threshold')}")
        print(f"  Enabled Categories:   {data.get('enabled_categories')}")
        print(f"  ROI Zones:            {len(data.get('roi_zones', []))} zone(s)")
        print("  ✅ PASSED")
    else:
        print(f"  ❌ FAILED — {resp.text}")
    return resp.status_code == 200


def test_update_settings(base_url: str):
    """Test: Update detection settings."""
    print("\n" + "=" * 60)
    print("TEST 2: POST /api/v1/live/settings")
    print("=" * 60)
    url = f"{base_url}/api/v1/live/settings"
    payload = {
        "sensitivity": 0.5,
        "motion_threshold": 0.08,
        "person_count_threshold": 2,
        "roi_zones": [
            {
                "name": "Server Room Perimeter",
                "coordinates": [[0.5, 0.2], [0.95, 0.2], [0.95, 0.85], [0.5, 0.85]],
            }
        ],
        "enabled_categories": ["intrusion", "rapid_motion", "group_gathering"],
    }
    resp = requests.post(url, json=payload)
    print(f"  Status: {resp.status_code}")
    if resp.status_code == 200:
        data = resp.json()
        assert data["sensitivity"] == 0.5, f"Expected sensitivity 0.5, got {data['sensitivity']}"
        assert len(data["roi_zones"]) == 1, "Expected 1 ROI zone"
        print(f"  Updated Sensitivity:  {data['sensitivity']}")
        print(f"  Updated ROI Zones:    {len(data['roi_zones'])} zone(s)")
        print(f"  Updated Categories:   {data['enabled_categories']}")
        print("  ✅ PASSED")
    else:
        print(f"  ❌ FAILED — {resp.text}")
    return resp.status_code == 200


def test_detect_frame(base_url: str):
    """Test: Submit a frame for live anomaly detection."""
    print("\n" + "=" * 60)
    print("TEST 3: POST /api/v1/live/detect")
    print("=" * 60)
    url = f"{base_url}/api/v1/live/detect"
    frame_bytes = make_test_frame()

    files = {"frame": ("test_frame.jpg", frame_bytes, "image/jpeg")}
    data = {"camera_id": "CAM-TEST", "location": "Test Location"}
    resp = requests.post(url, files=files, data=data)
    print(f"  Status: {resp.status_code}")
    if resp.status_code == 200:
        result = resp.json()
        print(f"  Camera ID:      {result['camera_id']}")
        print(f"  Timestamp:      {result['timestamp']}")
        print(f"  Person Count:   {result['person_count']}")
        print(f"  Motion Score:   {result['motion_score']}")
        print(f"  Motion Level:   {result['motion_level']}")
        print(f"  Anomaly Score:  {result['anomaly_score']}")
        print(f"  Status:         {result['status']}")
        print(f"  Risk Priority:  {result['risk_priority']}")
        print(f"  Activity Type:  {result['activity_type']}")
        print(f"  Boxes Detected: {len(result.get('boxes', []))}")
        if result.get("alert"):
            print(f"  🚨 ALERT:       Event {result['alert']['event_id']} created!")
        print("  ✅ PASSED")
    else:
        print(f"  ❌ FAILED — {resp.text}")
    return resp.status_code == 200


def test_websocket(base_url: str):
    """Test: WebSocket connection and frame submission."""
    print("\n" + "=" * 60)
    print("TEST 4: WebSocket /ws/live-detection")
    print("=" * 60)

    try:
        import websockets
    except ImportError:
        print("  ⚠️  SKIPPED — 'websockets' package not installed.")
        print("  Install with: pip install websockets")
        return True  # Don't fail on missing optional dep

    ws_url = base_url.replace("http://", "ws://").replace("https://", "wss://")
    ws_url = f"{ws_url}/ws/live-detection"

    async def _ws_test():
        async with websockets.connect(ws_url) as ws:
            # Test ping/pong
            await ws.send(json.dumps({"type": "ping"}))
            pong = json.loads(await ws.recv())
            assert pong.get("type") == "pong", f"Expected pong, got {pong}"
            print("  Ping/Pong:     ✅")

            # Test frame submission
            frame_bytes = make_test_frame()
            frame_b64 = base64.b64encode(frame_bytes).decode("utf-8")
            await ws.send(json.dumps({
                "frame_b64": frame_b64,
                "camera_id": "CAM-WS-TEST",
                "location": "WebSocket Test",
            }))
            result = json.loads(await ws.recv())
            assert "anomaly_score" in result, f"Missing anomaly_score in response: {result}"
            print(f"  WS Detection:  anomaly_score={result['anomaly_score']}, status={result['status']}")
            if result.get("alert"):
                print(f"  🚨 WS ALERT:   Event {result['alert']['event_id']}")
            print("  ✅ PASSED")

    try:
        asyncio.run(_ws_test())
        return True
    except Exception as e:
        print(f"  ❌ FAILED — {e}")
        return False


def main():
    parser = argparse.ArgumentParser(description="Test Live Detection API")
    parser.add_argument("--base-url", default="http://127.0.0.1:8000", help="API base URL")
    args = parser.parse_args()
    base = args.base_url.rstrip("/")

    print("=" * 60)
    print("  LIVE DETECTION API — TEST SUITE")
    print(f"  Target: {base}")
    print("=" * 60)

    results = []
    results.append(("GET  /settings", test_get_settings(base)))
    results.append(("POST /settings", test_update_settings(base)))
    results.append(("POST /detect",   test_detect_frame(base)))
    results.append(("WS   /ws/live",  test_websocket(base)))

    print("\n" + "=" * 60)
    print("  SUMMARY")
    print("=" * 60)
    all_passed = True
    for name, passed in results:
        icon = "✅" if passed else "❌"
        print(f"  {icon}  {name}")
        if not passed:
            all_passed = False

    print("=" * 60)
    if all_passed:
        print("  All tests PASSED!")
    else:
        print("  Some tests FAILED. Check output above.")
        sys.exit(1)


if __name__ == "__main__":
    main()
