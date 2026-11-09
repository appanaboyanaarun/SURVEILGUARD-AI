from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import List
from app.database.connection import get_db
from app.schemas.dto import CameraCreate, CameraUpdate, CameraResponse
from app.services.camera_service import CameraService
from app.services.stream_manager import stream_manager
import cv2
from fastapi.responses import StreamingResponse

router = APIRouter(prefix="/cameras", tags=["Cameras"])


@router.get("", response_model=List[CameraResponse])
def list_cameras(active_only: bool = False, db: Session = Depends(get_db)):
    return CameraService.get_all(db, active_only=active_only)


@router.get("/{camera_id}", response_model=CameraResponse)
def get_camera(camera_id: str, db: Session = Depends(get_db)):
    cam = CameraService.get_by_id(db, camera_id)
    if not cam:
        raise HTTPException(status_code=404, detail=f"Camera '{camera_id}' not found.")
    return cam


@router.post("", response_model=CameraResponse, status_code=status.HTTP_201_CREATED)
def create_camera(camera_data: CameraCreate, db: Session = Depends(get_db)):
    try:
        created = CameraService.create(db, camera_data)
        if created.is_active and created.stream_url:
            stream_manager.start_camera(created)
        return created
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.put("/{camera_id}", response_model=CameraResponse)
def update_camera(camera_id: str, camera_data: CameraUpdate, db: Session = Depends(get_db)):
    updated = CameraService.update(db, camera_id, camera_data)
    if not updated:
        raise HTTPException(status_code=404, detail=f"Camera '{camera_id}' not found.")
    
    if updated.is_active and updated.stream_url:
        stream_manager.start_camera(updated)
    else:
        stream_manager.stop_camera(camera_id)
        
    return updated


@router.delete("/{camera_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_camera(camera_id: str, db: Session = Depends(get_db)):
    success = CameraService.delete(db, camera_id)
    if not success:
        raise HTTPException(status_code=404, detail=f"Camera '{camera_id}' not found.")
    stream_manager.stop_camera(camera_id)
    return None

def generate_frames(camera_id: str):
    while True:
        frame = stream_manager.get_frame(camera_id)
        if frame is None:
            # Send a blank frame or yield placeholder
            import time
            time.sleep(0.1)
            continue
        ret, buffer = cv2.imencode('.jpg', frame)
        if not ret:
            continue
        frame_bytes = buffer.tobytes()
        yield (b'--frame\r\n'
               b'Content-Type: image/jpeg\r\n\r\n' + frame_bytes + b'\r\n')

@router.get("/{camera_id}/stream")
def video_feed(camera_id: str):
    return StreamingResponse(generate_frames(camera_id), media_type='multipart/x-mixed-replace; boundary=frame')
