from sqlalchemy.orm import Session
from typing import List, Optional
from app.models.schema import Camera
from app.schemas.dto import CameraCreate, CameraUpdate


class CameraService:
    @staticmethod
    def get_all(db: Session, active_only: bool = False) -> List[Camera]:
        q = db.query(Camera)
        if active_only:
            q = q.filter(Camera.is_active == True)
        return q.order_by(Camera.camera_id).all()

    @staticmethod
    def get_by_id(db: Session, camera_id: str) -> Optional[Camera]:
        return db.query(Camera).filter(Camera.camera_id == camera_id).first()

    @staticmethod
    def create(db: Session, camera_data: CameraCreate) -> Camera:
        existing = db.query(Camera).filter(Camera.camera_id == camera_data.camera_id).first()
        if existing:
            raise ValueError(f"Camera ID '{camera_data.camera_id}' already exists.")
        
        camera = Camera(
            camera_id=camera_data.camera_id,
            name=camera_data.name,
            location=camera_data.location,
            description=camera_data.description,
            camera_type=camera_data.camera_type or "CCTV",
            stream_url=camera_data.stream_url,
            status=camera_data.status or "OFFLINE",
            restricted_zone_coords=camera_data.restricted_zone_coords,
            is_active=camera_data.is_active if camera_data.is_active is not None else True,
        )
        db.add(camera)
        db.commit()
        db.refresh(camera)
        return camera

    @staticmethod
    def update(db: Session, camera_id: str, camera_data: CameraUpdate) -> Optional[Camera]:
        camera = CameraService.get_by_id(db, camera_id)
        if not camera:
            return None

        update_dict = camera_data.model_dump(exclude_unset=True)
        for key, value in update_dict.items():
            setattr(camera, key, value)

        db.commit()
        db.refresh(camera)
        return camera

    @staticmethod
    def delete(db: Session, camera_id: str) -> bool:
        camera = CameraService.get_by_id(db, camera_id)
        if not camera:
            return False
        db.delete(camera)
        db.commit()
        return True
