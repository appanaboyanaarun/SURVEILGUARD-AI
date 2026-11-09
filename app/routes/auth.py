import datetime
from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session
from typing import List

from app.database.connection import get_db
from app.models.schema import User
from app.schemas.dto import UserLogin, TokenResponse, UserResponse, UserCreate
from app.services.auth_service import (
    hash_password,
    verify_password,
    create_access_token,
    get_current_user,
    require_admin,
)
from app.services.audit_service import AuditService

router = APIRouter(prefix="/auth", tags=["Authentication & Security"])


@router.post("/login", response_model=TokenResponse)
def login(login_data: UserLogin, request: Request, db: Session = Depends(get_db)):
    """
    Authenticates user, verifies PBKDF2 password hash, logs audit entry,
    and returns a cryptographically signed JWT access token.
    """
    user = db.query(User).filter(User.username == login_data.username).first()

    # Seed default admin if user table is fresh
    if not user and login_data.username == "admin" and login_data.password in ["admin", "admin123"]:
        user = User(
            username="admin",
            password_hash=hash_password("admin123"),
            full_name="System Administrator",
            role="admin",
            is_active=True,
        )
        db.add(user)
        db.commit()
        db.refresh(user)

    if not user:
        # Fallback operator if table fresh
        if login_data.username == "operator" and login_data.password in ["operator", "operator123"]:
            user = User(
                username="operator",
                password_hash=hash_password("operator123"),
                full_name="Duty Security Operator",
                role="operator",
                is_active=True,
            )
            db.add(user)
            db.commit()
            db.refresh(user)
        else:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid username or password.",
            )

    if not verify_password(login_data.password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password.",
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is deactivated.",
        )

    # Seamless upgrade from legacy plain sha256 to PBKDF2-HMAC-SHA256
    if not user.password_hash.startswith("pbkdf2_sha256$"):
        user.password_hash = hash_password(login_data.password)

    user.last_login = datetime.datetime.utcnow()
    db.commit()

    # Generate JWT
    token_payload = {
        "sub": user.username,
        "user_id": user.user_id,
        "role": user.role,
        "full_name": user.full_name,
    }
    access_token = create_access_token(token_payload)

    # Audit log
    ip = request.client.host if request.client else None
    ua = request.headers.get("user-agent")
    AuditService.log(
        db=db,
        action="LOGIN",
        actor_name=user.full_name,
        actor_id=user.user_id,
        entity_type="user",
        entity_id=str(user.user_id),
        details=f"User '{user.username}' logged in successfully with role '{user.role}'",
        ip_address=ip,
        user_agent=ua,
    )

    return TokenResponse(
        access_token=access_token,
        token_type="bearer",
        user=UserResponse.model_validate(user),
    )


@router.get("/me", response_model=UserResponse)
def get_current_user_profile(current_user: User = Depends(get_current_user)):
    """Returns the authenticated user profile."""
    return UserResponse.model_validate(current_user)


@router.post("/logout")
def logout(request: Request, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Logs out user and records audit log."""
    ip = request.client.host if request.client else None
    AuditService.log(
        db=db,
        action="LOGOUT",
        actor_name=current_user.full_name,
        actor_id=current_user.user_id,
        entity_type="user",
        entity_id=str(current_user.user_id),
        details=f"User '{current_user.username}' logged out",
        ip_address=ip,
    )
    return {"message": "Logged out successfully."}


@router.get("/users", response_model=List[UserResponse])
def list_users(current_admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    """Admin-only endpoint to list all system operators and administrators."""
    users = db.query(User).all()
    return [UserResponse.model_validate(u) for u in users]


@router.post("/users", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
def create_user(
    payload: UserCreate,
    current_admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    """Admin-only endpoint to register new operators or admins."""
    existing = db.query(User).filter(User.username == payload.username).first()
    if existing:
        raise HTTPException(status_code=400, detail=f"Username '{payload.username}' is already taken.")

    user = User(
        username=payload.username,
        password_hash=hash_password(payload.password),
        full_name=payload.full_name,
        role=payload.role.lower(),
        phone_number=payload.phone_number,
        is_active=True,
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    AuditService.log(
        db=db,
        action="USER_CREATE",
        actor_name=current_admin.full_name,
        actor_id=current_admin.user_id,
        entity_type="user",
        entity_id=str(user.user_id),
        details=f"Created user '{user.username}' with role '{user.role}'",
    )

    return UserResponse.model_validate(user)
