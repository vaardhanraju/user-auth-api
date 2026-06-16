from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlmodel import select
from app.schemas import UserCreate, UserOut, TokenResponse, LoginRequest
from app.db.database import SessionDep
from app.db.models import User
from app.core.security import hash_password, verify_password, create_access_token, verify_token



router = APIRouter(prefix="/users",tags=["expenses"])


@router.post("/signup", response_model=UserOut)
def create_user(payload: UserCreate, session: SessionDep):
    """Register a new user."""
    existing_username = session.exec(select(User).where(User.username == payload.username)).first()
    if existing_username:
        raise HTTPException(status_code=409, detail="Username already exists")
    
    existing_email = session.exec(select(User).where(User.email == payload.email)).first()
    if existing_email:
        raise HTTPException(status_code=409, detail="Email already exists")
    
    hashed_pwd = hash_password(payload.password)

    db_user = User(
        username=payload.username,
        email=payload.email,
        hashed_password=hashed_pwd
    )
    
    session.add(db_user)
    session.commit()
    session.refresh(db_user)

    return db_user

@router.post("/login", response_model=TokenResponse)
def login(payload: LoginRequest, session: SessionDep):
    """Existing user login"""
    user = session.exec(select(User).where(User.username == LoginRequest.username)).first()

    if not user or not verify_password(payload.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid credentails")
    
    access_token = create_access_token(data={"sub": user.username})

    return {"access_token": access_token, "token_type": "bearer"}
