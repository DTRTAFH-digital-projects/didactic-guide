from fastapi import APIRouter, Depends, HTTPException, status, Response
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from typing import Annotated

from sqlalchemy import select, insert
from models.user import User, UserBase, UserCreate
from database import get_db

router = APIRouter(prefix="/auth", tags=["Auth"])

security = HTTPBasic()

async def get_user(credentials: Annotated[HTTPBasicCredentials, Depends(security)]) -> User:
    query = select(
        User
    ).where(User.username == credentials.username).where(User.password == credentials.password)
    unauthed_exc = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid username or password",
        headers={"WWW-Authenticate": "Basic"},
    )
    
    user = await get_db().fetch_one(query)
    
    if not user:
        raise unauthed_exc
    
    return user

@router.get("/basic-auth/")
async def basic_auth(response: Response, user: User = Depends(get_user)):
    response.set_cookie("username", user.username)
    print(user.username)
    return {"result": "ok"}

@router.post("/check-auth/")
async def check_auth(user: UserCreate):
    query = select(
        User
    ).where(User.username == user.username).where(User.password == user.password)
    unauthed_exc = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid username or password",
        headers={"WWW-Authenticate": "Basic"},
    )
    
    user = await get_db().fetch_one(query)
    
    if not user:
        raise unauthed_exc
        
    return {"result": "ok"}

@router.post("/register/")
async def basic_register(user: UserCreate):
    query = select(
        User
    ).where(User.username == user.username)
    conflict_exc = HTTPException(
        status_code=status.HTTP_409_CONFLICT,
        detail="Username exists",
    )
    
    iuser = await get_db().fetch_one(query)
    
    if iuser:
        raise conflict_exc
    
    query = insert(
        User
    ).values(username=user.username, password=user.password)
    
    await get_db().execute(query)
    
    return user.username
