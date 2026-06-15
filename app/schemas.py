from fastapi import BaseModel, Field


class userCreate(BaseModel):
    username: str Field(min_length=3, max_length=30)
    email: str
    password: str Field(min_length=8)

class userOut(BaseModel):
    id: int
    username: str
    email: str