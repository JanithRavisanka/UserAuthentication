from pydantic import BaseModel


class SigninUser(BaseModel):
    username: str
    password: str
