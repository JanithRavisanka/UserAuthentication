from pydantic import BaseModel

class SignupUser(BaseModel):
    username: str
    password: str
    email: str
    