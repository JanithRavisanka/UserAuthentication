from pydantic import BaseModel

class AdminAddUser(BaseModel):
    username: str
    email: str
