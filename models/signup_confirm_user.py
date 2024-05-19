from pydantic import BaseModel


class SignupConfirmUser(BaseModel):
    username: str
    confirmation_code: str
