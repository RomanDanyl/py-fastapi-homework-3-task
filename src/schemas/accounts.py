from pydantic import BaseModel, EmailStr, field_validator

from database import accounts_validators
from database.validators.accounts import validate_password_strength, validate_email


class UserBase(BaseModel):
    email: EmailStr

    @field_validator("email")
    @classmethod
    def email_validate(cls, value: EmailStr) -> EmailStr:
        return validate_email(value)


class UserRegistrationRequestSchema(UserBase):
    password: str

    @field_validator("password")
    @classmethod
    def password_validate(cls, value: str) -> str:
        return validate_password_strength(value)


class UserRegistrationResponseSchema(UserBase):
    id: int

    class Config:
        from_attributes = True


class UserActivationRequestSchema(BaseModel):
    email: EmailStr
    token: str


class MessageResponseSchema(BaseModel):
    message: str = "User account activated successfully."


class PasswordResetRequestSchema(BaseModel):
    email: EmailStr


class PasswordResetCompleteRequestSchema(UserRegistrationRequestSchema):
    token: str


class UserLoginResponseSchema(BaseModel):
    ...


class UserLoginRequestSchema(BaseModel):
    ...


class TokenRefreshRequestSchema(BaseModel):
    ...


class TokenRefreshResponseSchema(BaseModel):
    ...
