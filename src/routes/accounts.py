from datetime import datetime, timezone, timedelta

from fastapi import APIRouter, Depends, status, HTTPException
from sqlalchemy import select, delete
from sqlalchemy.ext.asyncio import AsyncSession

from config import get_jwt_auth_manager, get_settings, BaseAppSettings
from database import (
    get_db,
    UserModel,
    UserGroupModel,
    UserGroupEnum,
    ActivationTokenModel,
    PasswordResetTokenModel,
    RefreshTokenModel
)
from exceptions import BaseSecurityError, InvalidTokenError, TokenExpiredError
from schemas import UserRegistrationResponseSchema, UserRegistrationRequestSchema, UserActivationRequestSchema, \
    MessageResponseSchema, PasswordResetCompleteRequestSchema, PasswordResetRequestSchema, UserLoginRequestSchema, \
    UserLoginResponseSchema, TokenRefreshResponseSchema, TokenRefreshRequestSchema
from security.interfaces import JWTAuthManagerInterface
from security.utils import generate_secure_token

router = APIRouter()


@router.post(
    '/register/',
    response_model=UserRegistrationResponseSchema,
    status_code=status.HTTP_201_CREATED
)
async def register_user(
        user_data: UserRegistrationRequestSchema,
        db: AsyncSession = Depends(get_db)
):
    result_group = await db.execute(
        select(UserGroupModel).where(UserGroupModel.name == UserGroupEnum.USER)
    )
    default_group = result_group.scalar_one_or_none()
    if not default_group:
        raise HTTPException(
            status_code=404,
            detail="Default user group not found."
        )

    result_user = await db.execute(select(UserModel).where(UserModel.email == user_data.email))
    existing_user = result_user.scalar_one_or_none()
    if existing_user:
        raise HTTPException(
            status_code=409,
            detail=f"A user with this email {existing_user.email} already exists.",
        )
    try:
        user = UserModel.create(
            email=user_data.email,
            raw_password=user_data.password,
            group_id=default_group.id
        )
        db.add(user)
        await db.flush()
        await db.refresh(user)
        activation_token = ActivationTokenModel(user=user)
        db.add(activation_token)
        await db.commit()
        return user
    except Exception:
        raise HTTPException(
            status_code=500,
            detail="An error occurred during user creation."
        )


@router.post("/activate/", response_model=MessageResponseSchema)
async def activate_user(
        user_data: UserActivationRequestSchema,
        db: AsyncSession = Depends(get_db)
):
    result = await db.execute(select(UserModel).where(UserModel.email == user_data.email))
    user = result.scalar_one_or_none()

    if not user:
        raise HTTPException(status_code=400, detail="Invalid or expired activation token.")

    if user.is_active:
        raise HTTPException(status_code=400, detail="User account is already active.")

    result = await db.execute(
        select(ActivationTokenModel).where(
            ActivationTokenModel.user_id == user.id,
            ActivationTokenModel.token == user_data.token
        )
    )
    token = result.scalar_one_or_none()

    if not token or token.expires_at < datetime.now():
        raise HTTPException(status_code=400, detail="Invalid or expired activation token.")

    user.is_active = True
    await db.delete(token)
    await db.commit()

    return {"message": "User account activated successfully."}


@router.post(
    "/password-reset/request/",
    response_model=MessageResponseSchema
)
async def password_reset_request(
        user_data: PasswordResetRequestSchema,
        db: AsyncSession = Depends(get_db)
):
    result = await db.execute(select(UserModel).where(UserModel.email == user_data.email))
    user = result.scalar_one_or_none()
    if user and user.is_active:
        await db.execute(
            delete(PasswordResetTokenModel).where(PasswordResetTokenModel.user_id == user.id)
        )

        token_str = generate_secure_token()
        expires_at = datetime.now(timezone.utc) + timedelta(minutes=30)

        new_token = PasswordResetTokenModel(
            user_id=user.id,
            token=token_str,
            expires_at=expires_at
        )
        db.add(new_token)
        await db.commit()
    return {
        "message": "If you are registered, you will receive an email with instructions."
    }


@router.post(
    "/reset-password/complete/",
    response_model=MessageResponseSchema,
    status_code=200
)
async def password_reset_complete(
        user_data: PasswordResetCompleteRequestSchema,
        db: AsyncSession = Depends(get_db)
):
    stmt = select(UserModel).where(UserModel.email == user_data.email)
    result = await db.execute(stmt)
    user = result.scalar_one_or_none()

    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid email or token."
        )

    stmt = select(PasswordResetTokenModel).where(
        PasswordResetTokenModel.user_id == user.id
    )
    result = await db.execute(stmt)
    reset_token = result.scalar_one_or_none()
    if (
            not reset_token or
            reset_token.token != user_data.token or
            reset_token.expires_at.replace(tzinfo=timezone.utc) <= datetime.now(timezone.utc)
    ):
        if reset_token:
            await db.delete(reset_token)
            try:
                await db.commit()
            except Exception:
                await db.rollback()
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="An error occurred while resetting the password."
                )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid email or token."
        )

    user.password = user_data.password
    db.add(user)

    await db.delete(reset_token)

    try:
        await db.commit()
    except Exception:
        try:
            await db.rollback()
        except Exception:
            pass
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while resetting the password."
        )
    return {"message": "Password reset successfully."}


@router.post(
    "/login/",
    response_model=UserLoginResponseSchema,
    status_code=201
)
async def login(
        user_data: UserLoginRequestSchema,
        db: AsyncSession = Depends(get_db),
        jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
        settings: BaseAppSettings = Depends(get_settings)
):
    stmt = select(UserModel).where(
        UserModel.email == user_data.email,
    )
    result = await db.execute(stmt)
    user = result.scalar_one_or_none()

    if not user or not user.verify_password(user_data.password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password."
        )
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is not activated."
        )

    payload_for_token = {
        "user_id": user.id,
        "user_email": user.email,
        "user_group": user.group_id
    }

    try:
        refresh_token_str = jwt_manager.create_refresh_token(payload_for_token)
        refresh_token = RefreshTokenModel.create(
            user_id=user.id,
            token=refresh_token_str,
            days_valid=settings.LOGIN_TIME_DAYS
        )
        db.add(refresh_token)
        await db.commit()

        access_token = jwt_manager.create_access_token(payload_for_token)

        return UserLoginResponseSchema(
            access_token=access_token,
            refresh_token=refresh_token_str,
            token_type="bearer",
        )
    except Exception:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while processing the request."
        )


@router.post(
    "/refresh/",
    response_model=TokenRefreshResponseSchema,
    status_code=200
)
async def refresh_access_token(
        refresh_token: TokenRefreshRequestSchema,
        db: AsyncSession = Depends(get_db),
        jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
):
    try:
        user_data = jwt_manager.decode_refresh_token(refresh_token.refresh_token)
    except TokenExpiredError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Token has expired."
        )

    stmt = select(RefreshTokenModel).where(RefreshTokenModel.token == refresh_token.refresh_token)
    result = await db.execute(stmt)
    token = result.scalar_one_or_none()
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token not found."
        )

    user_result = await db.execute(
        select(UserModel).where(UserModel.id == user_data["user_id"])
    )
    user = user_result.scalar_one_or_none()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found."
        )

    access_token = jwt_manager.create_access_token(user_data)

    return {"access_token": access_token}
