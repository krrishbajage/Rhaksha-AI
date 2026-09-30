"""Endpoints for Google OAuth sign-in and token exchange."""

from fastapi import APIRouter, HTTPException, Query, status
from fastapi.responses import RedirectResponse
from pydantic import BaseModel, Field

from app.services.google_auth import exchange_code, get_authorization_url
from app.services.token_store import TokenStore

router = APIRouter(prefix="/api/auth/google", tags=["Google OAuth"])


class ExchangeRequest(BaseModel):
    auth_code: str = Field(..., description="One-time server auth code from Android")


@router.get("/login", summary="Browser OAuth Login (Testing only)")
def login():
    """Redirects the browser to Google OAuth consent screen."""
    try:
        auth_url, _ = get_authorization_url()
        return RedirectResponse(url=auth_url)
    except ValueError as err:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(err),
        )


@router.get("/callback", summary="Browser OAuth Callback (Testing only)")
def callback(code: str = Query(...), state: str = Query(None)):
    """Handles redirect from Google and stores refresh token."""
    try:
        user_email, refresh_token = exchange_code(code)
        TokenStore.save_refresh_token(user_email, refresh_token)
        return {"connected": user_email}
    except Exception as err:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"OAuth callback failed: {err}",
        )


@router.post("/exchange", summary="Android Server Auth Code Exchange")
def exchange_android_code(payload: ExchangeRequest):
    """Exchanges server auth code received from Android Google Play Services."""
    try:
        # Android server auth code flow requires redirect_uri=""
        user_email, refresh_token = exchange_code(payload.auth_code, redirect_uri="")
        TokenStore.save_refresh_token(user_email, refresh_token)
        return {"connected": user_email}
    except Exception as err:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Android token exchange failed: {err}",
        )