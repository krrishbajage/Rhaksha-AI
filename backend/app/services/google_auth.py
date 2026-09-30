"""Google OAuth2 service for Gmail API integration."""

import os
from typing import Optional
import urllib.parse
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build, Resource
import httpx

from app.services.token_store import TokenStore

SCOPES = ["https://www.googleapis.com/auth/gmail.readonly"]
TOKEN_URL = "https://oauth2.googleapis.com/token"
AUTH_BASE_URL = "https://accounts.google.com/o/oauth2/v2/auth"
GMAIL_PROFILE_URL = "https://gmail.googleapis.com/gmail/v1/users/me/profile"


def _get_env_credentials() -> tuple[str, str]:
    client_id = os.getenv("GOOGLE_OAUTH_CLIENT_ID", "").strip()
    client_secret = os.getenv("GOOGLE_OAUTH_CLIENT_SECRET", "").strip()
    if not client_id or not client_secret:
        raise ValueError("GOOGLE_OAUTH_CLIENT_ID and GOOGLE_OAUTH_CLIENT_SECRET must be set in .env.")
    return client_id, client_secret


def get_authorization_url() -> tuple[str, str]:
    """Generates the standard Google OAuth authorization URL without PKCE."""
    client_id, _ = _get_env_credentials()
    redirect_uri = os.getenv(
        "GOOGLE_OAUTH_REDIRECT_URI",
        "http://localhost:8000/api/auth/google/callback",
    ).strip()

    state = os.urandom(16).hex()
    params = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "scope": " ".join(SCOPES),
        "access_type": "offline",
        "prompt": "consent",
        "state": state,
    }
    url = f"{AUTH_BASE_URL}?{urllib.parse.urlencode(params)}"
    return url, state


def exchange_code(code: str, redirect_uri: Optional[str] = None) -> tuple[str, str]:
    """
    Exchanges authorization code for access and refresh tokens.
    - Browser dev flow: uses GOOGLE_OAUTH_REDIRECT_URI.
    - Android flow: redirect_uri must be empty string ("").
    """
    client_id, client_secret = _get_env_credentials()

    if redirect_uri is None:
        redirect_uri = os.getenv(
            "GOOGLE_OAUTH_REDIRECT_URI",
            "http://localhost:8000/api/auth/google/callback",
        ).strip()

    payload = {
        "code": code,
        "client_id": client_id,
        "client_secret": client_secret,
        "redirect_uri": redirect_uri,
        "grant_type": "authorization_code",
    }

    with httpx.Client(timeout=15.0) as client:
        resp = client.post(TOKEN_URL, data=payload)
        if resp.status_code != 200:
            raise ValueError(f"Google token exchange rejected: {resp.text}")

        token_data = resp.json()
        access_token = token_data.get("access_token")
        refresh_token = token_data.get("refresh_token")

        if not refresh_token:
            raise ValueError("No refresh_token returned by Google. Ensure prompt='consent' was granted.")

        # Fetch the authenticated user's email address
        profile_resp = client.get(
            GMAIL_PROFILE_URL,
            headers={"Authorization": f"Bearer {access_token}"},
        )
        if profile_resp.status_code != 200:
            raise ValueError(f"Failed to fetch Gmail profile: {profile_resp.text}")

        user_email = profile_resp.json().get("emailAddress", "").strip().lower()
        if not user_email:
            raise ValueError("Email address was empty in Gmail profile response.")

    return user_email, refresh_token


def build_gmail_client(user_email: str) -> Resource:
    """Builds an authorized Gmail API client from the stored refresh token."""
    refresh_token = TokenStore.get_refresh_token(user_email)
    if not refresh_token:
        raise ValueError(f"No Gmail refresh token found for {user_email}. User must authorize first.")

    client_id, client_secret = _get_env_credentials()

    credentials = Credentials(
        token=None,
        refresh_token=refresh_token,
        token_uri=TOKEN_URL,
        client_id=client_id,
        client_secret=client_secret,
        scopes=SCOPES,
    )

    return build("gmail", "v1", credentials=credentials, cache_discovery=False)