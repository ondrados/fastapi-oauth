import json
import os
import secrets

import dotenv
import httpx
import jwt
import oauthlib.oauth2.rfc6749.errors

from fastapi import FastAPI, Request
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates
from jwt.algorithms import RSAAlgorithm
from starlette.middleware.sessions import SessionMiddleware

from oauthlib.oauth2 import WebApplicationClient

dotenv.load_dotenv()

app = FastAPI()
app.add_middleware(
    SessionMiddleware, secret_key=os.environ.get("SECRET_KEY"), max_age=3600
)

templates = Jinja2Templates(directory="templates")


def pretty_json(value):
    return json.dumps(value, sort_keys=True, indent=4, separators=(",", ": "))


templates.env.filters["pretty_json"] = pretty_json


class OAuthClient:
    AUTHORIZATION_URI = "https://accounts.google.com/o/oauth2/v2/auth"
    TOKEN_URI = "https://oauth2.googleapis.com/token"
    REVOCATION_URI = "https://oauth2.googleapis.com/revoke"
    CERTS_URI = "https://www.googleapis.com/oauth2/v3/certs"
    ISSUER = "https://accounts.google.com"
    USER_INFO_URI = "https://openidconnect.googleapis.com/v1/userinfo"

    def __init__(
            self, client_id: str, client_secret: str, redirect_uri: str, scope: list[str]
    ):
        self.client_id = client_id
        self.client_secret = client_secret
        self.redirect_uri = redirect_uri
        self.scope = scope
        self._client = WebApplicationClient(client_id=client_id)

    async def get_authorization_uri(self) -> (str, str):
        state = secrets.token_urlsafe(16)
        authorization_uri: str = self._client.prepare_request_uri(  # noqa
            uri=self.AUTHORIZATION_URI,
            redirect_uri=self.redirect_uri,
            scope=["openid", "profile", "email"],
            state=state,
        )
        return authorization_uri, state

    async def validate_authorization_request(
            self, request: Request, state: str
    ) -> dict:
        try:
            query_dict = self._client.parse_request_uri_response(  # noqa
                uri=str(request.url), state=state
            )
        except oauthlib.oauth2.rfc6749.errors.OAuth2Error as e:
            return {"error": e.error}
        return query_dict  # noqa

    async def get_token(self, code: str) -> dict:
        params = self._client.prepare_request_body(  # noqa
            client_secret=self.client_secret,
            code=code,
            redirect_uri=self.redirect_uri,
            include_client_id=True,
        )

        async with httpx.AsyncClient() as c:
            response = await c.post(self.TOKEN_URI, params=params)
            if response.status_code == 200:
                return response.json()
            return response.json()

    async def revoke_token(self, token: str, token_type_hint: str) -> dict:
        url, headers, params = self._client.prepare_token_revocation_request(
            revocation_url=self.REVOCATION_URI,
            token=token,
            token_type_hint=token_type_hint,
        )

        async with httpx.AsyncClient() as c:
            response = await c.post(url=url, params=params, headers=headers)
            return response.json()

    async def get_google_jwks(self):
        async with httpx.AsyncClient() as c:
            response = await c.get(self.CERTS_URI)
            jwks = response.json()
        return jwks

    async def validate_id_token(self, id_token: str) -> dict:
        jwks = await self.get_google_jwks()
        # Extract the public keys from JWKS
        public_keys = {}
        for jwk in jwks["keys"]:
            kid = jwk["kid"]
            public_key = RSAAlgorithm.from_jwk(jwk)
            public_keys[kid] = {"key": public_key, "alg": jwk["alg"]}

        # Decode the ID token
        header = jwt.get_unverified_header(id_token)
        kid = header["kid"]
        if kid in public_keys:
            # Verify the token using the corresponding public key
            payload = jwt.decode(
                id_token,
                key=public_keys[kid]["key"],
                algorithms=[public_keys[kid]["alg"]],
                audience=self.client_id,
                issuer=self.ISSUER,
            )
            return payload
        else:
            raise Exception("Key ID not found in JWKS")

    async def get_user_info(self, access_token: str) -> dict:
        async with httpx.AsyncClient() as c:
            headers = {"Authorization": f"Bearer {access_token}"}
            response = await c.get(self.USER_INFO_URI, headers=headers)
            return response.json()


client = OAuthClient(
    client_id=os.environ.get("CLIENT_ID"),
    client_secret=os.environ.get("CLIENT_SECRET"),
    redirect_uri="http://localhost:8000/callback",
    scope=["openid", "profile", "email"],
)


@app.get("/")
async def read_root(request: Request):
    email = None
    openid_payload = None
    user_info = None
    if request.session.get("email"):
        email = request.session["email"]
        id_token = request.session["id_token"]
        try:
            openid_payload = await client.validate_id_token(id_token)
        except jwt.ExpiredSignatureError:
            request.session.clear()
            return RedirectResponse("/")

        user_info = await client.get_user_info(request.session["access_token"])
    return templates.TemplateResponse(
        "index.html",
        {
            "request": request,
            "email": email,
            "openid_payload": openid_payload,
            "user_info": user_info,
        },
    )


@app.get("/authorize")
async def authorize(request: Request):
    authorization_uri, state = await client.get_authorization_uri()
    request.session["state"] = state
    return RedirectResponse(authorization_uri)


@app.get("/callback")
async def callback(request: Request):
    state: str | None = request.session.get("state", None)
    if state is None:
        return {"error": "Invalid session"}
    query_dict = await client.validate_authorization_request(request, state)
    if "error" in query_dict:
        return query_dict

    token = await client.get_token(query_dict["code"])

    try:
        id_token = token["id_token"]
        openid_payload = await client.validate_id_token(id_token)
        email = openid_payload["email"]
        request.session["email"] = email
        request.session["id_token"] = token["id_token"]
        request.session["access_token"] = token["access_token"]

    except jwt.PyJWTError:
        return {"error": "Invalid ID token"}

    return RedirectResponse("/")


@app.get("/logout")
async def logout(request: Request):
    if "access_token" not in request.session:
        request.session.clear()
        return RedirectResponse("/")

    token = request.session["access_token"]
    await client.revoke_token(token, "access_token")

    request.session.clear()
    return RedirectResponse("/")
