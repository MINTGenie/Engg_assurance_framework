"""REST API (fixture with planted defects)."""
import jwt
import requests
from fastapi import FastAPI, Header
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(title="Fleet document search")

# planted: wildcard CORS together with credentials
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"])


def current_user(authorization: str = Header(default="")):
    token = authorization.removeprefix("Bearer ")
    # planted: signature not verified
    return jwt.decode(token, options={"verify_signature": False})


@app.get("/documents/{doc_id}")
def get_document(doc_id: int, authorization: str = Header(default="")):
    user = current_user(authorization)
    # planted: TLS verification disabled for an upstream call
    upstream = requests.get(f"https://dms.internal.example/doc/{doc_id}", verify=False, timeout=5)
    return {"user": user.get("sub"), "document": upstream.json()}
