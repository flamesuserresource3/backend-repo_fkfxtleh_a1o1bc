import os
import random
from datetime import datetime, timedelta, timezone
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, EmailStr
from typing import Optional

from database import db, create_document, get_documents
from schemas import OtpSession, Identity

app = FastAPI(title="Identity & Compliance API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
def read_root():
    return {"message": "Hello from FastAPI Backend!"}


@app.get("/api/hello")
def hello():
    return {"message": "Hello from the backend API!"}


@app.get("/test")
def test_database():
    """Test endpoint to check if database is available and accessible"""
    response = {
        "backend": "✅ Running",
        "database": "❌ Not Available",
        "database_url": None,
        "database_name": None,
        "connection_status": "Not Connected",
        "collections": []
    }

    try:
        if db is not None:
            response["database"] = "✅ Available"
            response["database_url"] = "✅ Configured"
            response["database_name"] = db.name if hasattr(db, 'name') else "✅ Connected"
            response["connection_status"] = "Connected"
            try:
                collections = db.list_collection_names()
                response["collections"] = collections[:10]
                response["database"] = "✅ Connected & Working"
            except Exception as e:
                response["database"] = f"⚠️  Connected but Error: {str(e)[:50]}"
        else:
            response["database"] = "⚠️  Available but not initialized"

    except Exception as e:
        response["database"] = f"❌ Error: {str(e)[:50]}"

    import os
    response["database_url"] = "✅ Set" if os.getenv("DATABASE_URL") else "❌ Not Set"
    response["database_name"] = "✅ Set" if os.getenv("DATABASE_NAME") else "❌ Not Set"

    return response


# -------------------------
# Identity & Compliance API
# -------------------------

class StartOtpRequest(BaseModel):
    phone: str = Field(..., description="MSISDN in international format e.g., +2250700000000")

class VerifyOtpRequest(BaseModel):
    phone: str
    code: str

class RegisterIdentityRequest(BaseModel):
    phone: str
    name: str
    email: EmailStr
    country: Optional[str] = None
    faith_affirmation: bool = Field(..., description="Affirms platform values")


def normalize_phone(msisdn: str) -> str:
    msisdn = msisdn.strip().replace(" ", "")
    if not msisdn.startswith("+"):
        # naive: assume already in international; in production, use libphonenumber
        if msisdn.startswith("00"):
            msisdn = "+" + msisdn[2:]
    return msisdn


def get_latest_otp(phone: str):
    records = db["otpsession"].find({"phone": phone}).sort("created_at", -1).limit(1)
    return next(records, None)


@app.post("/identity/otp/start")
def start_otp(payload: StartOtpRequest):
    if db is None:
        raise HTTPException(status_code=500, detail="Database not available")
    phone = normalize_phone(payload.phone)
    code = f"{random.randint(100000, 999999)}"
    expires_at = datetime.now(timezone.utc) + timedelta(minutes=5)

    session = OtpSession(phone=phone, code=code, expires_at=expires_at, verified=False)
    _ = create_document("otpsession", session)

    # In production: send SMS via Mobile Money/SMS provider. Here we return code for demo.
    return {"status": "OTP_SENT", "phone": phone, "expires_in_sec": 300, "debug_code": code}


@app.post("/identity/otp/verify")
def verify_otp(payload: VerifyOtpRequest):
    if db is None:
        raise HTTPException(status_code=500, detail="Database not available")
    phone = normalize_phone(payload.phone)
    rec = get_latest_otp(phone)
    if not rec:
        raise HTTPException(status_code=404, detail="No OTP session found")

    now = datetime.now(timezone.utc)
    if now > rec.get("expires_at", now):
        raise HTTPException(status_code=400, detail="OTP expired")
    if payload.code != rec.get("code"):
        raise HTTPException(status_code=400, detail="Invalid code")

    db["otpsession"].update_one({"_id": rec["_id"]}, {"$set": {"verified": True, "updated_at": datetime.now(timezone.utc)}})
    return {"status": "VERIFIED", "phone": phone}


def kyc_rule_engine(country: Optional[str], name: str, email: str) -> dict:
    # Minimal demo rules; expand per jurisdiction later
    flags = []
    if country and country.upper() not in {"CI", "SN", "BJ", "TG", "CM", "GA", "CG", "CD"}:
        flags.append("COUNTRY_UNSUPPORTED")
    if any(bad in name.lower() for bad in ["test", "fake", "demo"]):
        flags.append("SUSPECT_NAME")
    return {"pass": len(flags) == 0, "flags": flags}


@app.post("/identity/register")
def register_identity(payload: RegisterIdentityRequest):
    if db is None:
        raise HTTPException(status_code=500, detail="Database not available")

    phone = normalize_phone(payload.phone)

    rec = get_latest_otp(phone)
    if not rec or not rec.get("verified"):
        raise HTTPException(status_code=400, detail="Phone not verified via OTP")

    if not payload.faith_affirmation:
        raise HTTPException(status_code=400, detail="Faith affirmation is required")

    kyc = kyc_rule_engine(payload.country, payload.name, payload.email)
    if not kyc["pass"]:
        raise HTTPException(status_code=400, detail={"message": "KYC checks failed", "flags": kyc["flags"]})

    existing = db["identity"].find_one({"phone": phone})
    if existing:
        # Update existing
        db["identity"].update_one(
            {"_id": existing["_id"]},
            {"$set": {
                "name": payload.name,
                "email": str(payload.email),
                "country": payload.country,
                "faith_affirmation": payload.faith_affirmation,
                "updated_at": datetime.now(timezone.utc)
            }}
        )
        return {"status": "UPDATED", "phone": phone}

    identity = Identity(
        phone=phone,
        name=payload.name,
        email=payload.email,
        country=payload.country,
        faith_affirmation=payload.faith_affirmation,
    )
    _ = create_document("identity", identity)
    return {"status": "CREATED", "phone": phone}


@app.get("/identity/me")
def get_identity(phone: str):
    if db is None:
        raise HTTPException(status_code=500, detail="Database not available")
    phone = normalize_phone(phone)
    doc = db["identity"].find_one({"phone": phone}, {"_id": 0})
    if not doc:
        raise HTTPException(status_code=404, detail="Identity not found")
    return doc


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
