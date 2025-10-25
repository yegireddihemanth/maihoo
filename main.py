from fastapi import FastAPI, HTTPException, Request, Response, Depends
from pydantic import BaseModel
from motor.motor_asyncio import AsyncIOMotorClient
from fastapi.responses import JSONResponse
from datetime import datetime, timezone
from typing import List, Optional
import time, hmac, hashlib, base64, json
from fastapi.middleware.cors import CORSMiddleware
from bson import ObjectId
from fastapi.encoders import jsonable_encoder

# -------------------------------
# Config
# -------------------------------
# 🔒 Using your provided MongoDB URI directly
mongoUri = "mongodb+srv://maihoo:tzAnnPiezHR5RYtZ@maihoo.ztaytqd.mongodb.net/?appName=maihoo"
mongoDbName = "bgv_core"
sessionSecret = b"super-secret-key"

cookieName = "bgvSession"
cookieMaxAge = 60 * 60 * 2
cookieSecure = True
cookieSameSite = "none"

# -------------------------------
# Init
# -------------------------------
app = FastAPI(title="BGV Login API with Cookies", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "https://localhost:3000",
        "http://127.0.0.1:3000",
        "https://bgv-frontend.onrender.com",
        "https://*.ngrok-free.app",
        "*",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# -------------------------------
# MongoDB Collections
# -------------------------------
client = AsyncIOMotorClient(mongoUri)
db = client[mongoDbName]
usersCol = db["users"]
orgsCol = db["organizations"]
verificationsCol = db["verifications"]
activityLogsCol = db["activity_logs"]

# -------------------------------
# Utility
# -------------------------------
def toStrId(doc):
    if not doc:
        return None
    d = dict(doc)
    if "_id" in d:
        d["_id"] = str(d["_id"])
    return d


# -------------------------------
# Activity Logging Helper
# -------------------------------
async def logActivity(user: dict, action: str, details: str, status: str = "Success"):
    logDoc = {
        "userId": str(user.get("_id")) if user.get("_id") else None,
        "userName": user.get("userName"),
        "email": user.get("email"),
        "role": user.get("role"),
        "organizationId": user.get("organizationId"),
        "action": action,
        "details": details,
        "status": status,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    await activityLogsCol.insert_one(logDoc)


# -------------------------------
# Models
# -------------------------------
class loginRequest(BaseModel):
    email: str
    password: str


class ServiceItem(BaseModel):
    serviceName: str
    price: float


class CredentialsModel(BaseModel):
    totalAllowed: int
    used: Optional[int] = 0


class OrganizationRegistration(BaseModel):
    organizationName: str
    spocName: str
    mainDomain: str
    subDomain: Optional[str] = None
    email: str
    gstNumber: str
    services: List[ServiceItem]
    logoUrl: Optional[str] = None
    credentials: CredentialsModel


# -------------------------------
# Token helpers (HMAC)
# -------------------------------
def encodeToken(payload: dict) -> str:
    body = json.dumps(payload, separators=(",", ":")).encode()
    sig = hmac.new(sessionSecret, body, hashlib.sha256).digest()
    return f"{base64.urlsafe_b64encode(body).decode().rstrip('=')}.{base64.urlsafe_b64encode(sig).decode().rstrip('=')}"


def decodeToken(token: str) -> dict:
    try:
        bodyB64, sigB64 = token.split(".", 1)
        body = base64.urlsafe_b64decode(bodyB64 + "==")
        sig = base64.urlsafe_b64decode(sigB64 + "==")
        expected = hmac.new(sessionSecret, body, hashlib.sha256).digest()
        if not hmac.compare_digest(sig, expected):
            raise ValueError("bad signature")
        data = json.loads(body.decode())
        if data.get("exp", 0) < int(time.time()):
            raise ValueError("expired")
        return data
    except Exception:
        raise HTTPException(status_code=401, detail="invalid or expired session")


# -------------------------------
# Auth dependency
# -------------------------------
async def requireAuth(request: Request):
    token = request.cookies.get(cookieName)
    if not token:
        raise HTTPException(status_code=401, detail="no session cookie")

    data = decodeToken(token)
    user = await usersCol.find_one({"email": data["email"], "isActive": True})
    if not user:
        raise HTTPException(status_code=401, detail="user not found")
    return user


# -------------------------------
# Auth Routes
# -------------------------------
@app.post("/auth/login")
async def login(body: loginRequest, response: Response):
    user = await usersCol.find_one(
        {"email": body.email, "password": body.password, "isActive": True}
    )
    if not user:
        raise HTTPException(status_code=401, detail="invalid credentials")

    orgId = user.get("organizationId")
    now = int(time.time())
    payload = {
        "email": user["email"],
        "role": user["role"],
        "organizationId": orgId,
        "iat": now,
        "exp": now + cookieMaxAge,
    }
    token = encodeToken(payload)

    response.set_cookie(
        key=cookieName,
        value=token,
        httponly=True,
        secure=cookieSecure,
        samesite=cookieSameSite,
        max_age=cookieMaxAge,
        path="/",
    )

    await logActivity(user, "User Login", f"{user.get('email')} logged in.", "Success")

    return {
        "userName": user.get("userName"),
        "email": user.get("email"),
        "role": user.get("role"),
        "organizationId": orgId,
        "session": "created",
    }


@app.post("/auth/logout")
async def logout(user: dict = Depends(requireAuth), response: Response = None):
    await logActivity(user, "User Logout", f"{user.get('email')} logged out.", "Info")
    if response:
        response.delete_cookie(key=cookieName, path="/")
    return {"ok": True}


# -------------------------------
# Get All Organizations
# -------------------------------
@app.get("/secure/getAllOrganizations")
async def getAllOrganizations(user: dict = Depends(requireAuth)):
    if user.get("role") != "SUPER_ADMIN":
        raise HTTPException(
            status_code=403, detail="Only SUPER_ADMIN can access all organizations"
        )
    cursor = orgsCol.find({})
    orgList = await cursor.to_list(None)
    for org in orgList:
        org["_id"] = str(org["_id"])
    await logActivity(user, "View Organizations", "Fetched all organizations list.")
    return JSONResponse(
        status_code=200,
        content={"totalOrganizations": len(orgList), "organizations": orgList},
    )


# -------------------------------
# Register Organization
# -------------------------------
@app.post("/secure/registerOrganization")
async def registerOrganization(body: OrganizationRegistration, user: dict = Depends(requireAuth)):
    if user.get("role") != "SUPER_ADMIN":
        raise HTTPException(status_code=403, detail="Only SUPER_ADMIN can register organizations")

    cleanOrgName = body.organizationName.split()[0].lower()
    autoSubDomain = body.subDomain or f"{cleanOrgName}.bgvapp.in"

    existingOrg = await orgsCol.find_one({
        "$or": [{"email": body.email}, {"mainDomain": body.mainDomain}, {"subDomain": autoSubDomain}]
    })
    if existingOrg:
        raise HTTPException(status_code=409, detail="Organization already exists")

    now = datetime.now(timezone.utc).isoformat()
    orgDoc = {
        "organizationName": body.organizationName,
        "spocName": body.spocName,
        "mainDomain": body.mainDomain,
        "subDomain": autoSubDomain,
        "email": body.email,
        "gstNumber": body.gstNumber,
        "services": [s.dict() for s in body.services],
        "logoUrl": body.logoUrl,
        "credentials": body.credentials.dict(),
        "createdBy": user.get("email"),
        "createdAt": now,
        "updatedAt": now,
        "isActive": True,
    }

    insertOrg = await orgsCol.insert_one(orgDoc)
    orgId = str(insertOrg.inserted_id)

    spocUser = {
        "userName": body.spocName,
        "email": body.email,
        "password": "Welcome@123",
        "role": "ORG_HR",
        "organizationId": orgId,
        "isActive": True,
        "createdAt": now,
        "createdBy": user.get("email"),
    }
    await usersCol.insert_one(spocUser)

    await logActivity(user, "Created Organization", f"Organization '{body.organizationName}' created.")

    return JSONResponse(
        status_code=201,
        content=jsonable_encoder({
            "message": "Organization registered successfully",
            "orgId": orgId,
            "organizationName": body.organizationName,
            "spocEmail": body.email,
            "defaultPassword": "Welcome@123",
        }),
    )


# -------------------------------
# Dashboard
# -------------------------------
@app.get("/dashboard")
async def getDashboard(user: dict = Depends(requireAuth)):
    role = user.get("role")
    orgId = user.get("organizationId")

    if role == "SUPER_ADMIN":
        orgCount = await orgsCol.count_documents({})
        totalRequests = await verificationsCol.count_documents({})
        ongoingCount = await verificationsCol.count_documents({"status": {"$in": ["PENDING", "IN_PROGRESS"]}})
        completedCount = await verificationsCol.count_documents({"status": "COMPLETED"})
        failedCount = await verificationsCol.count_documents({"status": "FAILED"})

        stats = {
            "totalOrganizations": orgCount,
            "totalRequests": totalRequests,
            "ongoingVerifications": ongoingCount,
            "completedVerifications": completedCount,
            "failedVerifications": failedCount,
        }
        return JSONResponse(status_code=200, content=jsonable_encoder({"role": "SUPER_ADMIN", "stats": stats}))

    elif role == "ORG_HR":
        employeeCount = await usersCol.count_documents({"organizationId": orgId, "role": "EMPLOYEE"})
        totalRequests = await verificationsCol.count_documents({"organizationId": orgId})
        ongoingCount = await verificationsCol.count_documents({"organizationId": orgId, "status": {"$in": ["PENDING", "IN_PROGRESS"]}})
        completedCount = await verificationsCol.count_documents({"organizationId": orgId, "status": "COMPLETED"})
        failedCount = await verificationsCol.count_documents({"organizationId": orgId, "status": "FAILED"})

        stats = {
            "totalEmployees": employeeCount,
            "totalRequests": totalRequests,
            "ongoingVerifications": ongoingCount,
            "completedVerifications": completedCount,
            "failedVerifications": failedCount,
        }
        return JSONResponse(status_code=200, content=jsonable_encoder({"role": "ORG_HR", "stats": stats}))

    elif role == "EMPLOYEE":
        userId = str(user["_id"])
        totalRequests = await verificationsCol.count_documents({"verifiedByUserId": userId})
        ongoingCount = await verificationsCol.count_documents({"verifiedByUserId": userId, "status": {"$in": ["PENDING", "IN_PROGRESS"]}})
        completedCount = await verificationsCol.count_documents({"verifiedByUserId": userId, "status": "COMPLETED"})
        failedCount = await verificationsCol.count_documents({"verifiedByUserId": userId, "status": "FAILED"})

        stats = {
            "totalAssigned": totalRequests,
            "ongoingVerifications": ongoingCount,
            "completedVerifications": completedCount,
            "failedVerifications": failedCount,
        }
        return JSONResponse(status_code=200, content=jsonable_encoder({"role": "EMPLOYEE", "stats": stats}))

    else:
        raise HTTPException(status_code=403, detail="Unknown role or not authorized")


# -------------------------------
# Health Check
# -------------------------------
@app.get("/health")
async def health():
    return {"status": "ok"}
