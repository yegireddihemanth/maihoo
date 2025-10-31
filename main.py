from fastapi import FastAPI, HTTPException, Request, Response, Depends, Body
from pydantic import BaseModel
from motor.motor_asyncio import AsyncIOMotorClient
from fastapi.responses import JSONResponse
from datetime import datetime, timezone
from typing import List, Optional
import os, time, hmac, hashlib, base64, json
from fastapi.middleware.cors import CORSMiddleware
from bson import ObjectId
from fastapi.encoders import jsonable_encoder

# -------------------------------
# Config
# -------------------------------
mongoUri = "mongodb+srv://maihoo:akonpopStar%40143@maihoo.ztaytqd.mongodb.net/?appName=maihoo"
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

origins = [
    "https://localhost:3443",
    "https://bab4f4a54b2b.ngrok-free.app",
    "http://localhost:3000",
    "https://localhost:3000",
    "http://127.0.0.1:3000",
    "https://2440df7ab360.ngrok-free.app",
    "https://maihoo.onrender.com",
    "*"
]

app.add_middleware(
    CORSMiddleware,
    allow_origin_regex="https://.*",
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
        "timestamp": datetime.now(timezone.utc).isoformat()
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

class HrAdminModel(BaseModel):
    userName: str
    email: str
    password: Optional[str] = "Welcome1"
    phoneNumber: Optional[str] = None
    role: Optional[str] = "ORG_HR"

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
    hrAdmin: HrAdminModel

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
    user = await usersCol.find_one({
        "email": body.email,
        "password": body.password,
        "isActive": True
    })
    if not user:
        raise HTTPException(status_code=401, detail="invalid credentials")

    orgId = user.get("organizationId")
    isSuperAdmin = user.get("role") == "SUPER_ADMIN"
    now = int(time.time())
    payload = {
        "email": user["email"],
        "role": user["role"],
        "organizationId": orgId,
        "iat": now,
        "exp": now + cookieMaxAge
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
        "phoneNumber": user.get("phoneNumber"),
        "isSuperAdmin": isSuperAdmin,
        "session": "created",
        "token": token
    }

@app.get("/auth/session")
async def verifySession(user: dict = Depends(requireAuth)):
    return {
        "userName": user.get("userName"),
        "email": user.get("email"),
        "role": user.get("role"),
        "organizationId": user.get("organizationId"),
        "phoneNumber": user.get("phoneNumber"),
        "permissions": user.get("permissions", []),
        "session": "active"
    }

@app.post("/auth/logout")
async def logout(user: dict = Depends(requireAuth), response: Response = None):
    await logActivity(user, "User Logout", f"{user.get('email')} logged out.", "Info")
    if response:
        response.delete_cookie(key=cookieName, path="/")
    return {"ok": True}

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
        "$or": [
            {"email": body.email},
            {"mainDomain": body.mainDomain},
            {"subDomain": autoSubDomain}
        ]
    })
    if existingOrg:
        await logActivity(user, "Register Organization Failed", f"Duplicate org: {body.email}", "Error")
        raise HTTPException(status_code=409, detail="Organization with same email or domain already exists")

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
        "isActive": True
    }
    insertOrg = await orgsCol.insert_one(orgDoc)
    orgId = str(insertOrg.inserted_id)

    DEFAULT_HR_PERMISSIONS = [
        "organization:view",
        "organization:update",
        "employee:create",
        "verification:view",
        "verification:assign",
        "dashboard:view"
    ]

    hr = body.hrAdmin
    hrUser = {
        "userName": hr.userName,
        "email": hr.email,
        "password": hr.password or "Welcome1",
        "role": hr.role,
        "phoneNumber": hr.phoneNumber,
        "organizationId": orgId,
        "permissions": DEFAULT_HR_PERMISSIONS,
        "isActive": True,
        "createdAt": now,
        "createdBy": user.get("email")
    }

    await usersCol.insert_one(hrUser)
    await logActivity(user, "Created Organization", f"Created org '{body.organizationName}' with HR '{hr.email}'", "Success")

    return JSONResponse(
        status_code=201,
        content=jsonable_encoder({
            "message": "Organization registered successfully",
            "organizationId": orgId,
            "organizationName": body.organizationName,
            "hrEmail": hr.email,
            "hrPhoneNumber": hr.phoneNumber,
            "defaultPassword": hr.password or "Welcome1"
        })
    )

# -------------------------------
# Get All Organizations
# -------------------------------
@app.get("/secure/getAllOrganizations")
async def getAllOrganizations(user: dict = Depends(requireAuth)):
    if user.get("role") != "SUPER_ADMIN":
        raise HTTPException(status_code=403, detail="Only SUPER_ADMIN can access all organizations")

    cursor = orgsCol.find({})
    orgList = await cursor.to_list(None)
    results = []
    for org in orgList:
        org["_id"] = str(org["_id"])
        results.append(jsonable_encoder(org))

    await logActivity(user, "View Organizations", "Fetched all organizations list.", "Success")

    return JSONResponse(
        status_code=200,
        content={"totalOrganizations": len(results), "organizations": results}
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
            "failedVerifications": failedCount
        }

        await logActivity(user, "View Dashboard", "Super Admin viewed dashboard.", "Success")
        return JSONResponse(status_code=200, content=jsonable_encoder({"role": "SUPER_ADMIN", "stats": stats}))

    elif role == "ORG_HR":
        employeeCount = await usersCol.count_documents({
        "organizationId": orgId,
        "role": {"$in": ["ORG_HR", "HELPER", "EMPLOYEE"]},
        "isActive": True
        })

        totalRequests = await verificationsCol.count_documents({"organizationId": orgId})
        ongoingCount = await verificationsCol.count_documents({"organizationId": orgId, "status": {"$in": ["PENDING", "IN_PROGRESS"]}})
        completedCount = await verificationsCol.count_documents({"organizationId": orgId, "status": "COMPLETED"})
        failedCount = await verificationsCol.count_documents({"organizationId": orgId, "status": "FAILED"})

        stats = {
            "totalEmployees": employeeCount,
            "totalRequests": totalRequests,
            "ongoingVerifications": ongoingCount,
            "completedVerifications": completedCount,
            "failedVerifications": failedCount
        }

        await logActivity(user, "View Dashboard", f"ORG_HR viewed dashboard for org {orgId}.", "Success")
        return JSONResponse(status_code=200, content=jsonable_encoder({"role": "ORG_HR", "stats": stats}))

    elif role in ["EMPLOYEE", "HELPER"]:
        userId = str(user["_id"])
        totalRequests = await verificationsCol.count_documents({"verifiedByUserId": userId})
        ongoingCount = await verificationsCol.count_documents({"verifiedByUserId": userId, "status": {"$in": ["PENDING", "IN_PROGRESS"]}})
        completedCount = await verificationsCol.count_documents({"verifiedByUserId": userId, "status": "COMPLETED"})
        failedCount = await verificationsCol.count_documents({"verifiedByUserId": userId, "status": "FAILED"})

        stats = {
            "totalAssigned": totalRequests,
            "ongoingVerifications": ongoingCount,
            "completedVerifications": completedCount,
            "failedVerifications": failedCount
        }

        await logActivity(user, "View Dashboard", "Helper viewed personal dashboard.", "Success")
        return JSONResponse(status_code=200, content=jsonable_encoder({"role": role, "stats": stats}))


    else:
        raise HTTPException(status_code=403, detail="Unknown role or not authorized")

# -------------------------------
# Update Organization
# -------------------------------
@app.put("/secure/updateOrganization/{orgId}")
async def updateOrganization(orgId: str, body: dict, user: dict = Depends(requireAuth)):
    if user.get("role") != "SUPER_ADMIN":
        raise HTTPException(status_code=403, detail="Only SUPER_ADMIN can update organizations")

    try:
        object_id = ObjectId(orgId)
    except Exception:
        await logActivity(user, "Update Organization Failed", f"Invalid organization ID: {orgId}", "Error")
        raise HTTPException(status_code=400, detail="Invalid organization ID")

    org = await orgsCol.find_one({"_id": object_id})
    if not org:
        await logActivity(user, "Update Organization Failed", f"Organization not found: {orgId}", "Error")
        raise HTTPException(status_code=404, detail="Organization not found")

    validFields = [
        "organizationName", "spocName", "mainDomain", "subDomain", "email",
        "gstNumber", "services", "logoUrl", "credentials", "isActive"
    ]

    updateData = {k: body[k] for k in validFields if k in body}
    if not updateData:
        raise HTTPException(status_code=400, detail="No valid fields provided for update")

    updateData["updatedAt"] = datetime.now(timezone.utc).isoformat()
    await orgsCol.update_one({"_id": object_id}, {"$set": updateData})
    updatedOrg = await orgsCol.find_one({"_id": object_id})

    if "_id" in updatedOrg:
        updatedOrg["_id"] = str(updatedOrg["_id"])
    for field in ["createdAt", "updatedAt"]:
        if field in updatedOrg and isinstance(updatedOrg[field], datetime):
            updatedOrg[field] = updatedOrg[field].isoformat()

    await logActivity(user, "Updated Organization", f"Updated organization '{updatedOrg.get('organizationName')}'.", "Success")

    return JSONResponse(
        status_code=200,
        content={"message": "Organization details updated successfully", "updatedOrganization": updatedOrg}
    )

# -------------------------------
# Add Helper User (for Super Admin or HR)
# -------------------------------
@app.post("/secure/addHelper")
async def addHelper(body: dict = Body(...), user: dict = Depends(requireAuth)):
    role = user.get("role")
    if role not in ["SUPER_ADMIN", "ORG_HR"]:
        raise HTTPException(status_code=403, detail="Only SUPER_ADMIN or ORG_HR can add helpers")

    helperName = body.get("userName")
    helperEmail = body.get("email")
    helperRole = body.get("role")
    helperPhone = body.get("phoneNumber")
    helperPermissions = body.get("permissions", [])
    helperIsActive = body.get("isActive", True)
    helperPassword = body.get("password") or "Welcome1"

    if not helperName or not helperEmail or not helperRole:
        raise HTTPException(status_code=400, detail="Missing required fields: userName, email, role")

    orgId = user.get("organizationId")
    createdBy = user.get("email")

    org = await orgsCol.find_one({"_id": ObjectId(orgId)})
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")

    totalAllowed = org.get("credentials", {}).get("totalAllowed", 0)
    activeUsersCount = await usersCol.count_documents({"organizationId": orgId, "isActive": True})

    if activeUsersCount >= totalAllowed:
        await logActivity(user, "Add Helper Failed", f"User limit reached ({activeUsersCount}/{totalAllowed}) for org {orgId}", "Error")
        raise HTTPException(status_code=409, detail="User limit exceeded. Cannot add more helpers.")

    existingUser = await usersCol.find_one({"email": helperEmail})
    if existingUser:
        raise HTTPException(status_code=409, detail="A user with this email already exists")

    now = datetime.now(timezone.utc).isoformat()
    helperDoc = {
        "userName": helperName,
        "email": helperEmail,
        "password": helperPassword,
        "role": helperRole,
        "phoneNumber": helperPhone,
        "permissions": helperPermissions,
        "isActive": helperIsActive,
        "organizationId": orgId,
        "createdAt": now,
        "createdBy": createdBy
    }

    insertResult = await usersCol.insert_one(helperDoc)
    helperId = str(insertResult.inserted_id)

    newActiveUsersCount = await usersCol.count_documents({"organizationId": orgId, "isActive": True})
    await orgsCol.update_one({"_id": ObjectId(orgId)}, {"$set": {"credentials.used": newActiveUsersCount}})

    await logActivity(user, "Added Helper User", f"{createdBy} added helper {helperEmail} (role: {helperRole})", "Success")

    return JSONResponse(
        status_code=201,
        content=jsonable_encoder({
            "message": "Helper user added successfully",
            "userId": helperId,
            "organizationId": orgId,
            "usedCredentials": newActiveUsersCount,
            "totalAllowed": totalAllowed,
            "defaultPassword": helperPassword
        })
    )

# -------------------------------
# Fetch Activity Logs
# -------------------------------
@app.get("/secure/activityLogs")
async def getActivityLogs(user: dict = Depends(requireAuth)):
    query = {}
    if user.get("role") != "SUPER_ADMIN":
        query["organizationId"] = user.get("organizationId")

    cursor = activityLogsCol.find(query).sort("timestamp", -1)
    logs = await cursor.to_list(length=200)

    # Convert ObjectIds to string for each log (same convention as other functions)
    for log in logs:
        if "_id" in log:
            log["_id"] = str(log["_id"])
        if "userId" in log and isinstance(log["userId"], ObjectId):
            log["userId"] = str(log["userId"])
        if "organizationId" in log and isinstance(log["organizationId"], ObjectId):
            log["organizationId"] = str(log["organizationId"])

    # Use JSONResponse and jsonable_encoder like all other endpoints
    return JSONResponse(
        status_code=200,
        content=jsonable_encoder({
            "totalLogs": len(logs),
            "logs": logs
        })
    )


# -------------------------------
# Health Check
# -------------------------------
@app.get("/health")
async def health():
    return {"status": "ok"}
