
from fastapi import FastAPI, HTTPException, Request, Response, Depends
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
    "https://bab4f4a54b2b.ngrok-free.app",
    "http://10.12.88.79:5001",
    "https://2440df7ab360.ngrok-free.app",
    "https://bab4f4a54b2b.ngrok-free.app",
    "*",
    "https://maihoo.onrender.com"
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
activityLogsCol = db["activity_logs"]  # 👈 added new collection

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
    """Creates an audit trail entry for any CRUD or auth action."""
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
    user = await usersCol.find_one({
        "email": body.email,
        "password": body.password,
        "isActive": True
    })
    if not user:
        raise HTTPException(status_code=401, detail="invalid credentials")

    orgDoc = None
    orgId = user.get("organizationId")
    if orgId:
        try:
            orgDoc = await orgsCol.find_one({"_id": ObjectId(orgId)})
        except:
            orgDoc = await orgsCol.find_one({"_id": orgId})

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
        "isSuperAdmin": isSuperAdmin,
        "session": "created",
        "token" : token
    }


from fastapi import FastAPI, HTTPException, Request, Response, Depends
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
    "https://bab4f4a54b2b.ngrok-free.app",
    "http://10.12.88.79:5001",
    "https://2440df7ab360.ngrok-free.app",
    "https://bab4f4a54b2b.ngrok-free.app",
    "*",
    "https://maihoo.onrender.com"
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
activityLogsCol = db["activity_logs"]  # 👈 added new collection

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
    """Creates an audit trail entry for any CRUD or auth action."""
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
    user = await usersCol.find_one({
        "email": body.email,
        "password": body.password,
        "isActive": True
    })
    if not user:
        raise HTTPException(status_code=401, detail="invalid credentials")

    orgDoc = None
    orgId = user.get("organizationId")
    if orgId:
        try:
            orgDoc = await orgsCol.find_one({"_id": ObjectId(orgId)})
        except:
            orgDoc = await orgsCol.find_one({"_id": orgId})

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
        "isSuperAdmin": isSuperAdmin,
        "session": "created",
        "token" : token
    }

@app.get("/auth/session")
async def verifySession(user: dict = Depends(requireAuth)):
    """
    Verifies if the user session cookie is still valid.
    Returns user info if valid, else 401.
    """
    return {
        "userName": user.get("userName"),
        "email": user.get("email"),
        "role": user.get("role"),
        "organizationId": user.get("organizationId"),
        "session": "active"
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
from fastapi.encoders import jsonable_encoder

@app.get("/secure/getAllOrganizations")
async def getAllOrganizations(user: dict = Depends(requireAuth)):
    # Only super admin can access
    if user.get("role") != "SUPER_ADMIN":
        raise HTTPException(status_code=403, detail="Only SUPER_ADMIN can access all organizations")

    # Fetch all organizations
    cursor = orgsCol.find({})
    orgList = await cursor.to_list(None)

    # Convert ObjectId → str and datetime → ISO string
    results = []
    for org in orgList:
        org["_id"] = str(org["_id"])
        results.append(jsonable_encoder(org))

    # Log activity
    await logActivity(user, "View Organizations", "Fetched all organizations list.", "Success")

    return JSONResponse(
        status_code=200,
        content={
            "totalOrganizations": len(results),
            "organizations": results
        }
    )



# -------------------------------
# Register Organization
# -------------------------------
from fastapi.encoders import jsonable_encoder
from datetime import datetime, timezone
from bson import ObjectId
from fastapi import HTTPException
from fastapi.responses import JSONResponse

# -------------------------------
# Register Organization
# -------------------------------
@app.post("/secure/registerOrganization")
async def registerOrganization(body: OrganizationRegistration, user: dict = Depends(requireAuth)):
    # Allow only Super Admin
    if user.get("role") != "SUPER_ADMIN":
        raise HTTPException(status_code=403, detail="Only SUPER_ADMIN can register organizations")

    # Auto-generate subdomain if not provided
    cleanOrgName = body.organizationName.split()[0].lower()
    autoSubDomain = body.subDomain or f"{cleanOrgName}.bgvapp.in"

    # Check for duplicates
    existingOrg = await orgsCol.find_one({
        "$or": [
            {"email": body.email},
            {"mainDomain": body.mainDomain},
            {"subDomain": autoSubDomain}
        ]
    })
    if existingOrg:
        await logActivity(user, "Register Organization Failed", f"Duplicate domain or email: {body.email}", "Error")
        raise HTTPException(status_code=409, detail="Organization with same email or domain already exists")

    now = datetime.now(timezone.utc).isoformat()

    # Build org document
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

    # Insert organization
    insertOrg = await orgsCol.insert_one(orgDoc)
    orgId = str(insertOrg.inserted_id)

    # Create default SPOC user (ORG_HR)
    spocUser = {
        "userName": body.spocName,
        "email": body.email,
        "password": "Welcome@123",
        "role": "ORG_HR",
        "organizationId": orgId,
        "isActive": True,
        "createdAt": now,
        "createdBy": user.get("email")
    }
    await usersCol.insert_one(spocUser)

    await logActivity(user, "Created Organization", f"Organization '{body.organizationName}' created.", "Success")

    # ✅ Serialize safely
    return JSONResponse(
        status_code=201,
        content=jsonable_encoder({
            "message": "Organization registered successfully",
            "orgId": orgId,
            "organizationName": body.organizationName,
            "spocEmail": body.email,
            "defaultPassword": "Welcome@123"
        })
    )

from fastapi import HTTPException
from fastapi.responses import JSONResponse
from fastapi.encoders import jsonable_encoder

@app.get("/dashboard")
async def getDashboard(user: dict = Depends(requireAuth)):
    role = user.get("role")
    orgId = user.get("organizationId")

    # -------------------------------
    # SUPER ADMIN DASHBOARD
    # -------------------------------
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

    # -------------------------------
    # ORG HR DASHBOARD
    # -------------------------------
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
            "failedVerifications": failedCount
        }

        await logActivity(user, "View Dashboard", f"ORG_HR viewed dashboard for org {orgId}.", "Success")
        return JSONResponse(status_code=200, content=jsonable_encoder({"role": "ORG_HR", "stats": stats}))

    # -------------------------------
    # EMPLOYEE DASHBOARD
    # -------------------------------
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
            "failedVerifications": failedCount
        }

        await logActivity(user, "View Dashboard", f"Employee viewed personal dashboard.", "Success")
        return JSONResponse(status_code=200, content=jsonable_encoder({"role": "EMPLOYEE", "stats": stats}))

    else:
        raise HTTPException(status_code=403, detail="Unknown role or not authorized")

# -------------------------------
# Update Organization
# -------------------------------
@app.put("/secure/updateOrganization/{orgId}")
async def updateOrganization(orgId: str, body: dict, user: dict = Depends(requireAuth)):
    # Only SUPER_ADMIN can update
    if user.get("role") != "SUPER_ADMIN":
        raise HTTPException(status_code=403, detail="Only SUPER_ADMIN can update organizations")

    # Validate MongoDB ObjectId
    try:
        object_id = ObjectId(orgId)
    except Exception:
        await logActivity(user, "Update Organization Failed", f"Invalid organization ID: {orgId}", "Error")
        raise HTTPException(status_code=400, detail="Invalid organization ID")

    # Check organization existence
    org = await orgsCol.find_one({"_id": object_id})
    if not org:
        await logActivity(user, "Update Organization Failed", f"Organization not found: {orgId}", "Error")
        raise HTTPException(status_code=404, detail="Organization not found")

    # Allowed fields
    validFields = [
        "organizationName", "spocName", "mainDomain", "subDomain", "email",
        "gstNumber", "services", "logoUrl", "credentials", "isActive"
    ]

    # Filter incoming data
    updateData = {k: body[k] for k in validFields if k in body}
    if not updateData:
        raise HTTPException(status_code=400, detail="No valid fields provided for update")

    # Add updatedAt
    updateData["updatedAt"] = datetime.now(timezone.utc).isoformat()

    # Update organization
    await orgsCol.update_one({"_id": object_id}, {"$set": updateData})

    # ✅ Fetch updated doc safely
    updatedOrg = await orgsCol.find_one({"_id": object_id})

    # ✅ Convert ObjectId and datetime manually
    if "_id" in updatedOrg:
        updatedOrg["_id"] = str(updatedOrg["_id"])
    for field in ["createdAt", "updatedAt"]:
        if field in updatedOrg and isinstance(updatedOrg[field], datetime):
            updatedOrg[field] = updatedOrg[field].isoformat()

    # ✅ Log activity
    await logActivity(user, "Updated Organization", f"Updated organization '{updatedOrg.get('organizationName')}'.", "Success")

    # ✅ Return clean JSON
    return JSONResponse(
        status_code=200,
        content={
            "message": "Organization details updated successfully",
            "updatedOrganization": updatedOrg
        }
    )

# -------------------------------
# Fetch Activity Logs (role-based)
# -------------------------------
@app.get("/secure/activityLogs")
async def getActivityLogs(user: dict = Depends(requireAuth)):
    query = {}
    if user.get("role") != "SUPER_ADMIN":
        query["organizationId"] = user.get("organizationId")

    cursor = activityLogsCol.find(query).sort("timestamp", -1)
    logs = await cursor.to_list(length=200)
    for log in logs:
        log["_id"] = str(log["_id"])

    return {"totalLogs": len(logs), "logs": logs}


# -------------------------------
# Health Check
# -------------------------------
@app.get("/health")
async def health():
    return {"status": "ok"}

@app.post("/auth/logout")
async def logout(user: dict = Depends(requireAuth), response: Response = None):
    await logActivity(user, "User Logout", f"{user.get('email')} logged out.", "Info")
    if response:
        response.delete_cookie(key=cookieName, path="/")
    return {"ok": True}


# -------------------------------
# Get All Organizations
# -------------------------------
from fastapi.encoders import jsonable_encoder

@app.get("/secure/getAllOrganizations")
async def getAllOrganizations(user: dict = Depends(requireAuth)):
    # Only super admin can access
    if user.get("role") != "SUPER_ADMIN":
        raise HTTPException(status_code=403, detail="Only SUPER_ADMIN can access all organizations")

    # Fetch all organizations
    cursor = orgsCol.find({})
    orgList = await cursor.to_list(None)

    # Convert ObjectId → str and datetime → ISO string
    results = []
    for org in orgList:
        org["_id"] = str(org["_id"])
        results.append(jsonable_encoder(org))

    # Log activity
    await logActivity(user, "View Organizations", "Fetched all organizations list.", "Success")

    return JSONResponse(
        status_code=200,
        content={
            "totalOrganizations": len(results),
            "organizations": results
        }
    )



# -------------------------------
# Register Organization
# -------------------------------
from fastapi.encoders import jsonable_encoder
from datetime import datetime, timezone
from bson import ObjectId
from fastapi import HTTPException
from fastapi.responses import JSONResponse

# -------------------------------
# Register Organization
# -------------------------------
@app.post("/secure/registerOrganization")
async def registerOrganization(body: OrganizationRegistration, user: dict = Depends(requireAuth)):
    # Allow only Super Admin
    if user.get("role") != "SUPER_ADMIN":
        raise HTTPException(status_code=403, detail="Only SUPER_ADMIN can register organizations")

    # Auto-generate subdomain if not provided
    cleanOrgName = body.organizationName.split()[0].lower()
    autoSubDomain = body.subDomain or f"{cleanOrgName}.bgvapp.in"

    # Check for duplicates
    existingOrg = await orgsCol.find_one({
        "$or": [
            {"email": body.email},
            {"mainDomain": body.mainDomain},
            {"subDomain": autoSubDomain}
        ]
    })
    if existingOrg:
        await logActivity(user, "Register Organization Failed", f"Duplicate domain or email: {body.email}", "Error")
        raise HTTPException(status_code=409, detail="Organization with same email or domain already exists")

    now = datetime.now(timezone.utc).isoformat()

    # Build org document
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

    # Insert organization
    insertOrg = await orgsCol.insert_one(orgDoc)
    orgId = str(insertOrg.inserted_id)

    # Create default SPOC user (ORG_HR)
    spocUser = {
        "userName": body.spocName,
        "email": body.email,
        "password": "Welcome@123",
        "role": "ORG_HR",
        "organizationId": orgId,
        "isActive": True,
        "createdAt": now,
        "createdBy": user.get("email")
    }
    await usersCol.insert_one(spocUser)

    await logActivity(user, "Created Organization", f"Organization '{body.organizationName}' created.", "Success")

    # ✅ Serialize safely
    return JSONResponse(
        status_code=201,
        content=jsonable_encoder({
            "message": "Organization registered successfully",
            "orgId": orgId,
            "organizationName": body.organizationName,
            "spocEmail": body.email,
            "defaultPassword": "Welcome@123"
        })
    )

from fastapi import HTTPException
from fastapi.responses import JSONResponse
from fastapi.encoders import jsonable_encoder

@app.get("/dashboard")
async def getDashboard(user: dict = Depends(requireAuth)):
    role = user.get("role")
    orgId = user.get("organizationId")

    # -------------------------------
    # SUPER ADMIN DASHBOARD
    # -------------------------------
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

    # -------------------------------
    # ORG HR DASHBOARD
    # -------------------------------
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
            "failedVerifications": failedCount
        }

        await logActivity(user, "View Dashboard", f"ORG_HR viewed dashboard for org {orgId}.", "Success")
        return JSONResponse(status_code=200, content=jsonable_encoder({"role": "ORG_HR", "stats": stats}))

    # -------------------------------
    # EMPLOYEE DASHBOARD
    # -------------------------------
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
            "failedVerifications": failedCount
        }

        await logActivity(user, "View Dashboard", f"Employee viewed personal dashboard.", "Success")
        return JSONResponse(status_code=200, content=jsonable_encoder({"role": "EMPLOYEE", "stats": stats}))

    else:
        raise HTTPException(status_code=403, detail="Unknown role or not authorized")

# -------------------------------
# Update Organization
# -------------------------------
@app.put("/secure/updateOrganization/{orgId}")
async def updateOrganization(orgId: str, body: dict, user: dict = Depends(requireAuth)):
    # Only SUPER_ADMIN can update
    if user.get("role") != "SUPER_ADMIN":
        raise HTTPException(status_code=403, detail="Only SUPER_ADMIN can update organizations")

    # Validate MongoDB ObjectId
    try:
        object_id = ObjectId(orgId)
    except Exception:
        await logActivity(user, "Update Organization Failed", f"Invalid organization ID: {orgId}", "Error")
        raise HTTPException(status_code=400, detail="Invalid organization ID")

    # Check organization existence
    org = await orgsCol.find_one({"_id": object_id})
    if not org:
        await logActivity(user, "Update Organization Failed", f"Organization not found: {orgId}", "Error")
        raise HTTPException(status_code=404, detail="Organization not found")

    # Allowed fields
    validFields = [
        "organizationName", "spocName", "mainDomain", "subDomain", "email",
        "gstNumber", "services", "logoUrl", "credentials", "isActive"
    ]

    # Filter incoming data
    updateData = {k: body[k] for k in validFields if k in body}
    if not updateData:
        raise HTTPException(status_code=400, detail="No valid fields provided for update")

    # Add updatedAt
    updateData["updatedAt"] = datetime.now(timezone.utc).isoformat()

    # Update organization
    await orgsCol.update_one({"_id": object_id}, {"$set": updateData})

    # ✅ Fetch updated doc safely
    updatedOrg = await orgsCol.find_one({"_id": object_id})

    # ✅ Convert ObjectId and datetime manually
    if "_id" in updatedOrg:
        updatedOrg["_id"] = str(updatedOrg["_id"])
    for field in ["createdAt", "updatedAt"]:
        if field in updatedOrg and isinstance(updatedOrg[field], datetime):
            updatedOrg[field] = updatedOrg[field].isoformat()

    # ✅ Log activity
    await logActivity(user, "Updated Organization", f"Updated organization '{updatedOrg.get('organizationName')}'.", "Success")

    # ✅ Return clean JSON
    return JSONResponse(
        status_code=200,
        content={
            "message": "Organization details updated successfully",
            "updatedOrganization": updatedOrg
        }
    )

# -------------------------------
# Fetch Activity Logs (role-based)
# -------------------------------
@app.get("/secure/activityLogs")
async def getActivityLogs(user: dict = Depends(requireAuth)):
    query = {}
    if user.get("role") != "SUPER_ADMIN":
        query["organizationId"] = user.get("organizationId")

    cursor = activityLogsCol.find(query).sort("timestamp", -1)
    logs = await cursor.to_list(length=200)
    for log in logs:
        log["_id"] = str(log["_id"])

    return {"totalLogs": len(logs), "logs": logs}


# -------------------------------
# Health Check
# -------------------------------
@app.get("/health")
async def health():
    return {"status": "ok"}
