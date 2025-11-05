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

from bson.errors import InvalidId
from datetime import datetime, timezone
from fastapi import Body, Depends, HTTPException
from fastapi.responses import JSONResponse

from fastapi import APIRouter, Body, Depends, HTTPException
from fastapi.responses import JSONResponse
from datetime import datetime, timezone
from bson import ObjectId
from bson.errors import InvalidId
import asyncio
from apis import run_verification  # ← Import dummy verification dispatcher

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
candidatesCol = db["candidates"] 

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
        "token": token,
        "permissions": user.get("permissions")
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

# # -------------------------------
# # Get All Organizations
# # -------------------------------
# @app.get("/secure/getAllOrganizations")
# async def getAllOrganizations(user: dict = Depends(requireAuth)):
#     if user.get("role") != "SUPER_ADMIN":
#         raise HTTPException(status_code=403, detail="Only SUPER_ADMIN can access all organizations")

#     cursor = orgsCol.find({})
#     orgList = await cursor.to_list(None)
#     results = []
#     for org in orgList:
#         org["_id"] = str(org["_id"])
#         results.append(jsonable_encoder(org))

#     await logActivity(user, "View Organizations", "Fetched all organizations list.", "Success")

#     return JSONResponse(
#         status_code=200,
#         content={"totalOrganizations": len(results), "organizations": results}
#     )

# -------------------------------
# Dashboard
# -------------------------------
@app.get("/dashboard")
async def getDashboard(user: dict = Depends(requireAuth)):
    role = user.get("role")
    orgId = user.get("organizationId")

    # 🧩 Helper: Count verifications by stage activity (based on checks inside each stage)
    async def stage_breakdown(query):
        stages = ["primary", "secondary", "final"]
        breakdown = {}
        for stage in stages:
            count = await verificationsCol.count_documents({
                **query,
                f"stages.{stage}.status": {"$in": ["IN_PROGRESS", "COMPLETED"]}
            })
            breakdown[stage] = count
        return breakdown

    # -------------------------
    # SUPER ADMIN
    # -------------------------
    if role == "SUPER_ADMIN":
        orgCount = await orgsCol.count_documents({})
        totalRequests = await verificationsCol.count_documents({})
        ongoingCount = await verificationsCol.count_documents({"overallStatus": "IN_PROGRESS"})
        completedCount = await verificationsCol.count_documents({"overallStatus": "COMPLETED"})
        failedCount = await verificationsCol.count_documents({"overallStatus": "FAILED"})
        stageStats = await stage_breakdown({})

        stats = {
            "totalOrganizations": orgCount,
            "totalRequests": totalRequests,
            "ongoingVerifications": ongoingCount,
            "completedVerifications": completedCount,
            "failedVerifications": failedCount,
            "stageBreakdown": stageStats
        }

        await logActivity(user, "View Dashboard", "Super Admin viewed dashboard.", "Success")
        return JSONResponse(status_code=200, content=jsonable_encoder({
            "role": "SUPER_ADMIN",
            "stats": stats
        }))

    # -------------------------
    # SUPER ADMIN HELPER
    # -------------------------
    elif role == "SUPER_ADMIN_HELPER":
        accessible = user.get("accessibleOrganizations", [])
        if not accessible:
            raise HTTPException(status_code=403, detail="No organizations assigned")

        orgQuery = {"organizationId": {"$in": accessible}}
        totalRequests = await verificationsCol.count_documents(orgQuery)
        ongoingCount = await verificationsCol.count_documents({**orgQuery, "overallStatus": "IN_PROGRESS"})
        completedCount = await verificationsCol.count_documents({**orgQuery, "overallStatus": "COMPLETED"})
        failedCount = await verificationsCol.count_documents({**orgQuery, "overallStatus": "FAILED"})
        stageStats = await stage_breakdown(orgQuery)

        stats = {
            "accessibleOrganizations": len(accessible),
            "totalRequests": totalRequests,
            "ongoingVerifications": ongoingCount,
            "completedVerifications": completedCount,
            "failedVerifications": failedCount,
            "stageBreakdown": stageStats
        }

        await logActivity(
            user, "View Dashboard",
            f"Super Admin Helper viewed dashboard for {len(accessible)} orgs.",
            "Success"
        )

        return JSONResponse(status_code=200, content=jsonable_encoder({
            "role": "SUPER_ADMIN_HELPER",
            "stats": stats
        }))

    # -------------------------
    # HR ADMIN
    # -------------------------
    elif role == "ORG_HR":
        employeeCount = await usersCol.count_documents({
            "organizationId": orgId,
            "role": {"$in": ["ORG_HR", "HELPER", "EMPLOYEE"]},
            "isActive": True
        })

        orgQuery = {"organizationId": orgId}
        totalRequests = await verificationsCol.count_documents(orgQuery)
        ongoingCount = await verificationsCol.count_documents({**orgQuery, "overallStatus": "IN_PROGRESS"})
        completedCount = await verificationsCol.count_documents({**orgQuery, "overallStatus": "COMPLETED"})
        failedCount = await verificationsCol.count_documents({**orgQuery, "overallStatus": "FAILED"})
        stageStats = await stage_breakdown(orgQuery)

        stats = {
            "totalEmployees": employeeCount,
            "totalRequests": totalRequests,
            "ongoingVerifications": ongoingCount,
            "completedVerifications": completedCount,
            "failedVerifications": failedCount,
            "stageBreakdown": stageStats
        }

        await logActivity(user, "View Dashboard", f"ORG_HR viewed dashboard for org {orgId}.", "Success")
        return JSONResponse(status_code=200, content=jsonable_encoder({
            "role": "ORG_HR",
            "stats": stats
        }))

    # -------------------------
    # HELPER / EMPLOYEE
    # -------------------------
    elif role in ["HELPER", "EMPLOYEE"]:
        userId = str(user["_id"])
        userQuery = {"assignedTo": userId}
        totalRequests = await verificationsCol.count_documents(userQuery)
        ongoingCount = await verificationsCol.count_documents({**userQuery, "overallStatus": "IN_PROGRESS"})
        completedCount = await verificationsCol.count_documents({**userQuery, "overallStatus": "COMPLETED"})
        failedCount = await verificationsCol.count_documents({**userQuery, "overallStatus": "FAILED"})
        stageStats = await stage_breakdown(userQuery)

        stats = {
            "totalAssigned": totalRequests,
            "ongoingVerifications": ongoingCount,
            "completedVerifications": completedCount,
            "failedVerifications": failedCount,
            "stageBreakdown": stageStats
        }

        await logActivity(user, "View Dashboard", f"{role} viewed personal dashboard.", "Success")
        return JSONResponse(status_code=200, content=jsonable_encoder({
            "role": role,
            "stats": stats
        }))

    # -------------------------
    # FALLBACK
    # -------------------------
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
    accessibleOrgs = body.get("accessibleOrganizations", [])  # ✅ NEW FIELD for multi-org access

    if not helperName or not helperEmail or not helperRole:
        raise HTTPException(status_code=400, detail="Missing required fields: userName, email, role")

    # 🧠 Organization selection logic
    # SUPER_ADMIN can add to any org by giving orgId; if not given, default to their own org
    if role == "SUPER_ADMIN":
        orgId = body.get("organizationId") or user.get("organizationId")
    else:
        orgId = user.get("organizationId")

    if not orgId:
        raise HTTPException(status_code=400, detail="Organization ID missing or invalid")

    # 🧾 Validate organization
    try:
        org = await orgsCol.find_one({"_id": ObjectId(orgId)})
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid organization ID format")

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
        "accessibleOrganizations": accessibleOrgs,  # ✅ store assigned orgs for helper
        "isActive": helperIsActive,
        "organizationId": orgId,
        "createdAt": now,
        "createdBy": user.get("email")
    }

    insertResult = await usersCol.insert_one(helperDoc)
    helperId = str(insertResult.inserted_id)

    # 🔄 Update used credentials count for that organization
    newActiveUsersCount = await usersCol.count_documents({"organizationId": orgId, "isActive": True})
    await orgsCol.update_one({"_id": ObjectId(orgId)}, {"$set": {"credentials.used": newActiveUsersCount}})

    await logActivity(
        user,
        "Added Helper User",
        f"{user.get('email')} added helper {helperEmail} (role: {helperRole}) under org {org.get('organizationName')}",
        "Success"
    )

    # 🧠 Construct response
    response_data = {
        "message": "Helper user added successfully",
        "organization": {
            "organizationId": str(org["_id"]),
            "organizationName": org.get("organizationName")
        },
        "helper": {
            "userId": helperId,
            "userName": helperName,
            "email": helperEmail,
            "role": helperRole,
            "phoneNumber": helperPhone,
            "permissions": helperPermissions,
            "isActive": helperIsActive,
            "defaultPassword": helperPassword,
            "accessibleOrganizations": accessibleOrgs  # ✅ included in response
        },
        "credentialsStatus": {
            "used": newActiveUsersCount,
            "totalAllowed": totalAllowed
        }
    }

    return JSONResponse(status_code=201, content=jsonable_encoder(response_data))


# @app.get("/secure/getOrganizationsList")
# async def getOrganizationsList(user: dict = Depends(requireAuth)):
#     role = user.get("role")
#     orgs = []

#     # --- Super Admin: full access ---
#     if role == "SUPER_ADMIN":
#         cursor = orgsCol.find({}, {"organizationName": 1})
#         async for org in cursor:
#             orgs.append({
#                 "orgId": str(org["_id"]),
#                 "organizationName": org["organizationName"]
#             })

#     # --- Super Admin Helper: only assigned orgs ---
#     elif role == "SUPER_ADMIN_HELPER":
#         accessible = user.get("accessibleOrganizations", [])
#         if not accessible:
#             raise HTTPException(status_code=403, detail="No organizations assigned")
#         cursor = orgsCol.find(
#             {"_id": {"$in": [ObjectId(o) for o in accessible]}},
#             {"organizationName": 1}
#         )
#         async for org in cursor:
#             orgs.append({
#                 "orgId": str(org["_id"]),
#                 "organizationName": org["organizationName"]
#             })

#     # --- HR Admin: only their org ---
#     elif role == "ORG_HR":
#         orgId = user.get("organizationId")
#         org = await orgsCol.find_one(
#             {"_id": ObjectId(orgId)},
#             {"organizationName": 1}
#         )
#         if org:
#             orgs.append({
#                 "orgId": str(org["_id"]),
#                 "organizationName": org["organizationName"]
#             })

#     else:
#         raise HTTPException(status_code=403, detail="Not authorized to access organizations")

#     await logActivity(
#         user,
#         "Fetched Organizations List",
#         f"Returned {len(orgs)} organizations for role {role}",
#         "Success"
#     )

#     return JSONResponse(
#         status_code=200,
#         content=jsonable_encoder({"organizations": orgs})
#     )


# @app.get("/secure/getAllUsers")
# async def getAllUsers(user: dict = Depends(requireAuth)):
#     role = user.get("role")

#     # Allow only Super Admin or HR
#     if role not in ["SUPER_ADMIN", "ORG_HR"]:
#         raise HTTPException(status_code=403, detail="Not authorized to view users")

#     query = {}
#     if role == "ORG_HR":
#         query["organizationId"] = user.get("organizationId")

#     projection = {"password": 0}
#     cursor = usersCol.find(query, projection)
#     userList = await cursor.to_list(None)

#     results = []
#     for u in userList:
#         u["_id"] = str(u["_id"])
#         orgId = u.get("organizationId")
#         orgName = None

#         if orgId:
#             org = await orgsCol.find_one(
#                 {"_id": ObjectId(orgId)},
#                 {"organizationName": 1}
#             )
#             if org:
#                 orgName = org.get("organizationName")

#         u["organizationName"] = orgName
#         results.append(u)

#     await logActivity(
#         user,
#         "View Users List",
#         f"Fetched {len(results)} users ({'all orgs' if role == 'SUPER_ADMIN' else 'own org'})",
#         "Success"
#     )

#     return JSONResponse(
#         status_code=200,
#         content=jsonable_encoder({
#             "totalUsers": len(results),
#             "users": results
#         })
#     )

@app.get("/secure/getUsers")
async def getUsers(user: dict = Depends(requireAuth)):
    role = user.get("role")
    results = []

    # --- SUPER ADMIN: All users across all orgs ---
    if role == "SUPER_ADMIN":
        cursor = usersCol.find({}, {"password": 0})
        async for u in cursor:
            u["_id"] = str(u["_id"])
            orgId = u.get("organizationId")
            orgName = None
            if orgId:
                org = await orgsCol.find_one({"_id": ObjectId(orgId)}, {"organizationName": 1})
                if org:
                    orgName = org.get("organizationName")
            u["organizationName"] = orgName
            results.append(u)

    # --- SUPER ADMIN HELPER: users only from assigned organizations ---
    elif role == "SUPER_ADMIN_HELPER":
        accessible = user.get("accessibleOrganizations", [])
        if not accessible:
            raise HTTPException(status_code=403, detail="No organizations assigned to this helper")

        cursor = usersCol.find(
            {"organizationId": {"$in": accessible}},
            {"password": 0}
        )
        async for u in cursor:
            u["_id"] = str(u["_id"])
            orgId = u.get("organizationId")
            orgName = None
            if orgId:
                org = await orgsCol.find_one({"_id": ObjectId(orgId)}, {"organizationName": 1})
                if org:
                    orgName = org.get("organizationName")
            u["organizationName"] = orgName
            results.append(u)

    # --- HR ADMIN: only users from their own organization ---
    elif role == "ORG_HR":
        orgId = user.get("organizationId")
        if not orgId:
            raise HTTPException(status_code=400, detail="Organization ID missing for HR Admin")
        cursor = usersCol.find(
            {"organizationId": orgId},
            {"password": 0}
        )
        async for u in cursor:
            u["_id"] = str(u["_id"])
            u["organizationName"] = (await orgsCol.find_one(
                {"_id": ObjectId(orgId)},
                {"organizationName": 1}
            )).get("organizationName")
            results.append(u)

    else:
        raise HTTPException(status_code=403, detail="Not authorized to access users list")

    # ✅ Sort users organization-wise (for better clarity)
    results.sort(key=lambda x: x.get("organizationName", "").lower() if x.get("organizationName") else "")

    await logActivity(
        user,
        "View Users",
        f"Fetched {len(results)} users for role {role}",
        "Success"
    )

    return JSONResponse(
        status_code=200,
        content=jsonable_encoder({
            "totalUsers": len(results),
            "users": results
        })
    )

@app.put("/secure/updateUser/{userId}")
async def updateUser(userId: str, body: dict = Body(...), user: dict = Depends(requireAuth)):
    role = user.get("role")

    # --- Validate ID ---
    try:
        object_id = ObjectId(userId)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid user ID format")

    # --- Find Target User ---
    targetUser = await usersCol.find_one({"_id": object_id})
    if not targetUser:
        raise HTTPException(status_code=404, detail="User not found")

    targetOrgId = targetUser.get("organizationId")

    # --- Role-Based Access Control ---
    if role == "SUPER_ADMIN":
        pass  # full control

    elif role == "SUPER_ADMIN_HELPER":
        accessible = user.get("accessibleOrganizations", [])
        if targetOrgId not in accessible:
            raise HTTPException(status_code=403, detail="Not authorized to modify this user")

    elif role == "ORG_HR":
        if targetOrgId != user.get("organizationId"):
            raise HTTPException(status_code=403, detail="Not authorized to modify users in other organizations")

    else:
        raise HTTPException(status_code=403, detail="Not authorized to update users")

    # --- Define Editable Fields Based on Role ---
    editableFields = [
        "userName",
        "phoneNumber",
        "permissions",
        "isActive",
        "password"
    ]

    # Super Admin can also edit role + accessibleOrganizations
    if role == "SUPER_ADMIN":
        editableFields.extend(["role", "organizationId", "accessibleOrganizations"])

    # Super Admin Helper can edit role within allowed orgs, but only assign orgs within his accessible list
    if role == "SUPER_ADMIN_HELPER":
        editableFields.append("role")
        if "organizationId" in body and body["organizationId"] not in user.get("accessibleOrganizations", []):
            raise HTTPException(status_code=403, detail="Cannot assign user to unapproved organization")

    updateData = {k: body[k] for k in editableFields if k in body}
    if not updateData:
        raise HTTPException(status_code=400, detail="No valid fields provided for update")

    updateData["updatedAt"] = datetime.now(timezone.utc).isoformat()

    # --- Update in DB ---
    await usersCol.update_one({"_id": object_id}, {"$set": updateData})
    updatedUser = await usersCol.find_one({"_id": object_id}, {"password": 0})

    # --- Attach Organization Name ---
    org = await orgsCol.find_one({"_id": ObjectId(updatedUser["organizationId"])}, {"organizationName": 1})
    if org:
        updatedUser["organizationName"] = org.get("organizationName")

    updatedUser["_id"] = str(updatedUser["_id"])

    # --- Log Activity ---
    await logActivity(
        user,
        "Updated User",
        f"{user.get('email')} updated user {updatedUser.get('email')} (Role: {updatedUser.get('role')})",
        "Success"
    )

    # --- Response ---
    return JSONResponse(
        status_code=200,
        content=jsonable_encoder({
            "message": "User updated successfully",
            "updatedUser": updatedUser
        })
    )

@app.get("/secure/getOrganizations")
async def getOrganizations(user: dict = Depends(requireAuth)):
    role = user.get("role")
    orgs = []

    # --- Super Admin: get all organizations ---
    if role == "SUPER_ADMIN":
        cursor = orgsCol.find({})
        async for org in cursor:
            org["_id"] = str(org["_id"])
            orgs.append(org)

    # --- Super Admin Helper: get only assigned organizations ---
    elif role == "SUPER_ADMIN_HELPER":
        accessible = user.get("accessibleOrganizations", [])
        if not accessible:
            raise HTTPException(status_code=403, detail="No organizations assigned")
        cursor = orgsCol.find(
            {"_id": {"$in": [ObjectId(o) for o in accessible]}}
        )
        async for org in cursor:
            org["_id"] = str(org["_id"])
            orgs.append(org)

    # --- HR Admin: only their own organization ---
    elif role == "ORG_HR":
        orgId = user.get("organizationId")
        if not orgId:
            raise HTTPException(status_code=400, detail="Organization ID missing for HR Admin")
        org = await orgsCol.find_one({"_id": ObjectId(orgId)})
        if org:
            org["_id"] = str(org["_id"])
            orgs.append(org)

    else:
        raise HTTPException(status_code=403, detail="Not authorized to access organizations")

    await logActivity(
        user,
        "View Organizations",
        f"Fetched {len(orgs)} organizations for role {role}",
        "Success"
    )

    return JSONResponse(
        status_code=200,
        content=jsonable_encoder({
            "totalOrganizations": len(orgs),
            "organizations": orgs
        })
    )

from fastapi import Query
import math

@app.get("/secure/getVerifications")
async def getVerifications(
    candidateId: Optional[str] = Query(None),
    user: dict = Depends(requireAuth)
):
    """
    Fetch verification details and per-candidate progress summary.
    - If candidateId provided: only that candidate
    - Else: all verifications accessible to logged-in user
    Includes progress % and per-candidate completion stats.
    """
    role = user.get("role")
    accessibleOrgs = user.get("accessibleOrganizations", [])
    userOrgId = user.get("organizationId")
    userEmail = user.get("email")

    query = {}

    # 🔍 Filter by specific candidate if provided
    if candidateId:
        query["candidateId"] = candidateId

    # 🧩 Role-based access control
    if role == "SUPER_ADMIN":
        pass

    elif role == "SUPER_ADMIN_HELPER":
        if not accessibleOrgs:
            raise HTTPException(status_code=403, detail="No organizations assigned")
        query["organizationId"] = {"$in": accessibleOrgs}

    elif role == "ORG_HR":
        if not userOrgId:
            raise HTTPException(status_code=400, detail="Organization ID missing")
        query["organizationId"] = userOrgId

    elif role == "HELPER":
        query["initiatedBy"] = userEmail

    else:
        raise HTTPException(status_code=403, detail="Not authorized to view verifications")

    # --------------------------------------------
    # 🧾 Fetch verification records
    # --------------------------------------------
    verifications_cursor = verificationsCol.find(query).sort("initiatedAt", -1)
    verifications = []
    candidateSummaries = {}

    totalCompletedChecks = 0
    totalAssignedChecks = 0

    async for v in verifications_cursor:
        v["_id"] = str(v["_id"])
        v["candidateId"] = str(v["candidateId"])

        # 🧮 Compute stage-wise check stats
        totalChecks = 0
        completedChecks = 0
        failedChecks = 0
        inProgressChecks = 0

        for stage_name, checks in v.get("stages", {}).items():
            for check in checks:
                totalChecks += 1
                status = check.get("status", "NOT_STARTED")
                if status == "COMPLETED":
                    completedChecks += 1
                elif status == "FAILED":
                    failedChecks += 1
                elif status == "IN_PROGRESS":
                    inProgressChecks += 1

        # 🧮 Calculate per-verification completion %
        completionPercentage = (
            math.floor((completedChecks / totalChecks) * 100)
            if totalChecks > 0 else 0
        )

        v["progress"] = {
            "totalChecks": totalChecks,
            "completedChecks": completedChecks,
            "failedChecks": failedChecks,
            "inProgressChecks": inProgressChecks,
            "completionPercentage": completionPercentage
        }

        # Aggregate global stats
        totalCompletedChecks += completedChecks
        totalAssignedChecks += totalChecks
        verifications.append(v)

        # 🧩 Build per-candidate summary
        cId = v["candidateId"]
        candidateSummaries[cId] = {
            "candidateId": cId,
            "candidateName": v.get("candidateName"),
            "organizationName": v.get("organizationName"),
            "overallStatus": v.get("overallStatus"),
            "currentStage": v.get("currentStage"),
            "completionPercentage": completionPercentage,
            "failedChecks": failedChecks,
            "inProgressChecks": inProgressChecks,
            "totalChecks": totalChecks,
            "remarks": v.get("remarks", [])
        }

    # --------------------------------------------
    # 📊 Compute overall stats
    # --------------------------------------------
    overallCompletion = (
        math.floor((totalCompletedChecks / totalAssignedChecks) * 100)
        if totalAssignedChecks > 0 else 0
    )

    # --------------------------------------------
    # 🪵 Log activity
    # --------------------------------------------
    await logActivity(
        user,
        "View Verifications",
        f"{userEmail} viewed {len(verifications)} verifications (avg {overallCompletion}%)",
        "Success"
    )

    # --------------------------------------------
    # ✅ Final Response
    # --------------------------------------------
    return JSONResponse(
        status_code=200,
        content=jsonable_encoder({
            "totalVerifications": len(verifications),
            "overallCompletionPercentage": overallCompletion,
            "candidatesSummary": list(candidateSummaries.values()),
            "verifications": verifications
        })
    )

from fastapi import FastAPI, Body, Depends, HTTPException, Query

# ----------------------------------------------------------
# 📍 Get Candidates by Role / Organization Access Control
# ----------------------------------------------------------
@app.get("/secure/getCandidates")
async def getCandidates(
    orgId: Optional[str] = Query(None),
    user: dict = Depends(requireAuth)
):
    role = user.get("role")
    accessibleOrgs = user.get("accessibleOrganizations", [])
    userOrgId = user.get("organizationId")

    query = {}

    # 🧩 SUPER ADMIN → all candidates or specific org if provided
    if role == "SUPER_ADMIN":
        if orgId:
            query["organizationId"] = orgId
        # else: no filter → get all candidates

    # 🧩 SUPER ADMIN HELPER → only assigned orgs
    elif role == "SUPER_ADMIN_HELPER":
        if orgId:
            if orgId not in accessibleOrgs:
                await logActivity(
                    user,
                    "Unauthorized Attempt",
                    f"Tried accessing candidates of unauthorized org {orgId}",
                    "Error"
                )
                raise HTTPException(status_code=403, detail="You are not authorized for this organization")
            query["organizationId"] = orgId
        else:
            query["organizationId"] = {"$in": accessibleOrgs}

    # 🧩 ORG_HR / HELPER → only their own organization
    elif role in ["ORG_HR", "HELPER"]:
        if not userOrgId:
            raise HTTPException(status_code=400, detail="Organization ID missing in user profile")
        query["organizationId"] = userOrgId

    else:
        raise HTTPException(status_code=403, detail="You are not authorized to view candidates")

    # 🔍 Fetch candidates
    candidates_cursor = candidatesCol.find(query)
    candidates = []
    async for c in candidates_cursor:
        c["_id"] = str(c["_id"])
        candidates.append(c)

    # 🧾 Log the access
    await logActivity(
        user,
        "View Candidates",
        f"{user.get('email')} viewed {len(candidates)} candidates "
        f"{'for org ' + orgId if orgId else '(all accessible orgs)'}",
        "Success"
    )

    # ✅ Response
    return JSONResponse(
        status_code=200,
        content=jsonable_encoder({
            "total": len(candidates),
            "candidates": candidates
        })
    )


# Assuming these exist in your environment
# from your_project.auth import requireAuth
# from your_project.db import candidatesCol, verificationsCol, orgsCol
# from your_project.utils import logActivity

# -------------------------------------------------------------------------
# 🚀 GLOBAL PIPELINE FUNCTION (moved outside so it’s accessible everywhere)
# -------------------------------------------------------------------------
# -------------------------------------------------------------------------
# 🚀 GLOBAL PIPELINE FUNCTION (accessible everywhere)
# -------------------------------------------------------------------------
async def process_verification_pipeline(verification_id, candidate, stages):
    """
    Run all verification checks stage-by-stage (primary -> secondary -> final).
    - Skips checks already COMPLETED
    - Starts from the first stage that has any check not COMPLETED
    - Stops immediately on first FAILURE and marks overallStatus=FAILED
    - If everything passes, marks overallStatus=COMPLETED and candidate=VERIFIED
    """
    try:
        # Normalize verification_id to ObjectId
        verification_oid = verification_id if isinstance(verification_id, ObjectId) else ObjectId(verification_id)

        # Candidate ObjectId
        candidateObjId = None
        if isinstance(candidate.get("_id"), ObjectId):
            candidateObjId = candidate["_id"]
        elif candidate.get("_id"):
            candidateObjId = ObjectId(candidate["_id"])
        elif candidate.get("id"):
            candidateObjId = ObjectId(candidate["id"])

        organizationName = candidate.get("organizationName", "Unknown")

        stage_order = ["primary", "secondary", "final"]

        # Helper: find first stage that has any check not COMPLETED
        def first_incomplete_stage(_stages: dict) -> Optional[str]:
            for stg in stage_order:
                checks = _stages.get(stg, [])
                if any(ch.get("status") != "COMPLETED" for ch in checks):
                    return stg
            return None  # everything done

        # If caller passed a stale "stages", fetch fresh from DB to avoid drift
        ver_doc = await verificationsCol.find_one({"_id": verification_oid})
        if ver_doc and "stages" in ver_doc:
            stages = ver_doc["stages"]

        start_stage = first_incomplete_stage(stages)
        if start_stage is None:
            # Nothing left to do
            await verificationsCol.update_one(
                {"_id": verification_oid},
                {"$set": {"overallStatus": "COMPLETED", "currentStage": "final"}}
            )
            if candidateObjId:
                await candidatesCol.update_one(
                    {"_id": candidateObjId},
                    {"$set": {"status": "VERIFIED"}}
                )
            await logActivity(
                {"email": "system"},
                "Verification Completed",
                f"All stages already passed for {candidate.get('firstName')} ({organizationName})",
                "Success"
            )
            return

        # Walk from the first incomplete stage through to the end
        start_index = stage_order.index(start_stage)
        for stage_name in stage_order[start_index:]:
            checks = stages.get(stage_name, []) or []

            # Mark stage as active
            await verificationsCol.update_one(
                {"_id": verification_oid},
                {"$set": {"currentStage": stage_name}}
            )

            for check in checks:
                check_name = check["check"]
                current_status = (check.get("status") or "NOT_STARTED").upper()

                # ✅ Skip already completed checks
                if current_status == "COMPLETED":
                    continue

                # Mark check as in progress
                await verificationsCol.update_one(
                    {"_id": verification_oid, f"stages.{stage_name}.check": check_name},
                    {"$set": {f"stages.{stage_name}.$.status": "IN_PROGRESS"}}
                )

                # Run verification
                status, remarks = await run_verification(check_name, candidate)

                # Update result
                await verificationsCol.update_one(
                    {"_id": verification_oid, f"stages.{stage_name}.check": check_name},
                    {"$set": {
                        f"stages.{stage_name}.$.status": status,
                        f"stages.{stage_name}.$.remarks": remarks
                    }}
                )

                # Stop immediately if a check fails
                if status == "FAILED":
                    fail_tag = f"{stage_name}_{check_name}"
                    await verificationsCol.update_one(
                        {"_id": verification_oid},
                        {"$set": {
                            "overallStatus": "FAILED",
                            "failureStage": fail_tag,
                            "currentStage": stage_name
                        }}
                    )
                    if candidateObjId:
                        await candidatesCol.update_one(
                            {"_id": candidateObjId},
                            {"$set": {"status": f"FAILED_AT_{fail_tag.upper()}"}}
                        )
                    await logActivity(
                        {"email": "system"},
                        "Verification Failed",
                        f"Verification stopped at {fail_tag} for {candidate.get('firstName')}",
                        "Error"
                    )
                    return  # ❌ stop pipeline here

            # Small delay between stages (simulate queue)
            await asyncio.sleep(2)

        # If reached here, all checks in all stages are COMPLETED
        await verificationsCol.update_one(
            {"_id": verification_oid},
            {"$set": {"overallStatus": "COMPLETED", "currentStage": "final"}}
        )
        if candidateObjId:
            await candidatesCol.update_one(
                {"_id": candidateObjId},
                {"$set": {"status": "VERIFIED"}}
            )
        await logActivity(
            {"email": "system"},
            "Verification Completed",
            f"All stages passed for {candidate.get('firstName')} ({organizationName})",
            "Success"
        )

    except Exception as e:
        # Best-effort failure wrap
        try:
            verification_oid = verification_id if isinstance(verification_id, ObjectId) else ObjectId(verification_id)
            await verificationsCol.update_one(
                {"_id": verification_oid},
                {"$set": {"overallStatus": "FAILED", "error": str(e)}}
            )
        finally:
            pass
        # Candidate set to unknown failure (best-effort)
        try:
            if candidate.get("_id"):
                cid = candidate["_id"] if isinstance(candidate["_id"], ObjectId) else ObjectId(candidate["_id"])
                await candidatesCol.update_one(
                    {"_id": cid},
                    {"$set": {"status": "FAILED_UNKNOWN_ERROR"}}
                )
        finally:
            pass
        await logActivity(
            {"email": "system"},
            "Verification Failed",
            f"Error during verification pipeline: {str(e)}",
            "Error"
        )


# -------------------------------------------------------------------------
# ♻️ Retry only failed checks (auto-resume pipeline if all pass)
# -------------------------------------------------------------------------
async def retry_failed_checks(verification, failed_checks, candidate, user):
    """
    - Retries exactly the failed checks.
    - If any still fail -> overallStatus=FAILED and candidate status updated.
    - If all pass -> overallStatus=IN_PROGRESS and pipeline resumes from the first incomplete stage.
    """
    try:
        verification_oid = verification["_id"] if isinstance(verification["_id"], ObjectId) else ObjectId(verification["_id"])

        # 1) Retry all failed checks
        for stage_name, check_name in failed_checks:
            # Mark as in progress
            await verificationsCol.update_one(
                {"_id": verification_oid, f"stages.{stage_name}.check": check_name},
                {"$set": {f"stages.{stage_name}.$.status": "IN_PROGRESS"}}
            )

            # Run verification again
            status, remarks = await run_verification(check_name, candidate)

            # Update result
            await verificationsCol.update_one(
                {"_id": verification_oid, f"stages.{stage_name}.check": check_name},
                {"$set": {
                    f"stages.{stage_name}.$.status": status,
                    f"stages.{stage_name}.$.remarks": remarks
                }}
            )

        # 2) Fetch latest verification after retries
        updated_verification = await verificationsCol.find_one({"_id": verification_oid})

        # 3) Check if any still failed
        failed_any = any(
            ch.get("status") == "FAILED"
            for stg in ["primary", "secondary", "final"]
            for ch in (updated_verification["stages"].get(stg, []) or [])
        )

        if failed_any:
            # Still some failures
            await verificationsCol.update_one(
                {"_id": verification_oid},
                {"$set": {"overallStatus": "FAILED"}}
            )
            # Best-effort candidate mark
            try:
                cid = updated_verification.get("candidateId")
                if cid:
                    await candidatesCol.update_one(
                        {"_id": ObjectId(cid)},
                        {"$set": {"status": "FAILED_RETRY"}}
                    )
            finally:
                pass
            await logActivity(
                user,
                "Retry Verification",
                f"Reattempted checks failed again for {updated_verification.get('candidateName')}",
                "Error"
            )
            return

        # 4) All failed checks passed -> Resume the pipeline from first incomplete stage
        await verificationsCol.update_one(
            {"_id": verification_oid},
            {"$set": {"overallStatus": "IN_PROGRESS", "failureStage": None}}
        )

        # Fetch fresh candidate (ObjectId-safe)
        fresh_candidate = candidate
        try:
            if not candidate.get("_id") and updated_verification.get("candidateId"):
                fresh_candidate = await candidatesCol.find_one({"_id": ObjectId(updated_verification["candidateId"])})
        except Exception:
            pass

        await logActivity(
            user,
            "Retry Verification Success",
            f"All failed checks fixed for {updated_verification.get('candidateName')}, resuming pipeline...",
            "Success"
        )

        # Resume pipeline with the DB's current stages snapshot
        asyncio.create_task(
            process_verification_pipeline(
                verification_oid,
                fresh_candidate or candidate,
                updated_verification["stages"]
            )
        )

    except Exception as e:
        await logActivity(user, "Retry Verification Error", str(e), "Error")


# -------------------------------------------------------------------------
# 🚦 Initiate Verification (your original function — unchanged)
# -------------------------------------------------------------------------
@app.post("/secure/initiateVerification")
async def initiateVerification(body: dict = Body(...), user: dict = Depends(requireAuth)):
    role = user.get("role")
    candidateId = body.get("candidateId")
    stages = body.get("stages", {})

    if not candidateId:
        raise HTTPException(status_code=400, detail="Candidate ID is required")

    # ✅ Validate Candidate ID
    try:
        candidateObjId = ObjectId(candidateId)
    except InvalidId:
        raise HTTPException(status_code=400, detail="Invalid Candidate ID format")

    # --- Fetch Candidate ---
    candidate = await candidatesCol.find_one({"_id": candidateObjId})
    if not candidate:
        raise HTTPException(status_code=404, detail="Candidate not found")

    # --- Determine Organization Logic Based on Role ---
    organizationId = None
    organizationName = None

    # 🧩 SUPER ADMIN
    if role == "SUPER_ADMIN":
        organizationId = body.get("organizationId") or candidate.get("organizationId")
        if not organizationId:
            raise HTTPException(status_code=400, detail="Organization ID required for Super Admin")
        org = await orgsCol.find_one({"_id": ObjectId(organizationId)})
        if not org:
            raise HTTPException(status_code=404, detail="Organization not found")
        organizationName = org.get("organizationName")

    # 🧩 SUPER ADMIN HELPER
    elif role == "SUPER_ADMIN_HELPER":
        accessible = user.get("accessibleOrganizations", [])
        organizationId = body.get("organizationId") or candidate.get("organizationId")
        if not organizationId:
            raise HTTPException(status_code=400, detail="Organization ID required")
        if organizationId not in accessible:
            await logActivity(
                user,
                "Unauthorized Attempt",
                f"Tried initiating verification for unauthorized org {organizationId}",
                "Error"
            )
            raise HTTPException(status_code=403, detail="Not authorized for this organization")
        org = await orgsCol.find_one({"_id": ObjectId(organizationId)})
        if not org:
            raise HTTPException(status_code=404, detail="Organization not found")
        organizationName = org.get("organizationName")

    # 🧩 ORG HR or HELPER
    elif role in ["ORG_HR", "HELPER"]:
        organizationId = user.get("organizationId")

        # ✅ Ensure candidate belongs to same org
        if candidate.get("organizationId") != organizationId:
            await logActivity(
                user,
                "Unauthorized Attempt",
                f"Tried initiating verification for candidate {candidateId} "
                f"from different org {candidate.get('organizationId')}",
                "Error"
            )
            raise HTTPException(
                status_code=403,
                detail="You cannot initiate verification for candidates outside your organization"
            )

        org = await orgsCol.find_one({"_id": ObjectId(organizationId)})
        if not org:
            raise HTTPException(status_code=404, detail="Organization not found")
        organizationName = org.get("organizationName")

    else:
        raise HTTPException(status_code=403, detail="You are not authorized to initiate verifications")

    # ---------------------------------------------------------------------
    # 🔍 Enhanced check for existing verification (Retry / Completed logic)
    # ---------------------------------------------------------------------
    existing = await verificationsCol.find_one({"candidateId": candidateId, "organizationId": organizationId})
    if existing:
        existing_status = existing.get("overallStatus")
        if existing_status == "COMPLETED":
            return JSONResponse(
                status_code=200,
                content={"message": "Verification already completed successfully"}
            )
        elif existing_status == "IN_PROGRESS":
            return JSONResponse(
                status_code=200,
                content={"message": "Verification already in progress"}
            )
        elif existing_status == "FAILED":
            # re-run only failed checks
            failed_checks = []
            for stage_name, checks in existing["stages"].items():
                for check in checks:
                    if check["status"] == "FAILED":
                        failed_checks.append((stage_name, check["check"]))

            if not failed_checks:
                return JSONResponse(status_code=200, content={"message": "No failed checks to retry"})

            asyncio.create_task(retry_failed_checks(existing, failed_checks, candidate, user))
            return JSONResponse(
                status_code=202,
                content={"message": f"Re-attempting {len(failed_checks)} failed checks"}
            )

    # ✅ Prevent Duplicate Verification (existing unfinished)
    existingVerification = await verificationsCol.find_one({
        "candidateId": candidateId,
        "organizationId": organizationId,
        "overallStatus": {"$in": ["IN_PROGRESS", "PENDING"]}
    })
    if existingVerification:
        raise HTTPException(
            status_code=409,
            detail=f"Verification already exists for this candidate under {organizationName}."
        )

    # --- Helper for Building Checks ---
    def buildChecks(stageList):
        return [{"check": c, "status": "NOT_STARTED", "remarks": None} for c in stageList]

    primaryChecks = buildChecks(stages.get("primary", []))
    secondaryChecks = buildChecks(stages.get("secondary", []))
    finalChecks = buildChecks(stages.get("final", []))

    # --- Verification Document ---
    verificationDoc = {
        "candidateId": candidateId,
        "candidateName": f"{candidate.get('firstName', '')} {candidate.get('lastName', '')}".strip(),
        "organizationId": organizationId,
        "organizationName": organizationName,
        "initiatedBy": user.get("email"),
        "initiatedAt": datetime.now(timezone.utc).isoformat(),
        "stages": {
            "primary": primaryChecks,
            "secondary": secondaryChecks,
            "final": finalChecks
        },
        "currentStage": "primary",
        "overallStatus": "IN_PROGRESS",
        "assignedTo": str(user.get("_id")),
        "remarks": []
    }

    result = await verificationsCol.insert_one(verificationDoc)

    # --- Update Candidate Status ---
    await candidatesCol.update_one(
        {"_id": candidateObjId},
        {"$set": {"status": "IN_PROGRESS"}}
    )

    # --- Log Activity ---
    await logActivity(
        user,
        "Initiated Verification",
        f"{user.get('email')} initiated verification for {candidate.get('firstName')} ({organizationName})",
        "Success"
    )

    # 🔄 Run background task (calls global pipeline)
    asyncio.create_task(process_verification_pipeline(result.inserted_id, candidate, verificationDoc["stages"]))

    # --- Response ---
    return JSONResponse(
        status_code=201,
        content=jsonable_encoder({
            "message": "Verification initiated successfully",
            "verificationId": str(result.inserted_id),
            "candidate": {
                "id": candidateId,
                "name": f"{candidate.get('firstName', '')} {candidate.get('lastName', '')}".strip()
            },
            "organization": {
                "id": organizationId,
                "name": organizationName
            },
            "initiatedBy": user.get("email"),
            "stages": verificationDoc["stages"],
            "status": "IN_PROGRESS"
        })
    )





from apis import process_verification_record  # ✅ import the correct async worker
from bson import ObjectId

@app.post("/secure/resumePendingVerifications")
async def resumePendingVerifications(user: dict = Depends(requireAuth)):
    """Resume all pending or in-progress verifications."""
    if user.get("role") not in ["SUPER_ADMIN", "SUPER_ADMIN_HELPER"]:
        raise HTTPException(status_code=403, detail="Not authorized to resume verifications")

    pending_cursor = verificationsCol.find({"overallStatus": {"$in": ["IN_PROGRESS", "PENDING"]}})
    count = 0

    async for verification in pending_cursor:
        # Ensure candidate exists
        candidate = await candidatesCol.find_one({"_id": ObjectId(verification["candidateId"])})
        if not candidate:
            continue

        # Relaunch background worker
        asyncio.create_task(process_verification_record(verification))
        count += 1

    if count == 0:
        return {"message": "No pending verifications found"}

    return {"message": f"Resumed {count} pending verifications"}


@app.post("/secure/addCandidate")
async def addCandidate(body: dict = Body(...), user: dict = Depends(requireAuth)):
    role = user.get("role")
    creatorEmail = user.get("email")
    accessibleOrgs = user.get("accessibleOrganizations", [])
    orgId = None
    orgName = None

    # --- Extract fields from body ---
    firstName = body.get("firstName")
    middleName = body.get("middleName")
    lastName = body.get("lastName")
    phone = body.get("phone")
    aadhaarNumber = body.get("aadhaarNumber")
    panNumber = body.get("panNumber")
    address = body.get("address")
    inputOrgId = body.get("organizationId")

    # --- Basic validations ---
    if not all([firstName, lastName, phone, aadhaarNumber, panNumber, address]):
        raise HTTPException(status_code=400, detail="Missing required candidate details")

    # --- Access control by role ---

    # 1️⃣ SUPER_ADMIN → can add to any org (must specify orgId)
    if role == "SUPER_ADMIN":
        orgId = inputOrgId or user.get("organizationId")
        if not orgId:
            raise HTTPException(status_code=400, detail="Organization ID required for Super Admin")
        org = await orgsCol.find_one({"_id": ObjectId(orgId)})
        if not org:
            raise HTTPException(status_code=404, detail="Organization not found")
        orgName = org.get("organizationName")

    # 2️⃣ SUPER_ADMIN_HELPER → only assigned orgs
    elif role == "SUPER_ADMIN_HELPER":
        if not inputOrgId:
            raise HTTPException(status_code=400, detail="Organization ID required")
        if inputOrgId not in accessibleOrgs:
            await logActivity(
                user,
                "Unauthorized Attempt",
                f"Tried adding candidate to unauthorized org {inputOrgId}",
                "Error"
            )
            raise HTTPException(status_code=403, detail="You are not authorized for this organization")
        org = await orgsCol.find_one({"_id": ObjectId(inputOrgId)})
        if not org:
            raise HTTPException(status_code=404, detail="Organization not found")
        orgId = inputOrgId
        orgName = org.get("organizationName")

    # 3️⃣ ORG_HR / HELPER → only their own org
    elif role in ["ORG_HR", "HELPER"]:
        # Prevent attempts to override orgId
        if body.get("organizationId") and body.get("organizationId") != user.get("organizationId"):
            await logActivity(
                user,
                "Unauthorized Attempt",
                f"Tried adding candidate to another organization ({body.get('organizationId')})",
                "Error"
            )
            raise HTTPException(status_code=403, detail="You cannot add candidates to other organizations")

        orgId = user.get("organizationId")
        org = await orgsCol.find_one({"_id": ObjectId(orgId)})
        if not org:
            raise HTTPException(status_code=404, detail="Organization not found")
        orgName = org.get("organizationName")

    # 4️⃣ Everyone else — denied
    else:
        raise HTTPException(status_code=403, detail="Not authorized to add candidates")

    # --- Prevent duplicate candidate (same Aadhaar or PAN within same org) ---
    existing = await candidatesCol.find_one({
        "organizationId": orgId,
        "$or": [
            {"aadhaarNumber": aadhaarNumber},
            {"panNumber": panNumber}
        ]
    })
    if existing:
        raise HTTPException(
            status_code=409,
            detail=f"Candidate with Aadhaar/PAN already exists in {orgName}"
        )

    # --- Create candidate document ---
    now = datetime.now(timezone.utc).isoformat()
    candidateDoc = {
        "firstName": firstName,
        "middleName": middleName,
        "lastName": lastName,
        "phone": phone,
        "aadhaarNumber": aadhaarNumber,
        "panNumber": panNumber,
        "address": address,
        "organizationId": orgId,
        "organizationName": orgName,
        "status": "PENDING",
        "createdAt": now,
        "createdBy": creatorEmail
    }

    result = await candidatesCol.insert_one(candidateDoc)
    candidateDoc["_id"] = str(result.inserted_id)

    # --- Log success ---
    await logActivity(
        user,
        "Add Candidate",
        f"{creatorEmail} added candidate {firstName} {lastName} to {orgName}",
        "Success"
    )

    # --- Response ---
    return JSONResponse(
        status_code=201,
        content=jsonable_encoder({
            "message": "Candidate added successfully",
            "candidate": candidateDoc
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
