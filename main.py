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
