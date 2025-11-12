###Header should be included here#####

"i dom't want"
"it ok to be lazy"

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
from utils.email_utils import send_self_verification_link


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
    phone: Optional[str] = None       # ✅ ADD THIS LINE
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

    # Fallback for Postman / mobile clients
    if not token:
        authHeader = request.headers.get("Authorization")
        if authHeader and authHeader.startswith("Bearer "):
            token = authHeader.split("Bearer ")[1].strip()

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
    # --- Authenticate user ---
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

    # --- Build token payload ---
    payload = {
        "email": user["email"],
        "role": user["role"],
        "organizationId": orgId,
        "iat": now,
        "exp": now + cookieMaxAge
    }
    token = encodeToken(payload)

    # --- Set cookie ---
    response.set_cookie(
        key=cookieName,
        value=token,
        httponly=True,
        secure=cookieSecure,
        samesite=cookieSameSite,
        max_age=cookieMaxAge,
        path="/",
    )

    # --- Fetch organization details ---
    orgName = None
    orgServices = []
    if orgId:
        try:
            org = await orgsCol.find_one({"_id": ObjectId(orgId)})
            if org:
                orgName = org.get("organizationName")
                orgServices = org.get("services", [])
        except Exception as e:
            print(f"⚠️ Error fetching org details for {orgId}: {e}")

    # --- Log login activity ---
    await logActivity(user, "User Login", f"{user.get('email')} logged in.", "Success")

    # --- Build response ---
    return {
        "userName": user.get("userName"),
        "email": user.get("email"),
        "role": user.get("role"),
        "organizationId": orgId,
        "organizationName": orgName,
        "phoneNumber": user.get("phoneNumber"),
        "isSuperAdmin": isSuperAdmin,
        "session": "created",
        "token": token,
        "permissions": user.get("permissions", []),
        "services": orgServices
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
# Register Organization (Final Clean Version)
# -------------------------------
@app.post("/secure/registerOrganization")
async def registerOrganization(body: OrganizationRegistration, user: dict = Depends(requireAuth)):
    """
    FUNCTION: registerOrganization
    Input:
        - body: OrganizationRegistration object (no HR admin field)
        - user: Authenticated SUPER_ADMIN
    Output:
        - JSONResponse with organizationId and SPOC credentials
    Purpose:
        Registers a new organization and creates its SPOC user.
    """
    role = user.get("role")
    userOrgId = user.get("organizationId")

    # Fetch the org of the logged-in user
    userOrg = await orgsCol.find_one({"_id": ObjectId(userOrgId)})

    subDomain = (userOrg.get("subDomain", "") if userOrg else "").lower()

    isGlobalSpoc = (role == "SPOC" and subDomain in ["bgv.local", "bgvapp.in", "www.bgvapp.in"])

    if not (role == "SUPER_ADMIN" or isGlobalSpoc):
        raise HTTPException(status_code=403, detail="Only Super Admin or Global SPOC can add organizations")


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
        "phone": body.phone,
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

    DEFAULT_SPOC_PERMISSIONS = [
        "organization:view",
        "organization:update",
        "employee:create",
        "verification:view",
        "verification:assign",
        "dashboard:view",
        "users:manage"
    ]

    spocUser = {
        "userName": body.spocName,
        "email": body.email,
        "password": "Welcome1",
        "role": "SPOC",
        "phoneNumber": body.phone,
        "organizationId": orgId,
        "permissions": DEFAULT_SPOC_PERMISSIONS,
        "isActive": True,
        "createdAt": now,
        "createdBy": user.get("email")
    }

    await usersCol.insert_one(spocUser)
    await logActivity(
        user,
        "Created Organization",
        f"Created org '{body.organizationName}' with SPOC '{body.email}'",
        "Success"
    )

    return JSONResponse(
        status_code=201,
        content=jsonable_encoder({
            "message": "Organization registered successfully",
            "organizationId": orgId,
            "organizationName": body.organizationName,
            "spocEmail": body.email,
            "defaultPassword": "Welcome1",
            "note": "SPOC can now log in and add HR/Admin users if needed."
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

from fastapi import Depends, HTTPException
from fastapi.responses import JSONResponse
from fastapi.encoders import jsonable_encoder
from datetime import datetime, timezone
from bson import ObjectId

# ✅ Permission guard (import or place at the top of your routes file)
def requirePermission(requiredPermissions):
    async def wrapper(user: dict = Depends(requireAuth)):
        role = user.get("role")
        userPermissions = user.get("permissions", [])

        # SUPER_ADMIN and SPOC always bypass permission check
        if role in ["SUPER_ADMIN", "SPOC"]:
            return user

        # ✅ Dynamic permission validation
        if not any(p in userPermissions for p in requiredPermissions):
            raise HTTPException(
                status_code=403,
                detail=f"You don't have any of the required permissions: {', '.join(requiredPermissions)}"
            )

        return user
    return wrapper


# ✅ Updated Dashboard Route
from fastapi import Depends, HTTPException, Query
from fastapi.responses import JSONResponse
from fastapi.encoders import jsonable_encoder
from bson import ObjectId

@app.get("/dashboard")
async def getDashboard(
    organizationId: str = Query(None, description="Optional organizationId filter for authorized roles"),
    user: dict = Depends(requirePermission(["dashboard:view"]))
):
    role = user.get("role")
    orgId = user.get("organizationId")

    # 🧩 Helper for stage breakdown
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

    # ---------------------------------------------------
    # 🔒 STEP 1: Validate requested org access (centralized)
    # ---------------------------------------------------
    def ensure_org_access(organizationId):
        """Ensure the logged-in user has access to the requested organizationId"""
        # SUPER_ADMIN → full access
        if role == "SUPER_ADMIN":
            return True

        # SUPER_ADMIN_HELPER → must be in accessibleOrganizations
        if role == "SUPER_ADMIN_HELPER":
            accessible = user.get("accessibleOrganizations", [])
            if organizationId and organizationId not in accessible:
                raise HTTPException(
                    status_code=403,
                    detail=f"You are not authorized to view org {organizationId}"
                )
            return True

        # SPOC → check if BGV or not
        if role == "SPOC":
            # find org details
            orgRecord = None
            try:
                orgRecord = asyncio.run(orgsCol.find_one({"_id": ObjectId(orgId)}))
            except Exception:
                pass
            orgName = (orgRecord.get("organizationName", "") if orgRecord else "").lower()
            orgEmail = (orgRecord.get("email", "") if orgRecord else "").lower()
            orgSub = (orgRecord.get("subDomain", "") if orgRecord else "").lower()
            globalKeywords = ["bgvapp.in", "bgv.local", "bgvapp.com", "bgv"]

            isBgvSpoc = any(k in orgName for k in globalKeywords) or any(k in orgEmail for k in globalKeywords) or any(k in orgSub for k in globalKeywords)

            # Non-BGV SPOCs only allowed their own org
            if not isBgvSpoc and organizationId and organizationId != orgId:
                raise HTTPException(
                    status_code=403,
                    detail=f"You are not authorized to view dashboard of org {organizationId}"
                )
            return True

        # ORG_HR, HELPER, EMPLOYEE → only their org
        if role in ["ORG_HR", "HELPER", "EMPLOYEE"]:
            if organizationId and organizationId != orgId:
                raise HTTPException(
                    status_code=403,
                    detail=f"You are not authorized to view dashboard of org {organizationId}"
                )
            return True

        # Any other role
        raise HTTPException(status_code=403, detail="Unknown or unauthorized role")

    # validate org access
    if organizationId:
        ensure_org_access(organizationId)

    # ---------------------------------------------------
    # SUPER ADMIN
    # ---------------------------------------------------
    if role == "SUPER_ADMIN":
        orgFilter = {}
        if organizationId:
            orgFilter = {"organizationId": organizationId}

        orgCount = await orgsCol.count_documents({})
        totalRequests = await verificationsCol.count_documents(orgFilter)
        ongoingCount = await verificationsCol.count_documents({**orgFilter, "overallStatus": "IN_PROGRESS"})
        completedCount = await verificationsCol.count_documents({**orgFilter, "overallStatus": "COMPLETED"})
        failedCount = await verificationsCol.count_documents({**orgFilter, "overallStatus": "FAILED"})
        stageStats = await stage_breakdown(orgFilter)

        stats = {
            "filteredByOrganization": organizationId or "ALL",
            "totalOrganizations": orgCount,
            "totalRequests": totalRequests,
            "ongoingVerifications": ongoingCount,
            "completedVerifications": completedCount,
            "failedVerifications": failedCount,
            "stageBreakdown": stageStats
        }
        await logActivity(user, "View Dashboard", "Super Admin viewed dashboard", "Success")
        return JSONResponse(status_code=200, content=jsonable_encoder({
            "role": "SUPER_ADMIN",
            "stats": stats
        }))

    # ---------------------------------------------------
    # SUPER ADMIN HELPER
    # ---------------------------------------------------
    elif role == "SUPER_ADMIN_HELPER":
        accessible = user.get("accessibleOrganizations", [])
        orgQuery = {"organizationId": {"$in": accessible}}
        if organizationId:
            orgQuery = {"organizationId": organizationId}

        totalRequests = await verificationsCol.count_documents(orgQuery)
        ongoingCount = await verificationsCol.count_documents({**orgQuery, "overallStatus": "IN_PROGRESS"})
        completedCount = await verificationsCol.count_documents({**orgQuery, "overallStatus": "COMPLETED"})
        failedCount = await verificationsCol.count_documents({**orgQuery, "overallStatus": "FAILED"})
        stageStats = await stage_breakdown(orgQuery)

        stats = {
            "filteredByOrganization": organizationId or "ALL_ASSIGNED",
            "accessibleOrganizations": len(accessible),
            "totalRequests": totalRequests,
            "ongoingVerifications": ongoingCount,
            "completedVerifications": completedCount,
            "failedVerifications": failedCount,
            "stageBreakdown": stageStats
        }
        await logActivity(user, "View Dashboard", "Super Admin Helper viewed dashboard", "Success")
        return JSONResponse(status_code=200, content=jsonable_encoder({
            "role": "SUPER_ADMIN_HELPER",
            "stats": stats
        }))

    # ---------------------------------------------------
    # SPOC / ORG_HR
    # ---------------------------------------------------
    elif role in ["SPOC", "ORG_HR"]:
        orgQuery = {"organizationId": organizationId or orgId}
        employeeCount = await usersCol.count_documents({
            "organizationId": orgQuery["organizationId"],
            "role": {"$in": ["SPOC", "ORG_HR", "HELPER", "EMPLOYEE"]},
            "isActive": True
        })
        totalRequests = await verificationsCol.count_documents(orgQuery)
        ongoingCount = await verificationsCol.count_documents({**orgQuery, "overallStatus": "IN_PROGRESS"})
        completedCount = await verificationsCol.count_documents({**orgQuery, "overallStatus": "COMPLETED"})
        failedCount = await verificationsCol.count_documents({**orgQuery, "overallStatus": "FAILED"})
        stageStats = await stage_breakdown(orgQuery)

        stats = {
            "filteredByOrganization": orgQuery["organizationId"],
            "totalEmployees": employeeCount,
            "totalRequests": totalRequests,
            "ongoingVerifications": ongoingCount,
            "completedVerifications": completedCount,
            "failedVerifications": failedCount,
            "stageBreakdown": stageStats
        }
        await logActivity(user, "View Dashboard", f"{role} viewed dashboard", "Success")
        return JSONResponse(status_code=200, content=jsonable_encoder({
            "role": role,
            "stats": stats
        }))

    # ---------------------------------------------------
    # HELPER / EMPLOYEE
    # ---------------------------------------------------
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

    # ---------------------------------------------------
    # FALLBACK
    # ---------------------------------------------------
    else:
        raise HTTPException(status_code=403, detail="Unknown role or not authorized")

# -------------------------------
# Update Organization
# -------------------------------
@app.put("/secure/updateOrganization/{orgId}")
async def updateOrganization(orgId: str, body: dict, user: dict = Depends(requireAuth)):
    """
    FUNCTION: updateOrganization
    Input:
        - orgId: Organization ID (str)
        - body: Fields to update (dict)
        - user: Authenticated user (SUPER_ADMIN, SPOC, or ORG_HR)
    Output:
        - JSONResponse containing updated organization data
    Purpose:
        Allows SUPER_ADMIN to update any organization.
        Allows SPOC or ORG_HR to update their own organization.
    """

    role = user.get("role")

    # -------------------------
    # Role-based authorization
    # -------------------------
    if role not in ["SUPER_ADMIN", "SPOC", "ORG_HR"]:
        raise HTTPException(status_code=403, detail="You are not authorized to update organizations")

    try:
        object_id = ObjectId(orgId)
    except Exception:
        await logActivity(user, "Update Organization Failed", f"Invalid organization ID: {orgId}", "Error")
        raise HTTPException(status_code=400, detail="Invalid organization ID")

    org = await orgsCol.find_one({"_id": object_id})
    if not org:
        await logActivity(user, "Update Organization Failed", f"Organization not found: {orgId}", "Error")
        raise HTTPException(status_code=404, detail="Organization not found")

    # -------------------------
    # Access restriction for SPOC / ORG_HR
    # -------------------------
    if role in ["SPOC", "ORG_HR"]:
        if str(org["_id"]) != str(user.get("organizationId")):
            await logActivity(
                user,
                "Update Organization Failed",
                f"Unauthorized attempt by {role} ({user.get('email')}) to modify another organization {orgId}",
                "Error"
            )
            raise HTTPException(status_code=403, detail="You can only update your own organization")

    # -------------------------
    # Define allowed fields
    # -------------------------
    validFields = [
        "organizationName", "spocName", "mainDomain", "subDomain", "email",
        "gstNumber", "services", "logoUrl", "credentials", "isActive", "phone"
    ]

    updateData = {k: body[k] for k in validFields if k in body}
    if not updateData:
        raise HTTPException(status_code=400, detail="No valid fields provided for update")

    updateData["updatedAt"] = datetime.now(timezone.utc).isoformat()

    # -------------------------
    # Perform update
    # -------------------------
    await orgsCol.update_one({"_id": object_id}, {"$set": updateData})
    updatedOrg = await orgsCol.find_one({"_id": object_id})

    # Convert ObjectIds & timestamps for response
    if "_id" in updatedOrg:
        updatedOrg["_id"] = str(updatedOrg["_id"])
    for field in ["createdAt", "updatedAt"]:
        if field in updatedOrg and isinstance(updatedOrg[field], datetime):
            updatedOrg[field] = updatedOrg[field].isoformat()

    # -------------------------
    # Log activity
    # -------------------------
    await logActivity(
        user,
        "Updated Organization",
        f"{role} '{user.get('email')}' updated organization '{updatedOrg.get('organizationName')}'.",
        "Success"
    )

    return JSONResponse(
        status_code=200,
        content={"message": "Organization details updated successfully", "updatedOrganization": updatedOrg}
    )


# -------------------------------
# Add Helper User (for Super Admin or HR)
# -------------------------------
# -------------------------------
# Add Helper User (Full Fixed Version)
# -------------------------------
@app.post("/secure/addHelper")
async def addHelper(body: dict = Body(...), user: dict = Depends(requireAuth)):
    """
    FUNCTION: addHelper
    Input:
        - body: dict with helper details
        - user: authenticated user (SUPER_ADMIN, SUPER_ADMIN_HELPER, SPOC, ORG_HR)
    Output:
        - JSONResponse with helper details and org info
    Purpose:
        Allows authorized users to add new helper or HR users.
        - SUPER_ADMIN → any org
        - SUPER_ADMIN_HELPER → assigned orgs only
        - SPOC → own org (can add both HRs and Helpers)
        - ORG_HR → own org (Helpers only)
        - HELPER → cannot add anyone
    """

    role = user.get("role")

    # 🧩 Step 1: Role validation
    if role not in ["SUPER_ADMIN", "SUPER_ADMIN_HELPER", "SPOC", "ORG_HR"]:
        raise HTTPException(status_code=403, detail="You are not authorized to add helpers")

    # 🧾 Step 2: Extract helper data
    helperName = body.get("userName")
    helperEmail = body.get("email")
    helperRole = body.get("role")
    helperPhone = body.get("phoneNumber")
    helperPermissions = body.get("permissions", [])

    # 🧩 Default permissions by role (auto-assigned if not provided)
    defaultPermissionsMap = {
        "SUPER_ADMIN": [
            "organization:view", "organization:update", "users:manage",
            "verification:view", "verification:assign", "candidate:create", "dashboard:view",  "organization:create",
        ],
        "SUPER_ADMIN_HELPER": [
            "organization:view", "verification:view", "verification:assign", "candidate:create", "organization:create",
        ],
        "SPOC": [
            "organization:view", "organization:update",
            "employee:create", "verification:view", "verification:assign",
            "dashboard:view", "users:manage", "candidate:create"
        ],
        "ORG_HR": [
            "verification:view", "verification:assign",
            "candidate:create", "employee:create"
        ],
        "HELPER": [
            "verification:view", "verification:assign"
        ]
    }

    if not helperPermissions:
        helperPermissions = defaultPermissionsMap.get(helperRole, [])

    helperIsActive = body.get("isActive", True)
    helperPassword = body.get("password") or "Welcome1"
    accessibleOrgs = body.get("accessibleOrganizations", [])
    targetOrgId = body.get("organizationId")

    if not helperName or not helperEmail or not helperRole:
        raise HTTPException(status_code=400, detail="Missing required fields: userName, email, role")

    # 🧠 Step 3: Determine allowed organization (and restrict scope)
    orgId = None

    # SUPER_ADMIN → can add to any org
    if role == "SUPER_ADMIN":
        orgId = targetOrgId or user.get("organizationId")

    # SUPER_ADMIN_HELPER → only within accessible orgs (from user doc)
    elif role == "SUPER_ADMIN_HELPER":
        accessible = [str(x) for x in user.get("accessibleOrganizations", [])]
        if not accessible:
            raise HTTPException(status_code=403, detail="No organizations assigned to this helper")

        if not targetOrgId:
            raise HTTPException(status_code=400, detail="Target organization ID is required")

        if targetOrgId not in accessible:
            raise HTTPException(
                status_code=403,
                detail="You are not authorized to add helpers to this organization"
            )

        # ✅ Fixed: don’t require 'accessibleOrganizations' from request body anymore
        orgId = targetOrgId

    elif role == "SPOC":
        spocOrg = await orgsCol.find_one({"_id": ObjectId(user["organizationId"])})
        if not spocOrg:
            raise HTTPException(status_code=404, detail="SPOC organization not found")

        sub = spocOrg.get("subDomain", "").strip().lower()
        # ✅ Global SPOC = only exact bgvapp.in or base org
        isGlobalSpoc = sub in ["bgvapp.in", "www.bgvapp.in"]

        if not isGlobalSpoc:
            # Org SPOC can *only* add inside same org
            if targetOrgId and targetOrgId != str(user["organizationId"]):
                raise HTTPException(
                    status_code=403,
                    detail="SPOC can only add users to their own organization"
                )
            orgId = str(user["organizationId"])
        else:
            # ✅ Global SPOC (true central admin) — allow cross-org
            orgId = targetOrgId or user.get("organizationId")

    # ORG_HR → can add only helpers to own org
    elif role == "ORG_HR":
        orgId = user.get("organizationId")
        if not orgId:
            raise HTTPException(status_code=400, detail="Organization ID missing for your account")
        if targetOrgId and targetOrgId != orgId:
            raise HTTPException(status_code=403, detail="ORG_HR can only add helpers to their own organization")

    else:
        raise HTTPException(status_code=403, detail="You are not authorized to add helpers")

    # 🧩 Step 4: Validate organization existence
    try:
        org = await orgsCol.find_one({"_id": ObjectId(orgId)})
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid organization ID format")

    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")

    # 🧩 Step 5: Check user limit in org
    totalAllowed = org.get("credentials", {}).get("totalAllowed", 0)
    activeUsersCount = await usersCol.count_documents({"organizationId": orgId, "isActive": True})

    if activeUsersCount >= totalAllowed:
        await logActivity(
            user,
            "Add Helper Failed",
            f"User limit reached ({activeUsersCount}/{totalAllowed}) for org {orgId}",
            "Error"
        )
        raise HTTPException(status_code=409, detail="User limit exceeded. Cannot add more helpers.")

    # 🧩 Step 6: Check for duplicate email
    existingUser = await usersCol.find_one({
        "email": helperEmail,
        "organizationId": orgId
    })
    if existingUser:
        raise HTTPException(status_code=409, detail="A user with this email already exists")

    # 🧩 Step 7: Enforce creation rules by role
    if role == "ORG_HR":
        if helperRole != "HELPER":
            raise HTTPException(status_code=403, detail="ORG_HR can only add helpers, not HR Admins")

    elif role == "SPOC":
        if "bgvapp.in" not in org.get("subDomain", "") and helperRole not in ["HELPER", "ORG_HR"]:
            raise HTTPException(status_code=403, detail="SPOC can only add HR Admins or Helpers to their own org")

    elif role == "SUPER_ADMIN_HELPER":
        if helperRole not in ["HELPER", "ORG_HR"]:
            raise HTTPException(status_code=403, detail="SUPER_ADMIN_HELPER can only add Helpers or Org HRs")

    # 🧩 Step 8: Create helper user document
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
        "createdBy": user.get("email")
    }

    # ✅ Add accessibleOrganizations only if new user is SUPER_ADMIN_HELPER
    if helperRole == "SUPER_ADMIN_HELPER" and body.get("accessibleOrganizations"):
        helperDoc["accessibleOrganizations"] = body.get("accessibleOrganizations")

    insertResult = await usersCol.insert_one(helperDoc)
    helperId = str(insertResult.inserted_id)

    # 🔄 Step 9: Update used credentials count
    newActiveUsersCount = await usersCol.count_documents({"organizationId": orgId, "isActive": True})
    await orgsCol.update_one(
        {"_id": ObjectId(orgId)},
        {"$set": {"credentials.used": newActiveUsersCount}}
    )

    # 🪵 Step 10: Log activity
    await logActivity(
        user,
        "Added Helper User",
        f"{user.get('email')} ({role}) added helper {helperEmail} (role: {helperRole}) "
        f"under org {org.get('organizationName')}",
        "Success"
    )

    # ✅ Step 11: Construct response
    helperResponse = {
        "userId": helperId,
        "userName": helperName,
        "email": helperEmail,
        "role": helperRole,
        "phoneNumber": helperPhone,
        "permissions": helperPermissions,
        "isActive": helperIsActive,
        "defaultPassword": helperPassword
    }

    if helperRole == "SUPER_ADMIN_HELPER" and body.get("accessibleOrganizations"):
        helperResponse["accessibleOrganizations"] = body.get("accessibleOrganizations")

    response_data = {
        "message": "Helper user added successfully",
        "organization": {
            "organizationId": str(org["_id"]),
            "organizationName": org.get("organizationName")
        },
        "helper": helperResponse,
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

@app.middleware("http")
async def debug_auth(request: Request, call_next):
    print("\n--- DEBUG AUTH ---")
    print("PATH:", request.url.path)
    print("COOKIES:", request.cookies)
    print("AUTH HEADER:", request.headers.get("Authorization"))
    response = await call_next(request)
    return response

from fastapi import Request, Query

@app.get("/secure/getUsers")
async def getUsers(request: Request, organizationId: Optional[str] = Query(None), user: dict = Depends(requireAuth)):
    """
    FUNCTION: getUsers
    Input:
        - request: FastAPI Request (unused except for future extension)
        - organizationId: optional query param to filter users by org
        - user: logged-in user (from requireAuth)
    Output:
        - JSONResponse with list of users visible to the caller

    Rules (based on role hierarchy):
        - SUPER_ADMIN → all users across all orgs
        - BGV SPOC (global SPOC) → same as SUPER_ADMIN (full access)
        - ORG_SPOC → only own org
        - SUPER_ADMIN_HELPER → only users from accessibleOrganizations (or filter by org within that list)
        - ORG_HR → only own org
        - HELPER / EMPLOYEE → forbidden
    """
    role = user.get("role")
    callerOrgId = user.get("organizationId")
    accessibleOrgs = user.get("accessibleOrganizations", []) or []

    # -------------------------------
    # Helper function to attach orgName and sanitize data
    # -------------------------------
    async def enrich_user(u: dict):
        u["_id"] = str(u["_id"])
        orgIdForUser = u.get("organizationId")
        orgName = None
        if orgIdForUser:
            try:
                orgDoc = await orgsCol.find_one({"_id": ObjectId(orgIdForUser)}, {"organizationName": 1})
                if orgDoc:
                    orgName = orgDoc.get("organizationName")
            except Exception:
                orgName = None
        u["organizationName"] = orgName
        # remove password before returning
        u.pop("password", None)
        return u

    # -------------------------------
    # Determine access scope
    # -------------------------------
    allowedOrgIds = None  # None means unrestricted access (all orgs)
    isGlobalSpoc = False  # computed later for SPOC

    # 1️⃣ SUPER ADMIN → unrestricted
    if role == "SUPER_ADMIN":
        allowedOrgIds = None

    # 2️⃣ SPOC → could be global (BGV SPOC) or org-level SPOC
    elif role == "SPOC":
        # fetch org info to identify global vs normal spoc
        spocOrg = await orgsCol.find_one({"_id": ObjectId(callerOrgId)}) if callerOrgId else None
        orgEmail = (spocOrg.get("email", "") if spocOrg else "").lower()
        orgSub = (spocOrg.get("subDomain", "") if spocOrg else "").lower()

        globalKeywords = ["bgvapp.in", "bgv.local", "bgvapp.com"]
        isGlobalSpoc = any(x in orgEmail for x in globalKeywords) or any(x in orgSub for x in globalKeywords)

        if isGlobalSpoc:
            allowedOrgIds = None  # full access, same as SUPER_ADMIN
        else:
            if not callerOrgId:
                raise HTTPException(status_code=400, detail="Organization ID missing in user profile")
            allowedOrgIds = [str(callerOrgId)]

    # 3️⃣ SUPER_ADMIN_HELPER → restricted to assigned orgs
    elif role == "SUPER_ADMIN_HELPER":
        if not accessibleOrgs:
            raise HTTPException(status_code=403, detail="No organizations assigned to this helper")
        allowedOrgIds = [str(x) for x in accessibleOrgs]

    # 4️⃣ ORG_HR → restricted to own org
    elif role == "ORG_HR":
        if not callerOrgId:
            raise HTTPException(status_code=400, detail="Organization ID missing in user profile")
        allowedOrgIds = [str(callerOrgId)]

    # 5️⃣ HELPER / EMPLOYEE → forbidden
    elif role in ["HELPER", "EMPLOYEE"]:
        raise HTTPException(status_code=403, detail="You are not authorized to access users list")

    # 6️⃣ Unknown → forbidden
    else:
        raise HTTPException(status_code=403, detail="Unknown role or not authorized")

    # -------------------------------
    # Optional orgId filter from query param
    # -------------------------------
    if organizationId:
        try:
            _ = ObjectId(organizationId)
        except Exception:
            raise HTTPException(status_code=400, detail="Invalid organizationId filter")

        # if restricted roles, check the orgId is within allowed
        if allowedOrgIds is not None and str(organizationId) not in allowedOrgIds:
            raise HTTPException(status_code=403, detail="You cannot access users for this organization")

        # limit to that org
        query = {"organizationId": organizationId}

    else:
        # no explicit filter provided
        if allowedOrgIds is None:
            query = {}  # unrestricted
        else:
            query = {"organizationId": {"$in": allowedOrgIds}}

    # -------------------------------
    # Fetch users and enrich with org names
    # -------------------------------
    cursor = usersCol.find(query, {"password": 0})
    results = []
    async for u in cursor:
        results.append(await enrich_user(u))

    # sort alphabetically by organization name
    results.sort(key=lambda x: x.get("organizationName") or "")

    await logActivity(
        user,
        "View Users",
        f"Fetched {len(results)} users for role {role}",
        "Success"
    )

    # -------------------------------
    # Response
    # -------------------------------
    return JSONResponse(
        status_code=200,
        content=jsonable_encoder({
            "role": role,
            "isGlobalSpoc": isGlobalSpoc,
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

    elif role == "SPOC":
        # SPOC can only modify users from their own organization
        if targetOrgId != user.get("organizationId"):
            raise HTTPException(status_code=403, detail="Not authorized to modify users in other organizations")

        # Must also have users:manage permission
        if "users:manage" not in user.get("permissions", []):
            raise HTTPException(status_code=403, detail="You don't have permission to manage users")

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

from fastapi import HTTPException, Query
from bson import ObjectId
from fastapi.responses import JSONResponse
from fastapi.encoders import jsonable_encoder
from datetime import datetime, timezone

@app.get("/secure/getOrganizations")
async def getOrganizations(
    organizationId: Optional[str] = Query(None),
    user: dict = Depends(requireAuth)
):
    """
    FUNCTION: getOrganizations
    Input:
        - organizationId (optional): query param to fetch a single org
        - user: Authenticated user
    Output:
        - JSONResponse with list of organizations visible to the user
    Permissions:
        - SUPER_ADMIN → all orgs or specific org if ID passed
        - Global SPOC (bgvapp.in) → all orgs or specific org if ID passed
        - Org SPOC → only own org
        - SUPER_ADMIN_HELPER → only assigned orgs
        - ORG_HR → only own org
        - HELPER / EMPLOYEE → forbidden
    """
    role = user.get("role")
    orgs = []
    query = {}

    # --- SUPER ADMIN: All orgs or specific org ---
    if role == "SUPER_ADMIN":
        if organizationId:
            try:
                query = {"_id": ObjectId(organizationId)}
            except Exception:
                raise HTTPException(status_code=400, detail="Invalid organizationId format")
        else:
            query = {}

    # --- SPOC ---
    elif role == "SPOC":
        # Identify SPOC organization
        spocOrgId = user.get("organizationId")
        if not spocOrgId:
            raise HTTPException(status_code=400, detail="Organization ID missing for SPOC")

        spocOrg = await orgsCol.find_one({"_id": ObjectId(spocOrgId)})
        if not spocOrg:
            raise HTTPException(status_code=404, detail="SPOC's organization not found")

        subDomain = spocOrg.get("subDomain", "").lower()
        email = spocOrg.get("email", "").lower()
        isGlobalSpoc = any(x in subDomain for x in ["bgvapp.in", "bgv.local", "bgvapp.com"]) or any(
            x in email for x in ["bgvapp.in", "bgv.local", "bgvapp.com"]
        )

        if isGlobalSpoc:
            # ✅ Global SPOC: all orgs or filter by ID
            if organizationId:
                try:
                    query = {"_id": ObjectId(organizationId)}
                except Exception:
                    raise HTTPException(status_code=400, detail="Invalid organizationId format")
            else:
                query = {}
        else:
            # ❗ Org-level SPOC: only own org
            if organizationId and organizationId != spocOrgId:
                raise HTTPException(status_code=403, detail="You can only access your own organization")
            query = {"_id": ObjectId(spocOrgId)}

    # --- SUPER ADMIN HELPER: Assigned orgs only ---
    elif role == "SUPER_ADMIN_HELPER":
        accessible = user.get("accessibleOrganizations", [])
        if not accessible:
            raise HTTPException(status_code=403, detail="No organizations assigned")

        if organizationId:
            if organizationId not in accessible:
                raise HTTPException(status_code=403, detail="You cannot access this organization")
            query = {"_id": ObjectId(organizationId)}
        else:
            query = {"_id": {"$in": [ObjectId(o) for o in accessible]}}

    # --- ORG_HR: Only own org ---
    elif role == "ORG_HR":
        orgId = user.get("organizationId")
        if not orgId:
            raise HTTPException(status_code=400, detail="Organization ID missing for HR Admin")
        if organizationId and organizationId != orgId:
            raise HTTPException(status_code=403, detail="You can only access your own organization")
        query = {"_id": ObjectId(orgId)}

    # --- HELPER / EMPLOYEE ---
    elif role in ["HELPER", "EMPLOYEE"]:
        raise HTTPException(status_code=403, detail="You are not authorized to access organizations")

    else:
        raise HTTPException(status_code=403, detail="Unknown role or not authorized")

    # --- Fetch Organizations ---
    cursor = orgsCol.find(query)
    async for org in cursor:
        org["_id"] = str(org["_id"])
        orgs.append(org)

    # --- Log Activity ---
    await logActivity(
        user,
        "View Organizations",
        f"Fetched {len(orgs)} organizations for role {role}",
        "Success"
    )

    # --- Response ---
    return JSONResponse(
        status_code=200,
        content=jsonable_encoder({
            "totalOrganizations": len(orgs),
            "organizations": orgs
        })
    )

from fastapi import Query
import math

from fastapi import Query, HTTPException
from fastapi.responses import JSONResponse
from fastapi.encoders import jsonable_encoder
import math
from datetime import datetime, timezone
from bson import ObjectId

@app.get("/secure/getVerifications")
async def getVerifications(
    candidateId: Optional[str] = Query(None),
    user: dict = Depends(requireAuth)
):
    """
    Fetch verification details and per-candidate progress summary.
    Permissions:
    - SUPER_ADMIN: all verifications
    - GLOBAL_SPOC (bgvapp.in/bgvl): all verifications
    - SUPER_ADMIN_HELPER: only assigned organizations
    - ORG_SPOC / ORG_HR: only their own organization
    - HELPER: only those initiated by themselves
    - EMPLOYEE / CANDIDATE: forbidden
    """
    role = user.get("role")
    userEmail = user.get("email")
    userOrgId = user.get("organizationId")
    accessibleOrgs = user.get("accessibleOrganizations", []) or []
    query = {}

    # 🎯 Filter by candidateId if provided
    if candidateId:
        query["candidateId"] = candidateId

    # 🧩 Role-based Access Control
    if role == "SUPER_ADMIN":
        pass  # full access

    elif role == "SPOC":
        # Determine if Global SPOC (bgvapp.in or bgv.local)
        spocOrg = await orgsCol.find_one({"_id": ObjectId(userOrgId)})
        subDomain = spocOrg.get("subDomain", "").lower() if spocOrg else ""
        email = spocOrg.get("email", "").lower() if spocOrg else ""

        isGlobalSpoc = any(x in subDomain for x in ["bgvapp.in", "bgv.local", "bgvapp.com"]) or \
                       any(x in email for x in ["bgvapp.in", "bgv.local", "bgvapp.com"])

        if isGlobalSpoc:
            pass  # full access
        else:
            if not userOrgId:
                raise HTTPException(status_code=400, detail="Organization ID missing")
            query["organizationId"] = userOrgId

    elif role == "SUPER_ADMIN_HELPER":
        if not accessibleOrgs:
            raise HTTPException(status_code=403, detail="No organizations assigned")
        query["organizationId"] = {"$in": accessibleOrgs}

    elif role in ["ORG_SPOC", "ORG_HR"]:
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

        totalChecks = completedChecks = failedChecks = inProgressChecks = 0

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

        totalCompletedChecks += completedChecks
        totalAssignedChecks += totalChecks
        verifications.append(v)

        candidateSummaries[v["candidateId"]] = {
            "candidateId": v["candidateId"],
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

    # 🪵 Log Activity
    await logActivity(
        user,
        "View Verifications",
        f"{userEmail} viewed {len(verifications)} verifications (avg {overallCompletion}%)",
        "Success"
    )

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
    """
    FINAL LOCKED VERSION — ID, ROLE, and EMAIL based only.
    ------------------------------------------------------
    Rules:
      - SUPER_ADMIN and BGV SPOC (email ends with @bgv.local) → access ALL candidates
      - SUPER_ADMIN_HELPER → candidates from orgs in accessibleOrganizations
      - ORG_SPOC or ORG_HR → candidates only from their own org (organizationId)
      - HELPER → only candidates created by them (createdBy = their email)
    """

    role = user.get("role")
    userEmail = user.get("email", "").lower().strip()
    userOrgId = str(user.get("organizationId"))
    accessibleOrgs = [str(x) for x in user.get("accessibleOrganizations", [])]
    query = {}

    # 🔹 SUPER_ADMIN → access all
    if role == "SUPER_ADMIN":
        if orgId:
            query["organizationId"] = orgId

    # 🔹 BGV SPOC → access all (check email or org ID)
    elif role == "SPOC" and ("@bgv.local" in userEmail or "bgvapp.in" in userEmail):
        if orgId:
            query["organizationId"] = orgId
        # else all orgs

    # 🔹 SUPER_ADMIN_HELPER → access only assigned orgs
    elif role == "SUPER_ADMIN_HELPER":
        if not accessibleOrgs:
            raise HTTPException(status_code=403, detail="No organizations assigned to this helper")

        if orgId:
            if orgId not in accessibleOrgs:
                raise HTTPException(status_code=403, detail="You are not authorized for this organization")
            query["organizationId"] = orgId
        else:
            query["organizationId"] = {"$in": accessibleOrgs}

    # 🔹 ORG_SPOC or ORG_HR → only their org
    elif role in ["SPOC", "ORG_HR"]:
        if not userOrgId:
            raise HTTPException(status_code=400, detail="Organization ID missing in profile")
        query["organizationId"] = userOrgId

    # 🔹 HELPER → only candidates they created
    elif role == "HELPER":
        query["createdBy"] = userEmail

    # 🔹 Everyone else → forbidden
    else:
        raise HTTPException(status_code=403, detail="You are not authorized to view candidates")

    # --------------------------------
    # Fetch filtered candidates
    # --------------------------------
    candidates_cursor = candidatesCol.find(query)
    candidates = []
    async for c in candidates_cursor:
        c["_id"] = str(c["_id"])
        candidates.append(c)

    # --------------------------------
    # Log and return
    # --------------------------------
    await logActivity(
        user,
        "View Candidates",
        f"{userEmail} ({role}) viewed {len(candidates)} candidates with filter {query}",
        "Success"
    )

    return JSONResponse(
        status_code=200,
        content=jsonable_encoder({
            "total": len(candidates),
            "filterUsed": query,
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
async def process_verification_pipeline(verification_id, candidate, stages):
    """
    System-driven verification pipeline (role-agnostic).
    Runs all verification checks sequentially (Primary → Secondary → Final).
    """
    try:
        verification_oid = verification_id if isinstance(verification_id, ObjectId) else ObjectId(verification_id)

        candidateObjId = None
        if isinstance(candidate.get("_id"), ObjectId):
            candidateObjId = candidate["_id"]
        elif candidate.get("_id"):
            candidateObjId = ObjectId(candidate["_id"])
        elif candidate.get("id"):
            candidateObjId = ObjectId(candidate["id"])

        organizationName = candidate.get("organizationName", "Unknown")
        organizationId = str(candidate.get("organizationId", ""))

        stage_order = ["primary", "secondary", "final"]

        def first_incomplete_stage(_stages: dict) -> Optional[str]:
            for stg in stage_order:
                checks = _stages.get(stg, [])
                if any(ch.get("status") != "COMPLETED" for ch in checks):
                    return stg
            return None

        # Fetch latest from DB
        ver_doc = await verificationsCol.find_one({"_id": verification_oid})
        if ver_doc and "stages" in ver_doc:
            stages = ver_doc["stages"]

        start_stage = first_incomplete_stage(stages)
        if start_stage is None:
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

        # Run from first incomplete stage onward
        start_index = stage_order.index(start_stage)
        for stage_name in stage_order[start_index:]:
            checks = stages.get(stage_name, []) or []

            await verificationsCol.update_one(
                {"_id": verification_oid},
                {"$set": {"currentStage": stage_name}}
            )

            for check in checks:
                check_name = check["check"]
                current_status = (check.get("status") or "NOT_STARTED").upper()
                if current_status == "COMPLETED":
                    continue

                await verificationsCol.update_one(
                    {"_id": verification_oid, f"stages.{stage_name}.check": check_name},
                    {"$set": {f"stages.{stage_name}.$.status": "IN_PROGRESS"}}
                )

                # Safe verification runner
                try:
                    status, remarks = await run_verification(check_name, candidate)
                except Exception as e:
                    status, remarks = "FAILED", f"Runtime error in {check_name}: {str(e)}"

                await verificationsCol.update_one(
                    {"_id": verification_oid, f"stages.{stage_name}.check": check_name},
                    {"$set": {
                        f"stages.{stage_name}.$.status": status,
                        f"stages.{stage_name}.$.remarks": remarks
                    }}
                )

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
                        f"Verification stopped at {fail_tag} for {candidate.get('firstName')} ({organizationName}) [{organizationId}]",
                        "Error"
                    )
                    return

            await asyncio.sleep(2)

        # Everything passed
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
            f"All stages passed for {candidate.get('firstName')} ({organizationName}) [{organizationId}]",
            "Success"
        )

    except Exception as e:
        try:
            verification_oid = verification_id if isinstance(verification_id, ObjectId) else ObjectId(verification_id)
            await verificationsCol.update_one(
                {"_id": verification_oid},
                {"$set": {"overallStatus": "FAILED", "error": str(e)}}
            )
        except Exception:
            pass

        try:
            if candidate.get("_id"):
                cid = candidate["_id"] if isinstance(candidate["_id"], ObjectId) else ObjectId(candidate["_id"])
                await candidatesCol.update_one(
                    {"_id": cid},
                    {"$set": {"status": "FAILED_UNKNOWN_ERROR"}}
                )
        except Exception:
            pass

        await logActivity(
            {"email": "system"},
            "Verification Failed",
            f"Error during verification pipeline: {str(e)} [{organizationName}]",
            "Error"
        )

# -------------------------------------------------------------------------
# ♻️ Retry only failed checks (auto-resume pipeline if all pass)
# -------------------------------------------------------------------------
async def retry_failed_checks(verification, failed_checks, candidate, user):
    """
    Retries failed checks with strict role and org-level access control.
    ---------------------------------------------------------------
    Rules:
      - SUPER_ADMIN / BGV SPOC → can retry any verification
      - SUPER_ADMIN_HELPER → only in accessibleOrganizations
      - ORG_SPOC / ORG_HR → only their own organization
      - HELPER → only their own initiated verifications
    """
    try:
        role = user.get("role")
        userEmail = user.get("email", "").lower().strip()
        userOrgId = str(user.get("organizationId"))
        accessibleOrgs = [str(x) for x in user.get("accessibleOrganizations", [])]

        verification_oid = verification["_id"] if isinstance(verification["_id"], ObjectId) else ObjectId(verification["_id"])
        verificationOrgId = str(verification.get("organizationId", ""))  # ensure string form
        initiatedBy = verification.get("initiatedBy", "").lower().strip()

        # --------------------------------------------
        # 🔒 Role-based access validation
        # --------------------------------------------
        if role == "SUPER_ADMIN":
            pass  # full access

        elif role == "SPOC" and ("@bgv.local" in userEmail or "bgvapp.in" in userEmail):
            pass  # BGV global SPOC, full access

        elif role == "SUPER_ADMIN_HELPER":
            if verificationOrgId not in accessibleOrgs:
                raise HTTPException(status_code=403, detail="Not authorized for this organization")

        elif role in ["ORG_SPOC", "ORG_HR"]:
            if verificationOrgId != userOrgId:
                raise HTTPException(status_code=403, detail="You can only retry verifications in your organization")

        elif role == "HELPER":
            if initiatedBy != userEmail:
                raise HTTPException(status_code=403, detail="You can only retry your own verifications")

        else:
            raise HTTPException(status_code=403, detail="You are not authorized to retry verifications")

        # --------------------------------------------
        # ✅ Retry each failed check
        # --------------------------------------------
        for stage_name, check_name in failed_checks:
            await verificationsCol.update_one(
                {"_id": verification_oid, f"stages.{stage_name}.check": check_name},
                {"$set": {f"stages.{stage_name}.$.status": "IN_PROGRESS"}}
            )

            try:
                status, remarks = await run_verification(check_name, candidate)
            except Exception as e:
                status, remarks = "FAILED", f"Runtime error in {check_name}: {str(e)}"

            await verificationsCol.update_one(
                {"_id": verification_oid, f"stages.{stage_name}.check": check_name},
                {"$set": {
                    f"stages.{stage_name}.$.status": status,
                    f"stages.{stage_name}.$.remarks": remarks
                }}
            )

        # --------------------------------------------
        # 🔍 Evaluate results after retries
        # --------------------------------------------
        updated_verification = await verificationsCol.find_one({"_id": verification_oid})

        failed_any = any(
            ch.get("status") == "FAILED"
            for stg in ["primary", "secondary", "final"]
            for ch in (updated_verification["stages"].get(stg, []) or [])
        )

        # --------------------------------------------
        # ❌ If still failed
        # --------------------------------------------
        if failed_any:
            await verificationsCol.update_one(
                {"_id": verification_oid},
                {"$set": {"overallStatus": "FAILED"}}
            )
            cid = updated_verification.get("candidateId")
            if cid:
                await candidatesCol.update_one(
                    {"_id": ObjectId(cid)},
                    {"$set": {"status": "FAILED_RETRY"}}
                )
            await logActivity(
                user,
                "Retry Verification Failed",
                f"Reattempted checks failed again for {updated_verification.get('candidateName')}",
                "Error"
            )
            return

        # --------------------------------------------
        # ✅ All checks passed — resume verification
        # --------------------------------------------
        await verificationsCol.update_one(
            {"_id": verification_oid},
            {"$set": {"overallStatus": "IN_PROGRESS", "failureStage": None}}
        )

        fresh_candidate = candidate
        if not candidate.get("_id") and updated_verification.get("candidateId"):
            try:
                fresh_candidate = await candidatesCol.find_one({"_id": ObjectId(updated_verification["candidateId"])})
            except Exception:
                pass

        await logActivity(
            user,
            "Retry Verification Success",
            f"All failed checks fixed for {updated_verification.get('candidateName')}, resuming pipeline...",
            "Success"
        )

        asyncio.create_task(
            process_verification_pipeline(
                verification_oid,
                fresh_candidate or candidate,
                updated_verification["stages"]
            )
        )

    except HTTPException:
        raise
    except Exception as e:
        await logActivity(user, "Retry Verification Error", str(e), "Error")
        raise HTTPException(status_code=500, detail=f"Error retrying verifications: {str(e)}")


# -------------------------------------------------------------------------
# 🚦 Initiate Verification (your original function — unchanged)
# -------------------------------------------------------------------------
@app.post("/secure/initiateVerification")
async def initiateVerification(body: dict = Body(...), user: dict = Depends(requireAuth)):
    """
    Initiate a new candidate verification.
    Rules:
      - SUPER_ADMIN / BGV SPOC: can initiate for any org/candidate.
      - SUPER_ADMIN_HELPER: only for orgs inside accessibleOrganizations.
      - ORG_SPOC / ORG_HR: only for candidates within their own organization.
      - HELPER: only for candidates they created (createdBy == user.email).
    """
    role = user.get("role")
    userEmail = user.get("email", "").lower().strip()
    userOrgId = str(user.get("organizationId"))
    accessibleOrgs = [str(x) for x in user.get("accessibleOrganizations", [])]

    candidateId = body.get("candidateId")
    stages = body.get("stages", {})

    if not candidateId:
        raise HTTPException(status_code=400, detail="Candidate ID is required")

    try:
        candidateObjId = ObjectId(candidateId)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid Candidate ID format")

    # Fetch Candidate
    candidate = await candidatesCol.find_one({"_id": candidateObjId})
    if not candidate:
        raise HTTPException(status_code=404, detail="Candidate not found")

    candidateOrgId = str(candidate.get("organizationId"))
    candidateCreatedBy = candidate.get("createdBy", "").lower().strip()

    organizationId = None
    organizationName = None

    # ------------------------------------------------------
    # 🧩 Role-specific Authorization
    # ------------------------------------------------------

    # 1️⃣ SUPER_ADMIN → any org/candidate
    if role == "SUPER_ADMIN":
        organizationId = body.get("organizationId") or candidateOrgId
        if not organizationId:
            raise HTTPException(status_code=400, detail="Organization ID required for Super Admin")
        org = await orgsCol.find_one({"_id": ObjectId(organizationId)})
        if not org:
            raise HTTPException(status_code=404, detail="Organization not found")
        organizationName = org.get("organizationName")

    # 2️⃣ BGV SPOC (global spoc) → any org
    elif role == "SPOC" and ("@bgv.local" in userEmail or "bgvapp.in" in userEmail):
        organizationId = body.get("organizationId") or candidateOrgId
        if not organizationId:
            raise HTTPException(status_code=400, detail="Organization ID required for BGV SPOC")
        org = await orgsCol.find_one({"_id": ObjectId(organizationId)})
        if not org:
            raise HTTPException(status_code=404, detail="Organization not found")
        organizationName = org.get("organizationName")

    # 3️⃣ SUPER_ADMIN_HELPER → restricted by accessible orgs
    elif role == "SUPER_ADMIN_HELPER":
        organizationId = body.get("organizationId") or candidateOrgId
        if not organizationId:
            raise HTTPException(status_code=400, detail="Organization ID required")
        if organizationId not in accessibleOrgs:
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

    # 4️⃣ ORG_SPOC / ORG_HR → only own org candidates
    elif role in ["SPOC", "ORG_HR"]:
        organizationId = userOrgId
        if candidateOrgId != userOrgId:
            await logActivity(
                user,
                "Unauthorized Attempt",
                f"Tried initiating verification for candidate {candidateId} from different org {candidateOrgId}",
                "Error"
            )
            raise HTTPException(
                status_code=403,
                detail="You can only initiate verification for candidates within your organization"
            )
        org = await orgsCol.find_one({"_id": ObjectId(organizationId)})
        if not org:
            raise HTTPException(status_code=404, detail="Organization not found")
        organizationName = org.get("organizationName")

    # 5️⃣ HELPER → only candidates they created
    elif role == "HELPER":
        organizationId = userOrgId
        if candidateOrgId != userOrgId:
            raise HTTPException(status_code=403, detail="Candidate belongs to a different organization")
        if candidateCreatedBy != userEmail:
            raise HTTPException(status_code=403, detail="You can only initiate verifications for candidates you created")
        org = await orgsCol.find_one({"_id": ObjectId(organizationId)})
        if not org:
            raise HTTPException(status_code=404, detail="Organization not found")
        organizationName = org.get("organizationName")

    # 6️⃣ Others → denied
    else:
        raise HTTPException(status_code=403, detail="You are not authorized to initiate verifications")

    # ------------------------------------------------------
    # 🧩 Existing Verification Handling
    # ------------------------------------------------------
    existing = await verificationsCol.find_one({"candidateId": candidateId, "organizationId": organizationId})
    if existing:
        existing_status = existing.get("overallStatus")
        if existing_status == "COMPLETED":
            return JSONResponse(status_code=200, content={"message": "Verification already completed"})
        elif existing_status == "IN_PROGRESS":
            return JSONResponse(status_code=200, content={"message": "Verification already in progress"})
        elif existing_status == "FAILED":
            failed_checks = [
                (stg, chk["check"])
                for stg, chks in existing.get("stages", {}).items()
                for chk in chks if chk.get("status") == "FAILED"
            ]
            if not failed_checks:
                return JSONResponse(status_code=200, content={"message": "No failed checks to retry"})

            asyncio.create_task(retry_failed_checks(existing, failed_checks, candidate, user))
            return JSONResponse(status_code=202, content={"message": f"Retrying {len(failed_checks)} failed checks"})

    # ------------------------------------------------------
    # 🧩 Prevent Duplicate Pending Verification
    # ------------------------------------------------------
    ongoing = await verificationsCol.find_one({
        "candidateId": candidateId,
        "organizationId": organizationId,
        "overallStatus": {"$in": ["IN_PROGRESS", "PENDING"]}
    })
    if ongoing:
        raise HTTPException(
            status_code=409,
            detail=f"Verification already exists for this candidate under {organizationName}"
        )

    # ------------------------------------------------------
    # 🏗️ Build Stages
    # ------------------------------------------------------
    def buildChecks(stageList):
        return [{"check": c, "status": "NOT_STARTED", "remarks": None} for c in stageList]

    primaryChecks = buildChecks(stages.get("primary", []))
    secondaryChecks = buildChecks(stages.get("secondary", []))
    finalChecks = buildChecks(stages.get("final", []))

    verificationDoc = {
        "candidateId": candidateId,
        "candidateName": f"{candidate.get('firstName', '')} {candidate.get('lastName', '')}".strip(),
        "organizationId": organizationId,
        "organizationName": organizationName,
        "initiatedBy": userEmail,
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

    await candidatesCol.update_one(
        {"_id": candidateObjId},
        {"$set": {"status": "IN_PROGRESS"}}
    )

    await logActivity(
        user,
        "Initiated Verification",
        f"{userEmail} ({role}) initiated verification for {candidate.get('firstName')} ({organizationName})",
        "Success"
    )

    asyncio.create_task(process_verification_pipeline(result.inserted_id, candidate, verificationDoc["stages"]))

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
            "initiatedBy": userEmail,
            "stages": verificationDoc["stages"],
            "status": "IN_PROGRESS"
        })
    )



import uuid
from datetime import datetime, timezone, timedelta
from bson import ObjectId
from fastapi import HTTPException, Body, Depends
from fastapi.responses import JSONResponse
from utils.email_utils import send_self_verification_link


from fastapi import UploadFile, File, Form
from fastapi import APIRouter
from fastapi import Depends
from fastapi import HTTPException
from fastapi.responses import JSONResponse
from datetime import datetime, timezone
import jwt

# import utils functions
from utils import create_self_token, decode_self_token, send_self_verification_email

# Reuse your existing run_verification (synchronous check runner) or call the async one.
# from apis import run_verification   # ensure this import matches your project

# ROUTES: public prefix /self/*
# If you use APIRouter, attach; else directly in app: @app.post...
# e.g., router = APIRouter(prefix="/self")
# For simplicity below, use app directly (you can adapt to router).

# ---------------------------
# 1) Initiate self verification (called by logged-in admin)
# ---------------------------
@app.post("/secure/initiateSelfVerification")
async def initiateSelfVerification(body: dict = Body(...), user: dict = Depends(requireAuth)):
    """
    Called by authorized users to send an email link to candidate to complete self verification.
    Body expects: candidateId (string), stages {primary:[], secondary:[], final:[]}, optional organizationId
    Authorization rules: follow your existing rules for initiating verifications.
    """
    role = user.get("role")
    userEmail = user.get("email", "").lower().strip()
    candidateId = body.get("candidateId")
    stages = body.get("stages", {})
    requestedOrgId = body.get("organizationId") or None

    if not candidateId or not stages:
        raise HTTPException(status_code=400, detail="candidateId and stages are required")

    # Validate candidate
    try:
        candidateObjId = ObjectId(candidateId)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid candidateId")

    candidate = await candidatesCol.find_one({"_id": candidateObjId})
    if not candidate:
        raise HTTPException(status_code=404, detail="Candidate not found")

    candidateOrgId = str(candidate.get("organizationId"))
    # Determine organizationId based on role (reuse your authorize logic)
    organizationId = None
    organizationName = None

    # SUPER_ADMIN & BGV SPOC: can do any org (use requested or candidate's)
    if role == "SUPER_ADMIN" or (role == "SPOC" and ("@bgv.local" in userEmail or "bgvapp.in" in userEmail)):
        organizationId = requestedOrgId or candidateOrgId
    elif role == "SUPER_ADMIN_HELPER":
        accessible = [str(x) for x in user.get("accessibleOrganizations", [])]
        selected = requestedOrgId or candidateOrgId
        if not selected or selected not in accessible:
            raise HTTPException(status_code=403, detail="Not authorized for this organization")
        organizationId = selected
    elif role in ["ORG_HR", "SPOC"]:
        # Must be same org
        if candidateOrgId != str(user.get("organizationId")):
            raise HTTPException(status_code=403, detail="You can only send links for candidates in your organization")
        organizationId = str(user.get("organizationId"))
    elif role == "HELPER":
        # Helper allowed only for candidates they created
        if candidate.get("createdBy", "").lower().strip() != userEmail:
            raise HTTPException(status_code=403, detail="You can only send links to candidates created by you")
        organizationId = str(user.get("organizationId"))
    else:
        raise HTTPException(status_code=403, detail="Not authorized to initiate self-verification")

    # Validate org exists
    try:
        orgDoc = await orgsCol.find_one({"_id": ObjectId(organizationId)})
    except Exception:
        orgDoc = None
    if not orgDoc:
        raise HTTPException(status_code=404, detail="Organization not found")
    organizationName = orgDoc.get("organizationName")

    # Prevent duplicate active verification for same candidate + org
    existing = await verificationsCol.find_one({
        "candidateId": candidateId,
        "organizationId": organizationId,
        "overallStatus": {"$in": ["IN_PROGRESS", "PENDING"]}
    })
    if existing:
        raise HTTPException(status_code=409, detail="An active verification already exists for this candidate and organization")

    # Build verification doc (mode SELF)
    def buildChecks(stageList):
        return [{"check": c, "status": "NOT_STARTED", "remarks": None, "attachments": [], "submittedAt": None} for c in stageList]

    primaryChecks = buildChecks(stages.get("primary", []))
    secondaryChecks = buildChecks(stages.get("secondary", []))
    finalChecks = buildChecks(stages.get("final", []))

    now = datetime.now(timezone.utc).isoformat()

    # create self token
    token, tokenExp = create_self_token(candidateId, organizationId)

    verificationDoc = {
        "candidateId": candidateId,
        "candidateName": f"{candidate.get('firstName','')} {candidate.get('lastName','')}".strip(),
        "organizationId": organizationId,
        "organizationName": organizationName,
        "initiatedBy": userEmail,
        "initiatedAt": now,
        "mode": "SELF",
        "token": token,
        "tokenExpiresAt": datetime.fromtimestamp(tokenExp, tz=timezone.utc).isoformat(),
        "stages": {
            "primary": primaryChecks,
            "secondary": secondaryChecks,
            "final": finalChecks
        },
        "currentStage": "primary",
        "overallStatus": "PENDING",
        "assignedTo": None,
        "remarks": []
    }

    res = await verificationsCol.insert_one(verificationDoc)

    # Send email
    try:
        send_self_verification_email(candidate.get("email"), verificationDoc["candidateName"], token, organizationName)
    except Exception as e:
        # optionally remove verification if email fails
        await verificationsCol.delete_one({"_id": res.inserted_id})
        raise HTTPException(status_code=500, detail=f"Failed to send email: {str(e)}")

    await logActivity(user, "Initiated Self Verification", f"Sent self verification link to {candidate.get('email')} for {organizationName}", "Success")

    return JSONResponse(status_code=201, content=jsonable_encoder({
        "message": "Self verification link created and email sent",
        "verificationId": str(res.inserted_id),
        "tokenExpiresAt": verificationDoc["tokenExpiresAt"]
    }))


# ---------------------------
# 2) Validate link (candidate opens the URL)
# ---------------------------
@app.get("/self/verify/validate")
async def selfVerifyValidate(token: str):
    """
    Public endpoint. Validates token and returns current verification state.
    """
    try:
        payload = decode_self_token(token)
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token")

    candidateId = payload.get("candidateId")
    organizationId = payload.get("organizationId")

    ver = await verificationsCol.find_one({"candidateId": candidateId, "organizationId": organizationId, "token": token})
    if not ver:
        raise HTTPException(status_code=404, detail="Verification link not found or already used")

    # return verification summary (do not expose sensitive fields)
    safe_ver = {
        "verificationId": str(ver["_id"]),
        "candidateId": ver["candidateId"],
        "candidateName": ver.get("candidateName"),
        "organizationId": ver.get("organizationId"),
        "organizationName": ver.get("organizationName"),
        "overallStatus": ver.get("overallStatus"),
        "currentStage": ver.get("currentStage"),
        "stages": ver.get("stages"),
        "tokenExpiresAt": ver.get("tokenExpiresAt")
    }
    return JSONResponse(status_code=200, content=jsonable_encoder(safe_ver))


# ---------------------------
# 3) Candidate authenticate (simple identity check before starting)
# ---------------------------
@app.post("/self/verify/authenticate")
async def selfVerifyAuthenticate(token: str = Form(...), identifier: str = Form(...)):
    """
    A simple authentication step for candidate. Example identifier can be last4aadhaar or phone.
    Body form:
      - token: token from email
      - identifier: candidate-provided identifier (e.g., last4 of Aadhaar or phone)
    Returns: success if identifier matches candidate record
    """
    try:
        payload = decode_self_token(token)
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token")

    candidateId = payload.get("candidateId")
    ver = await verificationsCol.find_one({"candidateId": candidateId, "token": token})
    if not ver:
        raise HTTPException(status_code=404, detail="Verification not found")

    candidate = await candidatesCol.find_one({"_id": ObjectId(candidateId)})
    if not candidate:
        raise HTTPException(status_code=404, detail="Candidate not found")

    # Example checks: last 4 digits of Aadhaar OR phone
    provided = (identifier or "").strip()
    aadhaar = (candidate.get("aadhaarNumber") or "")
    phone = (candidate.get("phone") or "")

    match = False
    if aadhaar and provided and aadhaar.endswith(provided):
        match = True
    if phone and provided and phone.endswith(provided):
        match = True

    if not match:
        raise HTTPException(status_code=403, detail="Identifier does not match candidate records")

    # Mark verification as IN_PROGRESS if PENDING
    if ver.get("overallStatus") == "PENDING":
        await verificationsCol.update_one({"_id": ver["_id"]}, {"$set": {"overallStatus": "IN_PROGRESS"}})

    return JSONResponse(status_code=200, content={"message": "Authenticated", "verificationId": str(ver["_id"])})


# ---------------------------
# 4) Submit a single check (candidate action)
# ---------------------------
@app.post("/self/verify/check")
async def selfVerifySubmitCheck(
    token: str = Form(...),
    verificationId: str = Form(...),
    stage: str = Form(...),
    check: str = Form(...),
    metadata: Optional[str] = Form(None),
    file: Optional[UploadFile] = File(None)
):
    """
    Candidate submits data for a single check.
    - token: from email
    - verificationId: id returned from validate/authenticate
    - stage: primary|secondary|final
    - check: check key (aadhaar, pan, passport etc.)
    - metadata: optional JSON string for text inputs (e.g., aadhaar number)
    - file: optional file upload (image/pdf)
    """

    # Validate token -> ensure verification exists and token matches
    try:
        payload = decode_self_token(token)
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token")

    # verify verificationId & token stored on doc
    try:
        verObjId = ObjectId(verificationId)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid verificationId")

    ver = await verificationsCol.find_one({"_id": verObjId})
    if not ver or ver.get("token") != token:
        raise HTTPException(status_code=404, detail="Verification record not found or token mismatch")

    if ver.get("overallStatus") not in ["IN_PROGRESS", "PENDING"]:
        raise HTTPException(status_code=409, detail="Verification not in a state that accepts submissions")

    # Authoritative enforcement: only accept if the stage matches currentStage
    currentStage = ver.get("currentStage", "primary")
    if stage != currentStage:
        raise HTTPException(status_code=403, detail=f"This stage is not active. currentStage={currentStage}")

    # Ensure earlier checks in stage are COMPLETED
    stageChecks = ver.get("stages", {}).get(stage, [])
    # find index of the requested check
    idx = None
    for i, ch in enumerate(stageChecks):
        if ch.get("check") == check:
            idx = i
            break
    if idx is None:
        raise HTTPException(status_code=400, detail="Check not found in this stage")

    # If any prior check in stage has FAILED -> block
    for prior in stageChecks[:idx]:
        if prior.get("status") == "FAILED":
            raise HTTPException(status_code=403, detail="Previous check failed — resolve before continuing")

    # If the target check is already COMPLETED, return
    if stageChecks[idx].get("status") == "COMPLETED":
        return JSONResponse(status_code=200, content={"message": "Check already completed"})

    # Store uploaded file (optional) — you should replace this with your actual storage (S3/GCS)
    attachment_info = None
    if file:
        contents = await file.read()
        # For now, store as gridfs or as file in /tmp then upload. Here we'll save metadata.
        attachment_info = {
            "filename": file.filename,
            "contentType": file.content_type,
            # you should upload to storage and store the URL instead of raw bytes
            "size": len(contents),
            "uploadedAt": datetime.now(timezone.utc).isoformat()
        }
        # If you want to save file to disk: with open(...) write contents
        # For security, do not persist raw bytes into DB

    # run single-check verification synchronously (recommended for quicker checks)
    # Compose candidate object for run_verification
    candidate = await candidatesCol.find_one({"_id": ObjectId(ver["candidateId"])})
    try:
        status, remarks = await run_verification(check, candidate)  # ensure this is async in your code or wrap
    except Exception as e:
        status, remarks = "FAILED", f"Runtime error: {str(e)}"

    # update the specific check entry in DB
    update_fields = {
        f"stages.{stage}.{idx}.status": status,
        f"stages.{stage}.{idx}.remarks": remarks,
        f"stages.{stage}.{idx}.submittedAt": datetime.now(timezone.utc).isoformat()
    }
    if attachment_info:
        update_fields[f"stages.{stage}.{idx}.attachments"] = [attachment_info]

    await verificationsCol.update_one({"_id": verObjId}, {"$set": update_fields})

    # If FAILED: set verification overallStatus=FAILED and set failureStage
    if status == "FAILED":
        await verificationsCol.update_one(
            {"_id": verObjId},
            {"$set": {"overallStatus": "FAILED", "failureStage": f"{stage}_{check}", "currentStage": stage}}
        )
        # Update candidate status if desired
        await candidatesCol.update_one({"_id": ObjectId(ver["candidateId"])}, {"$set": {"status": f"FAILED_AT_{stage}_{check}"}})
        await logActivity({"email": "self_candidate"}, "Self Verification Failed", f"{ver['candidateName']} failed {check}", "Error")
        return JSONResponse(status_code=200, content={"status": status, "remarks": remarks})

    # If COMPLETED: check if entire stage completed -> move currentStage forward
    # Fetch fresh ver doc
    ver_latest = await verificationsCol.find_one({"_id": verObjId})
    stage_all = ver_latest.get("stages", {}).get(stage, [])
    if all(ch.get("status") == "COMPLETED" for ch in stage_all):
        # advance stage if next stage exists
        next_stage = None
        if stage == "primary":
            next_stage = "secondary" if ver_latest.get("stages", {}).get("secondary") else "final"
        elif stage == "secondary":
            next_stage = "final" if ver_latest.get("stages", {}).get("final") else None

        if next_stage:
            await verificationsCol.update_one({"_id": verObjId}, {"$set": {"currentStage": next_stage}})
        else:
            # No next stage -> finish
            await verificationsCol.update_one({"_id": verObjId}, {"$set": {"overallStatus": "COMPLETED", "currentStage": "final"}})
            await candidatesCol.update_one({"_id": ObjectId(ver["candidateId"])}, {"$set": {"status": "VERIFIED"}})

    await logActivity({"email": "self_candidate"}, "Self Verification Check Completed", f"{ver['candidateName']} completed {check}", "Success")
    return JSONResponse(status_code=200, content={"status": status, "remarks": remarks})


# ---------------------------
# 5) Get verification status (polling)
# ---------------------------
@app.get("/self/verify/status")
async def selfVerifyStatus(verificationId: str, token: str = None):
    """
    Return verification doc for frontend polling. If token provided, verify it; otherwise restrict.
    """
    try:
        verObjId = ObjectId(verificationId)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid verificationId")
    ver = await verificationsCol.find_one({"_id": verObjId})
    if not ver:
        raise HTTPException(status_code=404, detail="Verification not found")

    # If token present, validate it matches
    if token:
        try:
            payload = decode_self_token(token)
        except Exception:
            raise HTTPException(status_code=401, detail="Invalid token")

        if payload.get("candidateId") != ver.get("candidateId") or payload.get("organizationId") != ver.get("organizationId"):
            raise HTTPException(status_code=403, detail="Token does not match verification")

    # return sanitized doc
    safe_ver = {
        "verificationId": str(ver["_id"]),
        "candidateId": ver["candidateId"],
        "candidateName": ver.get("candidateName"),
        "organizationId": ver.get("organizationId"),
        "organizationName": ver.get("organizationName"),
        "currentStage": ver.get("currentStage"),
        "overallStatus": ver.get("overallStatus"),
        "stages": ver.get("stages"),
        "failureStage": ver.get("failureStage", None)
    }
    return JSONResponse(status_code=200, content=jsonable_encoder(safe_ver))
from apis import process_verification_record
from bson import ObjectId

@app.post("/secure/resumePendingVerifications")
async def resumePendingVerifications(user: dict = Depends(requireAuth)):
    """
    Resume pending or in-progress verifications.
    Rules:
      - SUPER_ADMIN → can resume all.
      - SUPER_ADMIN_HELPER → can resume only from accessible organizations.
      - Others → forbidden.
    """
    role = user.get("role")
    accessibleOrgs = [str(x) for x in user.get("accessibleOrganizations", [])]

    # ------------------------------
    # 🔒 Role-based Access Control
    # ------------------------------
    if role not in ["SUPER_ADMIN", "SUPER_ADMIN_HELPER"]:
        raise HTTPException(status_code=403, detail="Not authorized to resume verifications")

    # ------------------------------
    # 🎯 Build Query Based on Role
    # ------------------------------
    query = {"overallStatus": {"$in": ["IN_PROGRESS", "PENDING"]}}

    if role == "SUPER_ADMIN_HELPER":
        if not accessibleOrgs:
            raise HTTPException(status_code=403, detail="No organizations assigned to helper")
        query["organizationId"] = {"$in": accessibleOrgs}

    # ------------------------------
    # 🔄 Resume Matching Verifications
    # ------------------------------
    pending_cursor = verificationsCol.find(query)
    count = 0

    async for verification in pending_cursor:
        try:
            # Verify candidate still exists
            candidate = await candidatesCol.find_one({"_id": ObjectId(verification["candidateId"])})
            if not candidate:
                continue

            # Relaunch background verification task
            asyncio.create_task(process_verification_record(verification))
            count += 1

        except Exception as e:
            await logActivity(
                user,
                "Resume Verification Failed",
                f"Error resuming verification {verification.get('_id')}: {str(e)}",
                "Error"
            )

    # ------------------------------
    # ✅ Response + Activity Log
    # ------------------------------
    if count == 0:
        await logActivity(
            user,
            "Resume Verifications",
            f"No pending verifications found for {role}",
            "Info"
        )
        return {"message": "No pending verifications found"}

    await logActivity(
        user,
        "Resume Verifications",
        f"{role} resumed {count} verifications",
        "Success"
    )

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

    # ------------------------
    # 🔐 Role-based conditions
    # ------------------------

    # 1️⃣ SUPER_ADMIN / BGV SPOC → any org
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

    # 3️⃣ ORG_HR / ORG_SPOC → only own org
    elif role in ["ORG_HR", "ORG_SPOC"]:
        orgId = user.get("organizationId")
        if not orgId:
            raise HTTPException(status_code=400, detail="Organization ID missing for HR/SPOC")
        org = await orgsCol.find_one({"_id": ObjectId(orgId)})
        if not org:
            raise HTTPException(status_code=404, detail="Organization not found")
        orgName = org.get("organizationName")

    # 4️⃣ ORG_HELPER → must have 'candidate:create' permission
    elif role == "HELPER":
        if "candidate:create" not in user.get("permissions", []):
            raise HTTPException(status_code=403, detail="You don't have permission to add candidates")

        orgId = user.get("organizationId")
        if not orgId:
            raise HTTPException(status_code=400, detail="Organization ID missing for helper")
        org = await orgsCol.find_one({"_id": ObjectId(orgId)})
        if not org:
            raise HTTPException(status_code=404, detail="Organization not found")
        orgName = org.get("organizationName")

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

    # ---------------------
    # 🧾 Create candidate
    # ---------------------
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

    # ✅ Debug sanity check before insert
    if not orgId:
        raise HTTPException(status_code=400, detail="Internal error: missing organizationId before insert")

    # ✅ Force insert and confirm
    result = await candidatesCol.insert_one(candidateDoc)
    if not result or not result.inserted_id:
        raise HTTPException(status_code=500, detail="Candidate insert failed (no ID returned)")

    candidateDoc["_id"] = str(result.inserted_id)

    # 🪵 Log success
    await logActivity(
        user,
        "Add Candidate",
        f"{creatorEmail} added candidate {firstName} {lastName} to {orgName}",
        "Success"
    )

    # ✅ Final safety: re-fetch from DB to confirm persistence
    savedCandidate = await candidatesCol.find_one({"_id": ObjectId(result.inserted_id)})
    if not savedCandidate:
        raise HTTPException(status_code=500, detail="Candidate not found after insert (DB write issue)")

    savedCandidate["_id"] = str(savedCandidate["_id"])

    return JSONResponse(
        status_code=201,
        content=jsonable_encoder({
            "message": "Candidate added successfully",
            "candidate": savedCandidate
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