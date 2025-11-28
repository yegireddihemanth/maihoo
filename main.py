
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
from fastapi import UploadFile, File, HTTPException, Depends
from config import *
from bson import ObjectId
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
from utils.email_utils import send_self_verification_email, send_organization_welcome_email
from utils.email_utils import  send_self_verification_email
from fastapi import Depends, HTTPException
from fastapi.responses import JSONResponse
from fastapi.encoders import jsonable_encoder
from datetime import datetime, timezone
from bson import ObjectId
from fastapi import UploadFile, File, Form, Depends, HTTPException
from utils.ai_utils import generate_resume_embeddings_and_rank
from utils.email_utils import *

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
app = FastAPI(title="BGV Login API with Cookies",  version="1.0.0", docs_url="/docs")

origins = [
    "https://localhost:3443",
    "https://bab4f4a54b2b.ngrok-free.app",
    "http://localhost:3000",
    "https://localhost:3000",
    "http://127.0.0.1:3000",
    "https://2440df7ab360.ngrok-free.app",
    "https://maihoo.onrender.com",
    "https://bgv-zfdw.onrender.com",
    
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,  # ✅ Changed from allow_origin_regex to allow_origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["set-cookie"]
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
ticketsCol = db['tickets']
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

async def logActivity(user, action, description, status):
    # SELF-verification (public endpoint): no authenticated user
    if user is None:
        userId = None
        userEmail = "self-verification"
        userRole = "SELF"
        orgId = None
    else:
        userId = str(user.get("_id")) if user.get("_id") else None
        userEmail = user.get("email")
        userRole = user.get("role")
        orgId = str(user.get("organizationId")) if user.get("organizationId") else None

    logEntry = {
        "userId": userId,
        "userEmail": userEmail,
        "userRole": userRole,
        "organizationId": orgId,
        "action": action,
        "description": description,
        "status": status,
        "timestamp": datetime.now(timezone.utc)
    }

    # ✅ THIS LINE SAVES THE LOG TO MONGO
    await activityLogsCol.insert_one(logEntry)

    return True



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

from fastapi.openapi.docs import get_swagger_ui_html



@app.get("/swagger", include_in_schema=False)
async def custom_swagger():
    return get_swagger_ui_html(
        openapi_url=app.openapi_url,  # Auto uses correct domain
        title="Swagger UI",
    )

# -------------------------------
# Auth Routes
# -------------------------------
@app.post("/auth/login")
async def login(body: loginRequest, response: Response):
    # --- Authenticate user ---
    normalizedEmail = body.email.lower().strip()

    user = await usersCol.find_one({
        "email": {
            "$regex": f"^{normalizedEmail}$",
            "$options": "i"   # case insensitive
        },
        "password": body.password,
        "isActive": True
    })



    if not user:
        raise HTTPException(status_code=401, detail="invalid credentials")

    orgId = user.get("organizationId")
    isSuperAdmin = user.get("role") in ["SUPER_ADMIN", "SUPER_SPOC"]
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

    if not (role in ["SUPER_ADMIN",  "SUPER_SPOC"]):
        raise HTTPException(status_code=403, detail="Only Super Admin or Global SPOC can add organizations")

    # Auto-generate subdomain if not provided
    cleanOrgName = body.organizationName.split()[0].lower()
    autoSubDomain = body.subDomain or f"{cleanOrgName}.bgvapp.in"

    # -----------------------------------------
    # UPDATED: duplicate check with optional mainDomain
    # -----------------------------------------
    duplicateQuery = [
        {"email": body.email},
        {"subDomain": autoSubDomain}
    ]

    if body.mainDomain:   # include only if provided
        duplicateQuery.append({"mainDomain": body.mainDomain})

    existingOrg = await orgsCol.find_one({"$or": duplicateQuery})

    if existingOrg:
        await logActivity(user, "Register Organization Failed", f"Duplicate org: {body.email}", "Error")
        raise HTTPException(status_code=409, detail="Organization with same email or domain already exists")

    now = datetime.now(timezone.utc).isoformat()

    # -----------------------------------------
    # UPDATED: mainDomain may be None
    # -----------------------------------------
    orgDoc = {
        "organizationName": body.organizationName,
        "spocName": body.spocName,
        "mainDomain": body.mainDomain or None,
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
        # --- Send welcome email to SPOC ---
    try:
        send_organization_welcome_email(
            toEmail=body.email,
            organizationName=body.organizationName,
            spocName=body.spocName,
            loginEmail=body.email,
            defaultPassword="Welcome1",
            mainDomain=body.mainDomain,
            subDomain=autoSubDomain,
            services=[s.dict() for s in body.services],
            credentials=body.credentials.dict(),
            logoUrl=body.logoUrl
        )
    except Exception as e:
        print("Failed to send organization welcome email:", str(e))

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




# ✅ Permission guard (import or place at the top of your routes file)
def requirePermission(requiredPermissions):
    async def wrapper(user: dict = Depends(requireAuth)):
        role = user.get("role")
        userPermissions = user.get("permissions", [])

        # SUPER_ADMIN and SPOC always bypass permission check
        if role in ["SUPER_ADMIN", "SPOC", "SUPER_SPOC"]:
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
        if role in ["SUPER_ADMIN" ,"SUPER_SPOC"]:
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
    # SUPER ADMIN or SUPER_SPOC
    # ---------------------------------------------------
    if role in ["SUPER_ADMIN" , "SUPER_SPOC"]:
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
        await logActivity(user, "View Dashboard", f"{role}  viewed dashboard", "Success")
        return JSONResponse(status_code=200, content=jsonable_encoder({
            "role": role,
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
    if role not in ["SUPER_ADMIN", "SPOC", "ORG_HR", "SUPER_SPOC"]:
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
    if role not in ["SUPER_ADMIN", "SUPER_ADMIN_HELPER", "SPOC", "ORG_HR", "SUPER_SPOC"]:
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
        "SUPER_SPOC": [
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
    if role in [ "SUPER_ADMIN" , "SUPER_SPOC"]:
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
        - SPOC → only own org
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
    if role in ["SUPER_ADMIN" , "SUPER_SPOC"]:
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
    if role in ["SUPER_ADMIN" , "SUPER_SPOC"]:
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
    if role in [ "SUPER_ADMIN" , "SUPER_SPOC"]:
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
    if role in ["SUPER_ADMIN", "SUPER_SPOC"]:

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
# ============================
# REQUIRED IMPORTS (ONLY ADDITIONS)
# ============================
import math
from fastapi.encoders import jsonable_encoder
from fastapi.responses import JSONResponse
from bson import ObjectId

# If your logActivity is in utils.activity_logger

# If it's somewhere else, update the path properly.
# ============================
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
    - SPOC / ORG_HR: only their own organization
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
    if role in ["SUPER_ADMIN", "SUPER_SPOC"]:
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

    elif role in ["SPOC", "ORG_HR"]:
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

                # ---------------------------------------------------
                # 🔥 FIX: Prevent crash when DB contains raw strings
                # ---------------------------------------------------
                if isinstance(check, str):
                    check = {
                        "check": check,
                        "status": "NOT_STARTED",
                        "remarks": None
                    }
                # ---------------------------------------------------

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
      - SPOC or ORG_HR → candidates only from their own org (organizationId)
      - HELPER → only candidates created by them (createdBy = their email)
    """

    role = user.get("role")
    userEmail = user.get("email", "").lower().strip()
    userOrgId = str(user.get("organizationId"))
    accessibleOrgs = [str(x) for x in user.get("accessibleOrganizations", [])]
    query = {}

    # 🔹 SUPER_ADMIN → access all
    if role in ["SUPER_ADMIN", "SUPER_SPOC"]:
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

    # 🔹 SPOC or ORG_HR → only their org
    elif role in ["SPOC", "ORG_HR"]:
        if not userOrgId:
            raise HTTPException(status_code=400, detail="Organization ID missing in profile")
        query["organizationId"] = userOrgId

    # 🔹 HELPER → only candidates they created
    elif role == "HELPER":
        query["createdBy"] = {
        "$regex": f"^{userEmail}$",
        "$options": "i"
}


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

@app.post("/secure/modifyCandidate")
async def modifyCandidate(body: dict = Body(...), user: dict = Depends(requireAuth)):
    """
    Modify (EDIT / DELETE) a candidate with role-based access control.

    Body:
    {
        "operation": "edit" | "delete",
        "candidateId": "...",
        "organizationId": "...",
        "updates": { ... }   # only for edit
    }
    """

    operation = body.get("operation")
    candidateId = body.get("candidateId")
    organizationId = body.get("organizationId")
    updates = body.get("updates", {})

    if operation not in ["edit", "delete"]:
        raise HTTPException(400, "Invalid operation. Use 'edit' or 'delete'.")

    if not candidateId or not organizationId:
        raise HTTPException(400, "candidateId and organizationId are required")

    # Validate ObjectId
    try:
        candObjId = ObjectId(candidateId)
    except:
        raise HTTPException(400, "Invalid candidateId")

    # Fetch candidate
    candidate = await candidatesCol.find_one({"_id": candObjId})
    if not candidate:
        raise HTTPException(404, "Candidate not found")

    # Validate candidate belongs to given org
    candOrg = str(candidate.get("organizationId"))
    if candOrg != organizationId:
        raise HTTPException(403, "Candidate does not belong to provided organizationId")

    # -----------------------------------------
    # ROLE-BASED ACCESS CONTROL
    # -----------------------------------------
    role = user.get("role")
    userEmail = user.get("email", "").lower().strip()
    userOrgId = str(user.get("organizationId"))
    accessible = [str(x) for x in user.get("accessibleOrganizations", [])]
    createdBy = (candidate.get("createdBy") or "").lower().strip()

    allowed = False

    # 1. SUPER ADMIN → can edit/delete any candidate
    if role in ["SUPER_ADMIN", "SUPER_SPOC"]:
        allowed = True

    # 2. BGV SPOC (global spoc)
    elif role == "SPOC" and ("@bgv.local" in userEmail or "bgvapp.in" in userEmail):
        allowed = True

    # 3. SUPER_ADMIN_HELPER → only in allocated orgs
    elif role == "SUPER_ADMIN_HELPER":
        if organizationId in accessible:
            allowed = True

    # 4. ORG_HR / SPOC → only inside their org
    elif role in ["ORG_HR", "SPOC"]:
        if organizationId == userOrgId:
            allowed = True

    # 5. HELPER → only candidates created by them AND same org
    elif role == "HELPER":
        if organizationId == userOrgId and createdBy == userEmail:
            allowed = True

    if not allowed:
        raise HTTPException(403, "You are not authorized to modify this candidate")

    # ------------------------------------------
    # DELETE OPERATION
    # ------------------------------------------
    if operation == "delete":

        # do NOT allow deletion if candidate has active/in-progress verification
        activeVer = await verificationsCol.find_one({
            "candidateId": candidateId,
            "overallStatus": {"$in": ["PENDING", "IN_PROGRESS"]}
        })

        if activeVer:
            raise HTTPException(
                400,
                "Cannot delete candidate — active verification is in progress."
            )

        # delete candidate
        await candidatesCol.delete_one({"_id": candObjId})

        # delete all verification records (optional but recommended)
        await verificationsCol.delete_many({"candidateId": candidateId})

        await logActivity(
            user,
            "Delete Candidate",
            f"Candidate {candidateId} deleted",
            "Success"
        )

        return {"message": "Candidate deleted successfully"}

    # ------------------------------------------
    # EDIT OPERATION
    # ------------------------------------------
    if operation == "edit":

        if not isinstance(updates, dict) or len(updates) == 0:
            raise HTTPException(400, "updates object is required for edit")

        # ---------------------------------------------------------
        # UPDATED allowed fields with NEW fields added
        # ---------------------------------------------------------
        allowedFields = {
            "firstName",
            "middleName",
            "lastName",
            "email",
            "phone",
            "aadhaarNumber",
            "panNumber",
            "address",
            "dob",
            "passportNumber",
            "uanNumber",
            "bankAccountNumber",

            # NEWLY ADDED FIELDS
            "fatherName",
            "gender",
            "district",
            "state",
            "pincode"
        }

        clean_updates = {k: v for k, v in updates.items() if k in allowedFields}

        if len(clean_updates) == 0:
            raise HTTPException(400, "No valid fields provided to update")

        # apply update
        await candidatesCol.update_one(
            {"_id": candObjId},
            {"$set": clean_updates}
        )

        await logActivity(
            user,
            "Edit Candidate",
            f"Updated candidate {candidateId}",
            "Success"
        )

        return {
            "message": "Candidate updated successfully",
            "updatedFields": list(clean_updates.keys())
        }

@app.post("/secure/initiateStageVerification")
async def initiateStageVerification(body: dict = Body(...), user: dict = Depends(requireAuth)):
    """
    Controlled stage initiation (primary → secondary → final).
    """

    # Extract request body
    candidateId = body.get("candidateId")
    stagesIn = body.get("stages", {})
    requestedOrgId = body.get("organizationId")

    if not candidateId or not stagesIn:
        raise HTTPException(status_code=400, detail="candidateId and stages are required")

    # Exactly one stage must be provided
    if len(stagesIn.keys()) != 1:
        raise HTTPException(status_code=400, detail="Provide exactly one stage per request")

    stageName = list(stagesIn.keys())[0]  # primary / secondary / final
    stageList = stagesIn.get(stageName) or []

    if not isinstance(stageList, list) or len(stageList) == 0:
        raise HTTPException(status_code=400, detail="Stage must contain at least one check")

    # -------------------------------
    # VALIDATE NO DUPLICATE CHECKS IN SAME STAGE
    # -------------------------------
    if len(stageList) != len(set(stageList)):
        raise HTTPException(status_code=400, detail="Duplicate checks found in this stage. Duplicates are not allowed.")

    # -------------------------------
    # VALIDATE CANDIDATE
    # -------------------------------
    try:
        candidateObjId = ObjectId(candidateId)
    except:
        raise HTTPException(status_code=400, detail="Invalid candidateId")

    candidate = await candidatesCol.find_one({"_id": candidateObjId})
    if not candidate:
        raise HTTPException(status_code=404, detail="Candidate not found")

    candidateOrgId = str(candidate.get("organizationId"))

    # -------------------------------
    # CHECK IF CANDIDATE BELONGS TO GIVEN ORG
    # -------------------------------
    if candidateOrgId != requestedOrgId:
        raise HTTPException(
            status_code=403,
            detail="Candidate does not belong to the given organization"
        )

    # -------------------------------
    # ROLE → ORG ACCESS CONTROL
    # -------------------------------
    role = user.get("role")
    userEmail = user.get("email", "").lower().strip()
    userOrgId = str(user.get("organizationId"))
    accessible = [str(x) for x in user.get("accessibleOrganizations", [])]

    # SUPER_ADMIN → all orgs allowed
    if role in ["SUPER_ADMIN", "SUPER_SPOC"]:
        pass

    # BGV SPOC → all orgs allowed
    elif role == "SPOC" and ("@bgv.local" in userEmail or "bgvapp.in" in userEmail):
        pass

    # SUPER_ADMIN_HELPER → only allocated orgs
    elif role == "SUPER_ADMIN_HELPER":
        if requestedOrgId not in accessible:
            raise HTTPException(status_code=403, detail="Not authorized for this organization")

    # SPOC / ORG_HR → only their org
    elif role in ["ORG_HR", "SPOC"]:
        if requestedOrgId != userOrgId:
            raise HTTPException(status_code=403, detail="Not authorized for this organization")

    # HELPER → only own candidates and same org
    elif role == "HELPER":
        if requestedOrgId != userOrgId:
            raise HTTPException(status_code=403, detail="Not authorized for this organization")
        if candidate.get("createdBy", "").lower().strip() != userEmail:
            raise HTTPException(status_code=403, detail="You can only access candidates created by you")

    else:
        raise HTTPException(status_code=403, detail="Not authorized")

    # -------------------------------
    # ENSURE ORGANIZATION EXISTS
    # -------------------------------
    try:
        org = await orgsCol.find_one({"_id": ObjectId(requestedOrgId)})
    except:
        org = None

    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")

    organizationName = org.get("organizationName")

    # -------------------------------
    # CHECK EXISTING VERIFICATION DOC
    # -------------------------------
    ver = await verificationsCol.find_one({
        "candidateId": candidateId,
        "organizationId": requestedOrgId
    })

    # ---------------------------------------------------------------
    # 🛑 FIX INSERTED — BLOCK CREATING SECONDARY/FINAL AS FIRST STAGE
    # ---------------------------------------------------------------
    if not ver and stageName != "primary":
        raise HTTPException(
            status_code=403,
            detail="Primary stage must be initiated first before secondary/final."
        )
    # ---------------------------------------------------------------

    # Helper to build check objects
    def buildChecks(chkList):
        return [{"check": c, "status": "NOT_STARTED", "remarks": None,
                 "attachments": [], "submittedAt": None} for c in chkList]

    newChecks = buildChecks(stageList)

    # ======================================================
    # 🛑 VALIDATION — NO STAGE JUMPING + DUPLICATE BLOCKING
    # ======================================================
    if ver:
        existingStages = ver.get("stages", {})

        # Helper: stage exists and has checks
        def stage_exists(stageKey):
            return len(existingStages.get(stageKey, [])) > 0

        # Helper: stage fully completed
        def stage_completed(stageKey):
            stageChecks = existingStages.get(stageKey, [])
            return len(stageChecks) > 0 and all(c.get("status") == "COMPLETED" for c in stageChecks)

        # Helper: check duplicates across all stages
        def check_used(checkName):
            for st, chks in existingStages.items():
                for c in chks:
                    # Case 1: old format → "pan"
                    if isinstance(c, str):
                        if c == checkName:
                            return True

                    # Case 2: new format → {"check": "pan", ...}
                    elif isinstance(c, dict):
                        if c.get("check") == checkName:
                            return True

            return False


        # ❌ BLOCK duplicate checks ACROSS ALL STAGES
        for chk in stageList:
            if check_used(chk):
                raise HTTPException(
                    status_code=400,
                    detail=f"Check '{chk}' already used in another stage. Duplicate checks across stages are not allowed."
                )

        # ❌ BLOCK Starting SECONDARY without PRIMARY completed
        if stageName == "secondary":
            if not stage_exists("primary"):
                raise HTTPException(403, "Primary stage missing, cannot start Secondary")
            if not stage_completed("primary"):
                raise HTTPException(403, "Primary stage is not completed yet")

        # ❌ BLOCK Starting FINAL without PRIMARY + SECONDARY completed
        if stageName == "final":
            if not stage_exists("primary"):
                raise HTTPException(403, "Primary stage missing, cannot start Final")
            if not stage_completed("primary"):
                raise HTTPException(403, "Primary stage is not completed yet")
            if not stage_exists("secondary"):
                raise HTTPException(403, "Secondary stage missing, cannot start Final")
            if not stage_completed("secondary"):
                raise HTTPException(403, "Secondary stage is not completed yet")

        # ------------------------------------
        # IF STAGE ALREADY EXISTS
        # ------------------------------------
        if stageName in existingStages and len(existingStages[stageName]) > 0:
            statuses = [c.get("status") for c in existingStages[stageName]]

            if all(s == "COMPLETED" for s in statuses):
                return {
                    "message": f"Stage '{stageName}' already completed",
                    "stageStatus": "COMPLETED",
                    "verificationId": str(ver["_id"]),
                    "stages": ver["stages"]
                }

            return {
                "message": f"Stage '{stageName}' already exists and is incomplete",
                "stageStatus": "INCOMPLETE",
                "verificationId": str(ver["_id"]),
                "stages": ver["stages"]
            }

        # ------------------------------------
        # ADD NEW STAGE TO EXISTING VERIFICATION
        # ------------------------------------
        existingStages[stageName] = newChecks

        newStatus = ver.get("overallStatus", "PENDING")
        if newStatus == "COMPLETED":
            newStatus = "PENDING"

        await verificationsCol.update_one(
            {"_id": ver["_id"]},
            {"$set": {
                "stages": existingStages,
                "overallStatus": newStatus,
                "currentStage": stageName
            }}
        )

        return {
            "message": f"Stage '{stageName}' added to existing verification",
            "verificationId": str(ver["_id"]),
            "stage": stageName
        }

    # ======================================================
    # CREATE NEW VERIFICATION DOC
    # ======================================================
    now = datetime.now(timezone.utc).isoformat()

    verificationDoc = {
        "candidateId": candidateId,
        "candidateName": f"{candidate.get('firstName', '')} {candidate.get('lastName', '')}".strip(),
        "organizationId": requestedOrgId,
        "organizationName": organizationName,
        "initiatedBy": userEmail,
        "initiatedAt": now,
        "mode": "MANUAL",
        "stages": {
            "primary": newChecks if stageName == "primary" else [],
            "secondary": newChecks if stageName == "secondary" else [],
            "final": newChecks if stageName == "final" else []
        },
        "currentStage": stageName,
        "overallStatus": "PENDING",
        "assignedTo": str(user.get("_id")),
        "remarks": []
    }


    res = await verificationsCol.insert_one(verificationDoc)

    return {
        "message": f"Verification created with stage '{stageName}'",
        "verificationId": str(res.inserted_id),
        "stage": stageName
    }


@app.post("/secure/runStage")
async def runStage(body: dict = Body(...), user: dict = Depends(requireAuth)):
    """
    Run a verification stage with correct handling for missing data (SKIPPED → FAILED)
    without breaking retry logic or candidate status.
    """

    verificationId = body.get("verificationId")
    stage = body.get("stage")

    if not verificationId or not stage:
        raise HTTPException(status_code=400, detail="verificationId and stage are required")

    # Validate verificationId
    try:
        verObjId = ObjectId(verificationId)
    except:
        raise HTTPException(status_code=400, detail="Invalid verificationId")

    ver = await verificationsCol.find_one({"_id": verObjId})
    if not ver:
        raise HTTPException(status_code=404, detail="Verification not found")

    verificationOrgId = str(ver.get("organizationId"))
    candidateId = ver.get("candidateId")
    initiatedBy = ver.get("initiatedBy", "").lower().strip()

    # Load candidate
    candidate = await candidatesCol.find_one({"_id": ObjectId(candidateId)})

    # -------------------------------------------------------
    # ROLE + ORG ACCESS CONTROL (unchanged)
    # -------------------------------------------------------
    role = user.get("role")
    userEmail = user.get("email", "").lower().strip()
    userOrgId = str(user.get("organizationId"))
    accessible = [str(x) for x in user.get("accessibleOrganizations", [])]

    allowed = False

    # SUPER ADMIN → full access
    if role in ["SUPER_ADMIN", "SUPER_SPOC"]:
        allowed = True
    elif role == "SPOC" and ("@bgv.local" in userEmail or "bgvapp.in" in userEmail):
        allowed = True
    elif role == "SUPER_ADMIN_HELPER":
        if verificationOrgId in accessible:
            allowed = True
    elif role in ["ORG_HR", "SPOC"]:
        if verificationOrgId == userOrgId and initiatedBy == userEmail:
            allowed = True
    elif role == "HELPER":
        if(
            verificationOrgId == userOrgId and
            candidate.get("createdBy", "").lower().strip() == userEmail and
            initiatedBy == userEmail
        ):
            allowed = True

    if not allowed:
        raise HTTPException(status_code=403, detail="You are not authorized to run this stage")

    # -------------------------------------------------------
    # VALIDATE STAGE EXISTS
    # -------------------------------------------------------
    stageChecks = ver.get("stages", {}).get(stage)
    if stageChecks is None:
        raise HTTPException(status_code=404, detail=f"Stage '{stage}' not found")

    # -------------------------------------------------------
    # BLOCK STAGE JUMPING (unchanged)
    # -------------------------------------------------------
    stagesExisting = ver.get("stages", {})
    if stage == "secondary" and "primary" not in stagesExisting:
        raise HTTPException(status_code=403, detail="Primary stage must be completed first")

    if stage == "final" and "secondary" not in stagesExisting:
        raise HTTPException(status_code=403, detail="Secondary stage must be completed first")

    # -------------------------------------------------------
    # RUN THE CHECKS
    # -------------------------------------------------------
    for idx, ch in enumerate(stageChecks):

        checkName = ch.get("check")
        currentStatus = (ch.get("status") or "NOT_STARTED").upper()

        if currentStatus == "COMPLETED":
            continue

        # Mark IN_PROGRESS
        await verificationsCol.update_one(
            {"_id": verObjId},
            {"$set": {
                f"stages.{stage}.{idx}.status": "IN_PROGRESS",
                "currentStage": stage
            }}
        )

        # -----------------------------------------
        # RUN actual verification (your real API)
        # -----------------------------------------
        status, remarks = await run_verification(checkName, candidate)
        # LOG THE VERIFICATION CALL HERE
        await logActivity(
            user,
            "Verification Check Executed",
            f"Check: {checkName} | Stage: {stage} | Status: {status} | Remarks: {remarks}",
            "Success" if status == "COMPLETED" else "Failed"
        )

        # =========================================
        # 🟥 NEW: MISSING DATA → FAIL BUT SAFE
        # =========================================
        if status == "SKIPPED":
            # Mark FAILED (so retry works)
            await verificationsCol.update_one(
                {"_id": verObjId},
                {"$set": {
                    f"stages.{stage}.{idx}.status": "FAILED",
                    f"stages.{stage}.{idx}.remarks": f"Missing required data: {remarks}",
                    f"stages.{stage}.{idx}.submittedAt": datetime.now(timezone.utc).isoformat()
                }}
            )

            # STOP THE STAGE (same as failed)
            await verificationsCol.update_one(
                {"_id": verObjId},
                {"$set": {
                    "overallStatus": "FAILED",
                    "failureStage": f"{stage}_{checkName}",
                    "currentStage": stage
                }}
            )

            return {
                "message": "Check failed (missing required data)",
                "failedCheck": checkName,
                "status": "FAILED"
            }

        # =========================================
        # ✔ SUCCESS OR REAL FAILURE
        # =========================================
        await verificationsCol.update_one(
            {"_id": verObjId},
            {"$set": {
                f"stages.{stage}.{idx}.status": status,
                f"stages.{stage}.{idx}.remarks": remarks,
                f"stages.{stage}.{idx}.submittedAt": datetime.now(timezone.utc).isoformat()
            }}
        )

        # REAL FAILURE → STOP
        if status == "FAILED":
            await verificationsCol.update_one(
                {"_id": verObjId},
                {"$set": {
                    "overallStatus": "FAILED",
                    "failureStage": f"{stage}_{checkName}",
                    "currentStage": stage
                }}
            )
            await candidatesCol.update_one(
                {"_id": ObjectId(candidateId)},
                {"$set": {"status": f"FAILED_AT_{stage}_{checkName}"}}
            )
            return {
                "message": "Check failed",
                "failedCheck": checkName,
                "status": "FAILED"
            }

    # -------------------------------------------------------
    # FINAL STAGE FULL COMPLETION
    # -------------------------------------------------------
    verLatest = await verificationsCol.find_one({"_id": verObjId})
    stageChecksLatest = verLatest.get("stages", {}).get(stage, [])

    stageCompletedNow = len(stageChecksLatest) > 0 and all(
        ch.get("status") == "COMPLETED" for ch in stageChecksLatest
    )

    if stage == "final" and stageCompletedNow:
        await verificationsCol.update_one(
            {"_id": verObjId},
            {"$set": {
                "overallStatus": "COMPLETED",
                "currentStage": "final",
                "failureStage": None
            }}
        )

        await candidatesCol.update_one(
            {"_id": ObjectId(candidateId)},
            {"$set": {"status": "VERIFIED"}}
        )

        return {
            "message": "Verification COMPLETED",
            "stage": "final",
            "verificationId": verificationId,
            "overallStatus": "COMPLETED"
        }

    # -------------------------------------------------------
    # NORMAL STAGE COMPLETION
    # -------------------------------------------------------
    await verificationsCol.update_one(
        {"_id": verObjId},
        {"$set": {
            "currentStage": stage,
            "overallStatus": "IN_PROGRESS"
        }}
    )

    return {"message": "Stage completed", "stage": stage, "verificationId": verificationId}

@app.post("/secure/retryCheck")
async def retryCheck(body: dict = Body(...), user: dict = Depends(requireAuth)):

    verificationId = body.get("verificationId")
    stage = body.get("stage")
    checkKey = body.get("check")

    if not verificationId or not stage or not checkKey:
        raise HTTPException(status_code=400, detail="verificationId, stage and check are required")

    try:
        verObjId = ObjectId(verificationId)
    except:
        raise HTTPException(status_code=400, detail="Invalid verificationId")

    ver = await verificationsCol.find_one({"_id": verObjId})
    if not ver:
        raise HTTPException(status_code=404, detail="Verification not found")

    stageChecks = ver.get("stages", {}).get(stage)
    if stageChecks is None:
        raise HTTPException(status_code=404, detail="Stage not found")

    # --------------------------------------
    # Locate Check Index
    # --------------------------------------
    idx = None
    for i, ch in enumerate(stageChecks):
        if ch.get("check") == checkKey:
            idx = i
            break

    if idx is None:
        raise HTTPException(status_code=404, detail="Check not found in stage")

    currentStatus = stageChecks[idx].get("status", "NOT_STARTED").upper()

    if currentStatus != "FAILED":
        return JSONResponse(status_code=400, content={
            "message": "Check is not in FAILED state and cannot be retried",
            "currentStatus": currentStatus
        })

    # --------------------------------------
    # ROLE VALIDATION
    # --------------------------------------
    verificationOrgId = str(ver.get("organizationId", ""))
    userEmail = user.get("email", "").lower().strip()
    accessibleOrgs = [str(x) for x in user.get("accessibleOrganizations", [])]
    role = user.get("role")

    if role in ["SUPER_ADMIN", "SUPER_SPOC"]:
        pass
    elif role == "SPOC" and ("@bgv.local" in userEmail or "bgvapp.in" in userEmail):
        pass
    elif role == "SUPER_ADMIN_HELPER":
        if verificationOrgId not in accessibleOrgs:
            raise HTTPException(status_code=403, detail="Not authorized for this organization")
    elif role in ["ORG_HR", "SPOC"]:
        if verificationOrgId != str(user.get("organizationId")):
            raise HTTPException(status_code=403, detail="You can only retry checks in your organization")
    elif role == "HELPER":
        if ver.get("initiatedBy", "").lower().strip() != userEmail:
            raise HTTPException(status_code=403, detail="You can only retry checks you initiated")
    else:
        raise HTTPException(status_code=403, detail="Not authorized to retry checks")

    # --------------------------------------
    # Mark IN_PROGRESS
    # --------------------------------------
    await verificationsCol.update_one(
        {"_id": verObjId},
        {"$set": {
            f"stages.{stage}.{idx}.status": "IN_PROGRESS",
            f"stages.{stage}.{idx}.submittedAt": datetime.now(timezone.utc).isoformat()
        }}
    )

    # --------------------------------------
    # Run Verification
    # --------------------------------------
    candidate = await candidatesCol.find_one({"_id": ObjectId(ver["candidateId"])})

    try:
        status, remarks = await run_verification(checkKey, candidate)

        # 🔥 ADDING LOG
        await logActivity(
            user,
            "Retry Check Executed",
            f"Check: {checkKey} | Stage: {stage} | Result: {status} | Remarks: {remarks}",
            "Success" if status == "COMPLETED" else "Failed"
        )

    except Exception as e:
        status, remarks = "FAILED", f"Runtime error: {str(e)}"

        await logActivity(
            user,
            "Retry Check Error",
            f"Check: {checkKey} | Stage: {stage} | Error: {e}",
            "Error"
        )

    # --------------------------------------
    # Update check result
    # --------------------------------------
    await verificationsCol.update_one(
        {"_id": verObjId},
        {"$set": {
            f"stages.{stage}.{idx}.status": status,
            f"stages.{stage}.{idx}.remarks": remarks,
            f"stages.{stage}.{idx}.submittedAt": datetime.now(timezone.utc).isoformat()
        }}
    )

    # ========================================================
    # SKIPPED = FAILED
    # ========================================================
    if status == "SKIPPED":
        status = "FAILED"
        remarks = f"Missing data: {remarks}"

    # ========================================================
    # FAILED AGAIN → STOP
    # ========================================================
    if status == "FAILED":

        await verificationsCol.update_one(
            {"_id": verObjId},
            {"$set": {
                "overallStatus": "FAILED",
                "failureStage": f"{stage}_{checkKey}"
            }}
        )

        await candidatesCol.update_one(
            {"_id": ObjectId(ver["candidateId"])},
            {"$set": {"status": f"FAILED_AT_{stage}_{checkKey}"}}
        )

        return {
            "check": checkKey,
            "status": "FAILED",
            "remarks": remarks,
            "canProceed": False
        }

    # ========================================================
    # SUCCESS PATH
    # ========================================================
    await verificationsCol.update_one(
        {"_id": verObjId},
        {"$set": {
            "overallStatus": "IN_PROGRESS",
            "failureStage": None
        }}
    )

    verLatest = await verificationsCol.find_one({"_id": verObjId})
    stageAll = verLatest.get("stages", {}).get(stage, [])

    stageDone = len(stageAll) > 0 and all(ch.get("status") == "COMPLETED" for ch in stageAll)

    if stageDone:

        if stage == "final":
            await verificationsCol.update_one(
                {"_id": verObjId},
                {"$set": {
                    "overallStatus": "COMPLETED",
                    "currentStage": "final",
                    "failureStage": None
                }}
            )

            await candidatesCol.update_one(
                {"_id": ObjectId(ver["candidateId"])},
                {"$set": {"status": "VERIFIED"}}
            )

            return {
                "check": checkKey,
                "status": "COMPLETED",
                "finalStageCompleted": True,
                "canProceed": True
            }

        await verificationsCol.update_one(
            {"_id": verObjId},
            {"$set": {
                "overallStatus": "IN_PROGRESS",
                "currentStage": stage,
                "failureStage": None
            }}
        )

        return {
            "check": checkKey,
            "status": "COMPLETED",
            "stageCompleted": True,
            "canProceed": True
        }

    return {
        "check": checkKey,
        "status": status,
        "remarks": remarks,
        "canProceed": False
    }


@app.post("/secure/candidate/uploadResume")
async def uploadResume(
    candidateId: str = Form(...),
    resume: UploadFile = File(...),
    user: dict = Depends(requireAuth)
):
    try:
        objId = ObjectId(candidateId)
    except:
        raise HTTPException(400, "Invalid candidateId")

    candidate = await candidatesCol.find_one({"_id": objId})
    if not candidate:
        raise HTTPException(404, "Candidate not found")

    ext = resume.filename.split(".")[-1].lower()
    if ext not in ["pdf", "docx"]:
        raise HTTPException(400, "Only PDF/DOCX allowed")

    savePath = f"/mnt/resumes/{candidateId}.{ext}"

    with open(savePath, "wb") as f:
        f.write(await resume.read())

    await candidatesCol.update_one(
        {"_id": objId},
        {"$set": {"resumePath": savePath}}
    )

    await logActivity(
        user,
        "Resume Uploaded",
        f"Candidate={candidateId}, Path={savePath}",
        "Success"
    )

    return {"message": "Resume uploaded successfully", "path": savePath}

from fastapi import APIRouter, Body, HTTPException, Depends, Form, UploadFile, File
from datetime import datetime, timedelta, timezone
from bson import ObjectId
import uuid



# ---------------------------------------------------------
# HELPERS
# ---------------------------------------------------------

def buildChecks(checks: list):
    return [{
        "check": c,
        "status": "NOT_STARTED",
        "remarks": None,
        "attachments": [],
        "submittedAt": None
    } for c in checks]


def get_current_time():
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------
# 1) HUMAN INITIATES A STAGE MANUALLY
# ---------------------------------------------------------
@app.post("/secure/initiateStage")
async def initiateStage(
    body: dict = Body(...),
    user: dict = Depends(requireAuth)
):
    stage = body.get("stage")
    candidateId = body.get("candidateId")
    organizationId = body.get("organizationId")
    checks = body.get("checks", [])

    # -------------------------------------------
    # LOG: START
    # -------------------------------------------
    await logActivity(
        user,
        "Initiate Stage",
        f"Attempting to initiate stage '{stage}' for candidate {candidateId}",
        "Success"
    )

    def buildChecks(chkList):
        return [{
            "check": c,
            "status": "NOT_STARTED",
            "remarks": None,
            "attachments": [],
            "submittedAt": None,
            "metadata": None
        } for c in chkList]

    if len(checks) != len(set(checks)):
        raise HTTPException(400, "Duplicate checks found")

    if not stage or stage not in ["primary", "secondary", "final"]:
        raise HTTPException(400, "Invalid stage")

    if not candidateId or not organizationId:
        raise HTTPException(400, "Missing IDs")

    try:
        candObjId = ObjectId(candidateId)
    except:
        raise HTTPException(400, "Invalid candidateId")

    candidate = await candidatesCol.find_one({"_id": candObjId})
    if not candidate:
        raise HTTPException(404, "Candidate not found")

    org = await orgsCol.find_one({"_id": ObjectId(organizationId)})
    if not org:
        raise HTTPException(404, "Organization not found")

    organizationName = org.get("organizationName")

    ver = await verificationsCol.find_one({
        "candidateId": candidateId,
        "organizationId": organizationId
    })

    if ver:
        if ver.get("overallStatus") in ["COMPLETED", "FAILED"]:
            raise HTTPException(400, "Verification already closed for this candidate")

        if len(ver["stages"].get(stage, [])) > 0:
            raise HTTPException(400, f"Stage '{stage}' already initialized")

        activeStage = ver.get("currentStage")
        if activeStage:
            incomplete = any(c["status"] != "COMPLETED" for c in ver["stages"][activeStage])
            if incomplete:
                raise HTTPException(400, f"Cannot start {stage}, {activeStage} not completed")

    else:
        verDoc = {
            "candidateId": candidateId,
            "candidateName": f"{candidate.get('firstName','')} {candidate.get('lastName','')}".strip(),
            "organizationId": organizationId,
            "organizationName": organizationName,
            "initiatedBy": user.get("email", "").lower(),
            "initiatedAt": get_current_time(),
            "mode": "SELF",
            "stages": {
                "primary": [],
                "secondary": [],
                "final": []
            },
            "currentStage": None,
            "overallStatus": "PENDING",
            "assignedTo": None,
            "remarks": [],
            "failureStage": None,
            "selfLinkExpiresAt": None
        }
        await verificationsCol.insert_one(verDoc)
        ver = await verificationsCol.find_one({
            "candidateId": candidateId,
            "organizationId": organizationId
        })

    verId = ver["_id"]

    used = set()
    for stageName, stageList in ver["stages"].items():
        for c in stageList:
            used.add(c["check"])

    for c in checks:
        if c in used:
            raise HTTPException(400, f"Check '{c}' already used in previous stage")

    newChecks = buildChecks(checks)

    token = str(uuid.uuid4())
    expiresAt = (datetime.now(timezone.utc) + timedelta(hours=24)).isoformat()

    await verificationsCol.update_one(
        {"_id": verId},
        {
            "$set": {
                f"stages.{stage}": newChecks,
                "currentStage": stage,
                "overallStatus": "IN_PROGRESS",
                "selfLinkExpiresAt": expiresAt,
                f"{stage}Token": token,
                "failureStage": None
            }
        }
    )

    # -------------------------------------------
    # LOG: STAGE INITIALIZED
    # -------------------------------------------
    await logActivity(
        user,
        "Stage Initialized",
        f"Stage '{stage}' initialized for candidate {candidateId} | Checks: {checks}",
        "Success"
    )

    candidateEmail = candidate.get("email")
    if not candidateEmail:
        raise HTTPException(400, "Invalid candidate email")

    send_self_verification_email(
        to_email=candidateEmail,
        candidateName=ver["candidateName"],
        organizationName=organizationName,
        stage=stage,
        token=token,
        expiresAt=expiresAt
    )

    # -------------------------------------------
    # LOG: EMAIL SENT
    # -------------------------------------------
    await logActivity(
        user,
        "Self Verification Email Sent",
        f"Email sent to {candidateEmail} for stage '{stage}' with token {token}",
        "Success"
    )

    return {"message": f"{stage} stage initiated", "token": token}

# ---------------------------------------------------------
# 2) CANDIDATE OPENS THE STAGE
# ---------------------------------------------------------
@app.post("/self/verify/start")
async def selfVerifyStart(token: str = Form(...)):
    """
    Candidate starts a stage using token.
    """

    ver = await verificationsCol.find_one({
        "$or": [
            {"primaryToken": token},
            {"secondaryToken": token},
            {"finalToken": token}
        ]
    })

    if not ver:
        raise HTTPException(status_code=404, detail="Invalid token")

    stage = ver["currentStage"]
    if not stage:
        raise HTTPException(status_code=400, detail="No active stage")

    expiresAt = ver.get("selfLinkExpiresAt")
    if not expiresAt:
        raise HTTPException(status_code=500, detail="Missing expiry timestamp")

    expire_dt = datetime.fromisoformat(expiresAt)
    if datetime.now(timezone.utc) > expire_dt:
        raise HTTPException(status_code=410, detail="Link expired")

    return {
        "verificationId": str(ver["_id"]),
        "candidateName": ver["candidateName"],
        "organizationName": ver["organizationName"],
        "stage": stage,
        "checks": ver["stages"][stage]
    }


# ---------------------------------------------------------
# 3) SUBMIT A CHECK
# ---------------------------------------------------------
@app.post("/self/verify/check")
async def submitCheck(
    verificationId: str = Form(...),
    check: str = Form(...),
    metadata: str = Form(None)
):

    try:
        verObjId = ObjectId(verificationId)
    except:
        raise HTTPException(status_code=400, detail="Invalid verificationId")

    ver = await verificationsCol.find_one({"_id": verObjId})
    if not ver:
        raise HTTPException(status_code=404, detail="Verification not found")

    stage = ver["currentStage"]
    stageList = ver["stages"].get(stage, [])

    idx = next((i for i, c in enumerate(stageList) if c["check"] == check), None)
    if idx is None:
        raise HTTPException(status_code=400, detail="Check not found")

    for i in range(idx):
        if stageList[i]["status"] != "COMPLETED":
            raise HTTPException(status_code=400, detail="Previous checks not completed")

    # ------------------------------
    # LOG: Check execution started
    # ------------------------------
    await logActivity(
        None,
        "Self Verification Check Started",
        f"VerificationId={verificationId}, Stage={stage}, Check={check}",
        "Started"
    )

    # Run the actual check
    candidate = await candidatesCol.find_one({"_id": ObjectId(ver["candidateId"])})

    try:
        status, remarks = await run_verification(check, candidate)
    except:
        status, remarks = ("FAILED", "Runtime error")

    if status == "SKIPPED":
        status = "FAILED"
        remarks = f"Missing required data: {remarks}"

    # Update check result
    await verificationsCol.update_one(
        {"_id": verObjId},
        {"$set": {
            f"stages.{stage}.{idx}.status": status,
            f"stages.{stage}.{idx}.remarks": remarks,
            f"stages.{stage}.{idx}.submittedAt": get_current_time(),
            f"stages.{stage}.{idx}.metadata": metadata
        }}
    )

    # ------------------------------
    # LOG: Check completed
    # ------------------------------
    await logActivity(
        None,
        "Self Verification Check Completed",
        f"VerificationId={verificationId}, Stage={stage}, Check={check}, Status={status}, Remarks={remarks}",
        "Success" if status == "COMPLETED" else "Failed"
    )

    # FAILURE path
    if status == "FAILED":
        await verificationsCol.update_one(
            {"_id": verObjId},
            {"$set": {
                "overallStatus": "FAILED",
                "failureStage": f"{stage}_{check}"
            }}
        )
        return {"status": "FAILED", "remarks": remarks}

    # Reload fresh doc
    ver = await verificationsCol.find_one({"_id": verObjId})
    stageList = ver["stages"][stage]

    # --------------------------------------
    #    🟩 COMPLETE FIX FOR STAGE STATUS
    # --------------------------------------
    if all(c["status"] == "COMPLETED" for c in stageList):

        # ❗ FIX: Write stageStatus OUTSIDE the "stages" dict
        await verificationsCol.update_one(
            {"_id": verObjId},
            {"$set": {f"{stage}Status": "COMPLETED"}}
        )

        # ❗ FIX: REMOVE WRONG FIELD IF IT EXISTS
        await verificationsCol.update_one(
            {"_id": verObjId},
            {"$unset": {f"stages.{stage}Status": ""}}
        )

        # ------------------------------
        # LOG: Stage completed
        # ------------------------------
        await logActivity(
            None,
            "Self Verification Stage Completed",
            f"VerificationId={verificationId}, Stage={stage}",
            "Success"
        )

        # FINAL stage fully complete
        if stage == "final":
            await verificationsCol.update_one(
                {"_id": verObjId},
                {"$set": {
                    "overallStatus": "COMPLETED",
                    "currentStage": "final",
                    "failureStage": None
                }}
            )

            await candidatesCol.update_one(
                {"_id": ObjectId(ver["candidateId"])},
                {"$set": {"status": "VERIFIED"}}
            )

    return {"status": status, "remarks": remarks}


# ---------------------------------------------------------
# 4) RETRY FAILED CHECK
# ---------------------------------------------------------
@app.post("/self/verify/retryCheck")
async def retryCheck(
    verificationId: str = Form(...),
    check: str = Form(...),
    metadata: str = Form(None)
):

    try:
        verObjId = ObjectId(verificationId)
    except:
        raise HTTPException(status_code=400, detail="Invalid verificationId")

    ver = await verificationsCol.find_one({"_id": verObjId})
    if not ver:
        raise HTTPException(status_code=404, detail="Not found")

    stage = ver["currentStage"]
    stageList = ver["stages"][stage]

    idx = next((i for i, c in enumerate(stageList) if c["check"] == check), None)
    if idx is None:
        raise HTTPException(status_code=400, detail="Check not found")

    if stageList[idx]["status"] != "FAILED":
        raise HTTPException(status_code=400, detail="Retry allowed only for FAILED checks")

    candidate = await candidatesCol.find_one({"_id": ObjectId(ver["candidateId"])})

    try:
        status, remarks = await run_verification(check, candidate)

        # 🟦 LOG SUCCESSFUL / FAILED API CALL BEFORE SKIPPED HANDLING
        await logActivity(
            None,
            "Self Verification Retry Check Executed",
            f"Check: {check} | Stage: {stage} | Status: {status} | Remarks: {remarks}",
            "Success" if status == "COMPLETED" else "Failed"
        )

    except:
        status, remarks = ("FAILED", "Runtime error")

        # 🟥 LOG RUNTIME FAILURE
        await logActivity(
            None,
            "Self Verification Retry Check Error",
            f"Check: {check} | Stage: {stage} | Error: {remarks}",
            "Failed"
        )

    # 🟦 SKIPPED behaves like FAILED
    if status == "SKIPPED":
        status = "FAILED"
        remarks = f"Missing required data: {remarks}"

    # Update check result
    await verificationsCol.update_one(
        {"_id": verObjId},
        {
            "$set": {
                f"stages.{stage}.{idx}.status": status,
                f"stages.{stage}.{idx}.remarks": remarks,
                f"stages.{stage}.{idx}.submittedAt": get_current_time(),
                f"stages.{stage}.{idx}.metadata": metadata
            }
        }
    )

    # ❌ FAILED again
    if status == "FAILED":
        await verificationsCol.update_one(
            {"_id": verObjId},
            {
                "$set": {
                    "overallStatus": "FAILED",
                    "failureStage": f"{stage}_{check}"
                }
            }
        )
        return {"status": "FAILED", "remarks": remarks}

    # 🟩 SUCCESS path → clear failure state
    await verificationsCol.update_one(
        {"_id": verObjId},
        {
            "$set": {"overallStatus": "IN_PROGRESS"},
            "$unset": {"failureStage": ""}
        }
    )

    # Reload latest doc
    ver = await verificationsCol.find_one({"_id": verObjId})
    stageList = ver["stages"][stage]

    # Stage completed?
    if all(c["status"] == "COMPLETED" for c in stageList):

        await verificationsCol.update_one(
            {"_id": verObjId},
            {"$set": {f"stages.{stage}Status": "COMPLETED"}}
        )

        # 🟩 FINAL STAGE
        if stage == "final":
            await verificationsCol.update_one(
                {"_id": verObjId},
                {
                    "$set": {
                        "overallStatus": "COMPLETED",
                        "currentStage": "final",
                        "failureStage": None
                    }
                }
            )
            await candidatesCol.update_one(
                {"_id": ObjectId(ver["candidateId"])},
                {"$set": {"status": "VERIFIED"}}
            )

    return {"status": status, "remarks": remarks}

# ---------------------------------------------------------
# 5) POLL STATUS
# ---------------------------------------------------------
@app.get("/self/verify/status")
async def status(verificationId: str):
    try:
        vid = ObjectId(verificationId)
    except:
        raise HTTPException(status_code=400, detail="Invalid ID")

    ver = await verificationsCol.find_one({"_id": vid})
    if not ver:
        raise HTTPException(status_code=404, detail="Not found")

    return {
        "verificationId": str(ver["_id"]),
        "currentStage": ver.get("currentStage"),
        "overallStatus": ver.get("overallStatus"),
        "stages": ver.get("stages"),
        "failureStage": ver.get("failureStage")
    }


# from apis import process_verification_record
# from bson import ObjectId

# @app.post("/secure/resumePendingVerifications")
# async def resumePendingVerifications(user: dict = Depends(requireAuth)):
#     """
#     Resume pending or in-progress verifications.
#     Rules:
#       - SUPER_ADMIN → can resume all.
#       - SUPER_ADMIN_HELPER → can resume only from accessible organizations.
#       - Others → forbidden.
#     """
#     role = user.get("role")
#     accessibleOrgs = [str(x) for x in user.get("accessibleOrganizations", [])]

#     # ------------------------------
#     # 🔒 Role-based Access Control
#     # ------------------------------
#     if role not in ["SUPER_ADMIN", "SUPER_ADMIN_HELPER", "SUPER_SPOC"]:
#         raise HTTPException(status_code=403, detail="Not authorized to resume verifications")

#     # ------------------------------
#     # 🎯 Build Query Based on Role
#     # ------------------------------
#     query = {"overallStatus": {"$in": ["IN_PROGRESS", "PENDING"]}}

#     if role == "SUPER_ADMIN_HELPER":
#         if not accessibleOrgs:
#             raise HTTPException(status_code=403, detail="No organizations assigned to helper")
#         query["organizationId"] = {"$in": accessibleOrgs}

#     # ------------------------------
#     # 🔄 Resume Matching Verifications
#     # ------------------------------
#     pending_cursor = verificationsCol.find(query)
#     count = 0

#     async for verification in pending_cursor:
#         try:
#             # Verify candidate still exists
#             candidate = await candidatesCol.find_one({"_id": ObjectId(verification["candidateId"])})
#             if not candidate:
#                 continue

#             # Relaunch background verification task
#             asyncio.create_task(process_verification_record(verification))
#             count += 1

#         except Exception as e:
#             await logActivity(
#                 user,
#                 "Resume Verification Failed",
#                 f"Error resuming verification {verification.get('_id')}: {str(e)}",
#                 "Error"
#             )

#     # ------------------------------
#     # ✅ Response + Activity Log
#     # ------------------------------
#     if count == 0:
#         await logActivity(
#             user,
#             "Resume Verifications",
#             f"No pending verifications found for {role}",
#             "Info"
#         )
#         return {"message": "No pending verifications found"}

#     await logActivity(
#         user,
#         "Resume Verifications",
#         f"{role} resumed {count} verifications",
#         "Success"
#     )

#     return {"message": f"Resumed {count} pending verifications"}

# ============================================================
#                SELF VERIFICATION MODULE (V2)
# ============================================================

from fastapi import Body, Form, File, UploadFile, HTTPException
from fastapi.responses import JSONResponse
from bson import ObjectId
from datetime import datetime, timedelta, timezone

# IMPORTANT: Requires send_self_verification_email() imported from utils
# from utils.email_utils import send_self_verification_email

# ------------------------------------------------------------
# 1) ADMIN INITIATES SELF VERIFICATION
# ------------------------------------------------------------
# @app.post("/secure/self/initiate")
# async def initiateSelfVerificationV2(body: dict = Body(...), user: dict = Depends(requireAuth)):
#     """
#     Admin initiates self verification (PRIMARY → SECONDARY → FINAL).
#     Sends an email containing candidateId, orgId, email, Aadhaar last4.
#     """

#     role = user.get("role")
#     userEmail = user.get("email", "").lower().strip()

#     candidateId = body.get("candidateId")
#     requestedOrgId = body.get("organizationId")
#     stages = body.get("stages", {})

#     if not candidateId or not stages:
#         raise HTTPException(status_code=400, detail="candidateId and stages required")

#     # ---- Validate candidate ----
#     try:
#         cid = ObjectId(candidateId)
#     except:
#         raise HTTPException(status_code=400, detail="Invalid candidateId")

#     candidate = await candidatesCol.find_one({"_id": cid})
#     if not candidate:
#         raise HTTPException(status_code=404, detail="Candidate not found")

#     candidateOrgId = str(candidate.get("organizationId"))

#     # ---- Resolve organization by role ----
#     organizationId = None

#     if role in ["SUPER_ADMIN", "SUPER_SPOC"]:
#         organizationId = requestedOrgId or candidateOrgId

#     elif role == "SUPER_ADMIN_HELPER":
#         accessible = [str(x) for x in user.get("accessibleOrganizations", [])]
#         sel = requestedOrgId or candidateOrgId
#         if sel not in accessible:
#             raise HTTPException(status_code=403, detail="Not allowed for this organization")
#         organizationId = sel

#     elif role in ["ORG_HR", "SPOC"]:
#         if candidateOrgId != str(user.get("organizationId")):
#             raise HTTPException(status_code=403, detail="Candidate not in your org")
#         organizationId = candidateOrgId

#     elif role == "HELPER":
#         if candidate.get("createdBy", "").lower().strip() != userEmail:
#             raise HTTPException(status_code=403, detail="Not your candidate")
#         organizationId = candidateOrgId

#     else:
#         raise HTTPException(status_code=403, detail="Not authorized")

#     org = await orgsCol.find_one({"_id": ObjectId(organizationId)})
#     if not org:
#         raise HTTPException(status_code=404, detail="Organization not found")

#     organizationName = org.get("organizationName")

#     # ---- Prevent duplicate active self verification ----
#     existing = await verificationsCol.find_one({
#         "candidateId": candidateId,
#         "organizationId": organizationId,
#         "mode": "SELF",
#         "overallStatus": {"$in": ["PENDING", "IN_PROGRESS"]}
#     })
#     if existing:
#         raise HTTPException(status_code=409, detail="Self verification already started for this candidate")

#     # ---- Build stage structure ----
#     def buildChecks(stageList):
#         return [{
#             "check": c,
#             "status": "NOT_STARTED",
#             "remarks": None,
#             "attachments": [],
#             "submittedAt": None
#         } for c in stageList]

#     primary = buildChecks(stages.get("primary", []))
#     secondary = buildChecks(stages.get("secondary", []))
#     final = buildChecks(stages.get("final", []))

#     now = datetime.now(timezone.utc).isoformat()
#     expiresAt = datetime.now(timezone.utc) + timedelta(hours=24)

#     verificationDoc = {
#         "candidateId": candidateId,
#         "candidateName": f"{candidate.get('firstName','')} {candidate.get('lastName','')}".strip(),
#         "organizationId": organizationId,
#         "organizationName": organizationName,
#         "initiatedBy": userEmail,
#         "initiatedAt": now,
#         "mode": "SELF",
#         "stages": {
#             "primary": primary,
#             "secondary": secondary,
#             "final": final
#         },
#         "currentStage": "primary",
#         "overallStatus": "PENDING",
#         "assignedTo": None,
#         "remarks": [],
#         "selfInfo": {
#             "enabled": True,
#             "expiresAt": expiresAt.isoformat(),
#             "initiatedBy": userEmail,
#             "startedAt": None,
#             "lastActivity": None,
#             "adminOverrideAllowed": True,
#             "candidateCanVerify": True
#         }
#     }

#     res = await verificationsCol.insert_one(verificationDoc)

#     # ---- Send email ----
#     try:
#         email = candidate.get("email")
#         if not email:
#             raise Exception("Invalid candidate email")

#         aadhaar = candidate.get("aadhaarNumber", "XXXX")
#         last4 = aadhaar[-4:]

#         send_self_verification_email(
#             to_email=email,
#             candidateName=verificationDoc["candidateName"],
#             organizationName=organizationName,
#             candidateId=candidateId,
#             organizationId=organizationId,
#             aadhaarLast4=last4
#         )

#     except Exception as e:
#         await verificationsCol.delete_one({"_id": res.inserted_id})
#         raise HTTPException(status_code=500, detail=f"Email send failed: {str(e)}")

#     return {"message": "Self verification initiated", "verificationId": str(res.inserted_id)}


# ------------------------------------------------------------
# 2) CANDIDATE STARTS SELF VERIFICATION
# ------------------------------------------------------------
# @app.post("/self/start")
# async def selfVerifyStartV2(
#     candidateId: str = Form(...),
#     organizationId: str = Form(...),
#     email: str = Form(...),
#     aadhaarLast4: str = Form(...)
# ):
#     """Candidate authenticates using 4 values from the email."""
    
#     try:
#         cid = ObjectId(candidateId)
#     except:
#         raise HTTPException(status_code=400, detail="Invalid candidateId")

#     cand = await candidatesCol.find_one({"_id": cid})
#     if not cand:
#         raise HTTPException(status_code=404, detail="Candidate not found")

#     if str(cand.get("organizationId")) != organizationId:
#         raise HTTPException(status_code=403, detail="Organization mismatch")

#     if cand.get("email", "").lower().strip() != email.lower().strip():
#         raise HTTPException(status_code=403, detail="Email mismatch")

#     aadhaar = cand.get("aadhaarNumber", "")
#     if not aadhaar.endswith(aadhaarLast4):
#         raise HTTPException(status_code=403, detail="Aadhaar last4 mismatch")

#     # Fetch verification doc
#     ver = await verificationsCol.find_one({
#         "candidateId": candidateId,
#         "organizationId": organizationId,
#         "mode": "SELF"
#     })
#     if not ver:
#         raise HTTPException(status_code=404, detail="Verification not found")

#     # Check expiry
#     expires = ver.get("selfInfo", {}).get("expiresAt")
#     if not expires:
#         raise HTTPException(status_code=500, detail="Invalid verification state")

#     expiry_dt = datetime.fromisoformat(expires)

#     if datetime.now(timezone.utc) > expiry_dt:
#         raise HTTPException(status_code=410, detail="Verification link expired. Contact HR.")

#     # Start verification
#     await verificationsCol.update_one(
#         {"_id": ver["_id"]},
#         {"$set": {
#             "overallStatus": "IN_PROGRESS",
#             "selfInfo.startedAt": datetime.now(timezone.utc).isoformat()
#         }}
#     )

#     safe = {
#         "verificationId": str(ver["_id"]),
#         "candidateName": ver["candidateName"],
#         "organizationName": ver["organizationName"],
#         "currentStage": ver["currentStage"],
#         "overallStatus": "IN_PROGRESS",
#         "stages": ver["stages"],
#         "expiresAt": expires
#     }
#     return safe


# # ------------------------------------------------------------
# # 3) CANDIDATE SUBMITS CHECK
# # ------------------------------------------------------------
# @app.post("/self/check")
# async def selfVerifyCheckV2(
#     verificationId: str = Form(...),
#     stage: str = Form(...),
#     check: str = Form(...),
#     metadata: str = Form(None),
#     file: UploadFile = File(None)
# ):
#     """Candidate uploads text or file for a check."""

#     try:
#         vid = ObjectId(verificationId)
#     except:
#         raise HTTPException(status_code=400, detail="Invalid verificationId")

#     ver = await verificationsCol.find_one({"_id": vid})
#     if not ver:
#         raise HTTPException(status_code=404, detail="Verification not found")

#     if ver.get("overallStatus") != "IN_PROGRESS":
#         raise HTTPException(status_code=403, detail="Verification not active")

#     if stage != ver.get("currentStage"):
#         raise HTTPException(status_code=403, detail="Stage mismatch")

#     stageList = ver["stages"].get(stage, [])
#     idx = next((i for i, c in enumerate(stageList) if c["check"] == check), None)
#     if idx is None:
#         raise HTTPException(status_code=400, detail="Check not found")

#     # Block if prior failed
#     for p in stageList[:idx]:
#         if p["status"] == "FAILED":
#             raise HTTPException(status_code=403, detail="Previous check failed")

#     # File handling (you may later upload to S3)
#     attachment = None
#     if file:
#         content = await file.read()
#         attachment = {
#             "filename": file.filename,
#             "size": len(content),
#             "contentType": file.content_type,
#             "uploadedAt": datetime.now(timezone.utc).isoformat()
#         }

#     # Run verification check via your existing engine
#     candidate = await candidatesCol.find_one({"_id": ObjectId(ver["candidateId"])})
#     try:
#         status, remarks = await run_verification(check, candidate)
#     except Exception as e:
#         status, remarks = "FAILED", f"Runtime error: {str(e)}"

#     # Update check entry
#     update = {
#         f"stages.{stage}.{idx}.status": status,
#         f"stages.{stage}.{idx}.remarks": remarks,
#         f"stages.{stage}.{idx}.submittedAt": datetime.now(timezone.utc).isoformat(),
#         "selfInfo.lastActivity": datetime.now(timezone.utc).isoformat()
#     }
#     if attachment:
#         update[f"stages.{stage}.{idx}.attachments"] = [attachment]

#     await verificationsCol.update_one({"_id": vid}, {"$set": update})

#     # If failed → stop
#     if status == "FAILED":
#         await verificationsCol.update_one(
#             {"_id": vid},
#             {"$set": {"overallStatus": "FAILED", "failureStage": f"{stage}_{check}"}}
#         )
#         return {"status": status, "remarks": remarks}

#     # If stage fully complete, move forward
#     fresh = await verificationsCol.find_one({"_id": vid})
#     allChecks = fresh["stages"][stage]

#     if all(c["status"] == "COMPLETED" for c in allChecks):

#         nextStage = None

#         if stage == "primary":
#             nextStage = "secondary" if fresh["stages"].get("secondary") else "final"

#         elif stage == "secondary":
#             nextStage = "final"

#         if nextStage:
#             await verificationsCol.update_one(
#                 {"_id": vid},
#                 {"$set": {"currentStage": nextStage}}
#             )
#         else:
#             await verificationsCol.update_one(
#                 {"_id": vid},
#                 {"$set": {"overallStatus": "COMPLETED"}}
#             )
#             await candidatesCol.update_one(
#                 {"_id": ObjectId(ver["candidateId"])},
#                 {"$set": {"status": "VERIFIED"}}
#             )

#     return {"status": status, "remarks": remarks}


# ------------------------------------------------------------
# 4) ADMIN OVERRIDE: RUN STAGE MANUALLY
# ------------------------------------------------------------
# @app.post("/secure/self/runStage")
# async def adminRunSelfStage(body: dict = Body(...), user: dict = Depends(requireAuth)):
#     """
#     Admin manually runs a stage for SELF verification.
#     Only allowed if:
#         - Candidate has not completed stage
#         - Admin belongs to that org (or super admin)
#     """

#     verificationId = body.get("verificationId")
#     stage = body.get("stage")
#     if not verificationId or not stage:
#         raise HTTPException(status_code=400, detail="verificationId and stage required")

#     try:
#         vid = ObjectId(verificationId)
#     except:
#         raise HTTPException(status_code=400, detail="Invalid verificationId")

#     ver = await verificationsCol.find_one({"_id": vid})
#     if not ver:
#         raise HTTPException(status_code=404, detail="Not found")

#     # ---- Role Authorization ----
#     role = user.get("role")
#     userEmail = user.get("email", "").lower().strip()
#     userOrg = str(user.get("organizationId", ""))

#     verOrg = ver.get("organizationId")

#     allowed = False

#     if role in ["SUPER_ADMIN", "SUPER_SPOC"]:
#         allowed = True
#     elif role == "SUPER_ADMIN_HELPER":
#         if verOrg in [str(x) for x in user.get("accessibleOrganizations", [])]:
#             allowed = True
#     elif role == "SPOC" and ("@bgv.local" in userEmail or "bgvapp.in" in userEmail):
#         allowed = True
#     elif role == "ORG_HR" and verOrg == userOrg:
#         allowed = True
#     elif role == "HELPER":
#         # only if created by the helper
#         cand = await candidatesCol.find_one({"_id": ObjectId(ver["candidateId"])})
#         if cand and cand.get("createdBy", "").lower().strip() == userEmail:
#             allowed = True

#     if not allowed:
#         raise HTTPException(status_code=403, detail="Not authorized to run this stage")

#     # ---- Check stage exists ----
#     stageChecks = ver.get("stages", {}).get(stage)
#     if not stageChecks:
#         raise HTTPException(status_code=404, detail=f"Stage '{stage}' not found")

#     # ---- If already completed ----
#     if all(c["status"] == "COMPLETED" for c in stageChecks):
#         return {"message": f"Stage '{stage}' already completed"}

#     # Run each check
#     for idx, chk in enumerate(stageChecks):
#         checkName = chk["check"]
#         if chk["status"] == "COMPLETED":
#             continue

#         try:
#             status, remarks = await run_verification(checkName, await candidatesCol.find_one({"_id": ObjectId(ver["candidateId"])}))
#         except Exception as e:
#             status, remarks = "FAILED", f"Runtime error: {str(e)}"

#         update = {
#             f"stages.{stage}.{idx}.status": status,
#             f"stages.{stage}.{idx}.remarks": remarks,
#             f"stages.{stage}.{idx}.submittedAt": datetime.now(timezone.utc).isoformat()
#         }
#         await verificationsCol.update_one({"_id": vid}, {"$set": update})

#         if status == "FAILED":
#             await verificationsCol.update_one(
#                 {"_id": vid},
#                 {"$set": {"overallStatus": "FAILED", "failureStage": f"{stage}_{checkName}"}}
#             )
#             return {"message": "Stage failed", "failedCheck": checkName}

#     # Mark stage completed
#     await verificationsCol.update_one(
#         {"_id": vid},
#         {"$set": {"currentStage": stage, "overallStatus": "IN_PROGRESS"}}
#     )

#     return {"message": "Stage completed by admin", "stage": stage}


# ------------------------------------------------------------
# 5) STATUS POLLING
# ------------------------------------------------------------
@app.get("/self/status")
async def selfVerifyStatusV2(verificationId: str):
    try:
        vid = ObjectId(verificationId)
    except:
        raise HTTPException(status_code=400, detail="Invalid ID")

    ver = await verificationsCol.find_one({"_id": vid})
    if not ver:
        raise HTTPException(status_code=404, detail="Not found")

    return {
        "verificationId": str(ver["_id"]),
        "candidateName": ver["candidateName"],
        "organizationName": ver["organizationName"],
        "currentStage": ver["currentStage"],
        "overallStatus": ver["overallStatus"],
        "stages": ver["stages"],
        "failureStage": ver.get("failureStage"),
        "selfInfo": ver.get("selfInfo")
    }


@app.post("/secure/addCandidate")
async def addCandidate(body: dict = Body(...), user: dict = Depends(requireAuth)):
    role = user.get("role")
    creatorEmail = user.get("email")
    accessibleOrgs = user.get("accessibleOrganizations", [])
    orgId = None
    orgName = None

    # ---------------------------------------------
    # EXTRACT FIELDS (added new fields)
    # ---------------------------------------------
    firstName = body.get("firstName")
    middleName = body.get("middleName")
    lastName = body.get("lastName")
    phone = body.get("phone")
    aadhaarNumber = body.get("aadhaarNumber")
    panNumber = body.get("panNumber")
    address = body.get("address")
    inputOrgId = body.get("organizationId")
    candidateEmail = body.get("email")

    # NEW FIELDS
    fatherName = body.get("fatherName")
    dob = body.get("dob")
    gender = body.get("gender")
    uanNumber = body.get("uanNumber")
    district = body.get("district")
    state = body.get("state")
    pincode = body.get("pincode")

    # ---------------------------------------------
    # VALIDATION
    # ---------------------------------------------
    requiredFields = [
        firstName,
        lastName,
        phone,
        aadhaarNumber,
        panNumber,
        address,
        candidateEmail,
        fatherName,
        dob,
        gender,
        district,
        state,
        pincode
    ]

    if not all(requiredFields):
        raise HTTPException(status_code=400, detail="Missing required candidate details")

    # ------------------------
    # 🔐 Role-based conditions
    # ------------------------

    # 1️⃣ SUPER_ADMIN / BGV SPOC → any org
    if role in ["SUPER_ADMIN", "SUPER_SPOC"]:
        orgId = inputOrgId or user.get("organizationId")
        if not orgId:
            raise HTTPException(status_code=400, detail="Organization ID required for Super Admin")
        org = await orgsCol.find_one({"_id": ObjectId(orgId)})
        if not org:
            raise HTTPException(status_code=404, detail="Organization not found")
        orgName = org.get("organizationName")

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

    elif role in ["ORG_HR", "SPOC"]:
        orgId = user.get("organizationId")
        if not orgId:
            raise HTTPException(status_code=400, detail="Organization ID missing for HR/SPOC")

        org = await orgsCol.find_one({"_id": ObjectId(orgId)})
        if not org:
            raise HTTPException(status_code=404, detail="Organization not found")

        orgName = org.get("organizationName")

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

    # ---------------------------------------------
    # DUPLICATE CHECK (same as before)
    # ---------------------------------------------
    existing = await candidatesCol.find_one({
        "organizationId": orgId,
        "$or": [
            {"aadhaarNumber": aadhaarNumber},
            {"panNumber": panNumber},
            {"email": candidateEmail}
        ]
    })

    if existing:
        raise HTTPException(
            status_code=409,
            detail=f"Candidate with Aadhaar/PAN/email already exists in {orgName}"
        )

    # ---------------------------------------------
    # INSERT CANDIDATE (added new fields)
    # ---------------------------------------------
    now = datetime.now(timezone.utc).isoformat()

    candidateDoc = {
        "firstName": firstName,
        "middleName": middleName,
        "lastName": lastName,
        "phone": phone,
        "aadhaarNumber": aadhaarNumber,
        "panNumber": panNumber,
        "address": address,
        "fatherName": fatherName,
        "dob": dob,
        "gender": gender,
        "uanNumber": uanNumber,
        "district": district,
        "state": state,
        "pincode": pincode,
        "organizationId": orgId,
        "organizationName": orgName,
        "status": "PENDING",
        "createdAt": now,
        "createdBy": creatorEmail,
        "email": candidateEmail
    }

    if not orgId:
        raise HTTPException(status_code=400, detail="Internal error: missing organizationId before insert")

    result = await candidatesCol.insert_one(candidateDoc)
    if not result or not result.inserted_id:
        raise HTTPException(status_code=500, detail="Candidate insert failed (no ID returned)")

    candidateDoc["_id"] = str(result.inserted_id)

    await logActivity(
        user,
        "Add Candidate",
        f"{creatorEmail} added candidate {firstName} {lastName} to {orgName}",
        "Success"
    )

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
    role = user.get("role")
    userOrgId = str(user.get("organizationId"))
    accessibleOrgs = [str(x) for x in user.get("accessibleOrganizations", [])]

    # -----------------------------------------
    # ROLE-BASED ACCESS RESTRICTION
    # -----------------------------------------

    # HELPER → NOT ALLOWED
    if role == "HELPER":
        raise HTTPException(status_code=403, detail="You are not allowed to view logs")

    query = {}

    # SUPER_ADMIN & SUPER_SPOC → full access
    if role in ["SUPER_ADMIN", "SUPER_SPOC"]:
        pass  # no filter

    # SUPER_ADMIN_HELPER → only assigned orgs
    elif role == "SUPER_ADMIN_HELPER":
        if not accessibleOrgs:
            raise HTTPException(403, "No organizations assigned")
        query["organizationId"] = {"$in": accessibleOrgs}

    # ORG_HR & SPOC → only their own org logs
    elif role in ["ORG_HR", "SPOC"]:
        query["organizationId"] = userOrgId

    # Unknown roles → block
    else:
        raise HTTPException(status_code=403, detail="You are not allowed to view logs")

    # -----------------------------------------
    # EXECUTE QUERY
    # -----------------------------------------
    cursor = activityLogsCol.find(query).sort("timestamp", -1)
    logs = await cursor.to_list()

    # Convert ObjectIds to string
    for log in logs:
        if "_id" in log:
            log["_id"] = str(log["_id"])
        if "userId" in log and isinstance(log["userId"], ObjectId):
            log["userId"] = str(log["userId"])
        if "organizationId" in log and isinstance(log["organizationId"], ObjectId):
            log["organizationId"] = str(log["organizationId"])

    return JSONResponse(
        status_code=200,
        content=jsonable_encoder({
            "totalLogs": len(logs),
            "logs": logs
        })
    )

# get specific logs
@app.get("/secure/recentImportantActivity")
async def getRecentImportantActivity(
    noOfLogs: int = 50,
    user: dict = Depends(requireAuth)
):

    IMPORTANT_LOG_TYPES = [
        "Add Candidate",
        "Self Verification Email Sent",
        "Verification Check Executed",
        "New Verification Initiated",
        "Add User",
        "Add Organization",
        "Update Verification Status",
        "Unauthorized Attempt",
        "Error",
        "Add Candidate",
        "Stage Initialized",
        "Login",
        "Logout",
        "Password Reset Failed",
        "Update Organization Failed",
        "Updated Organization",
        "Add Helper Failed",
        "Added Helper User",
        "Updated User",
        "Delete Candidate",
        "Edit Candidate",
        "Run Stage Failed",
        "Retry Check",
        "Upload Logo Failed",
        "Register Organization Failed",
        "Created Organization"
    ]

    role = user.get("role")
    userOrgId = str(user.get("organizationId"))
    accessibleOrgs = [str(o) for o in user.get("accessibleOrganizations", [])]

    query = {
        "action": {"$in": IMPORTANT_LOG_TYPES}
    }

    # -----------------------------------------
    # HELPER → NOT ALLOWED
    # -----------------------------------------
    if role == "HELPER":
        raise HTTPException(
            status_code=403,
            detail="You are not allowed to view logs"
        )

    # -----------------------------------------
    # SUPER_ADMIN + SUPER_SPOC → FULL ACCESS
    # -----------------------------------------
    if role in ["SUPER_ADMIN", "SUPER_SPOC"]:
        pass  # no org restrictions

    # -----------------------------------------
    # SUPER_ADMIN_HELPER → ONLY ACCESSIBLE ORGS
    # -----------------------------------------
    elif role == "SUPER_ADMIN_HELPER":

        if not accessibleOrgs:
            raise HTTPException(403, "No organizations assigned to this helper")

        objIds = []
        for oid in accessibleOrgs:
            try:
                objIds.append(ObjectId(oid))
            except:
                pass

        # Match logs with organizationId as string OR objectId
        query["$or"] = [
            {"organizationId": {"$in": accessibleOrgs}},   # string storage
            {"organizationId": {"$in": objIds}}            # ObjectId storage
        ]

    # -----------------------------------------
    # ORG_HR / SPOC → ONLY THEIR ORG
    # -----------------------------------------
    elif role in ["ORG_HR", "SPOC"]:
        query["organizationId"] = userOrgId

    # -----------------------------------------
    # UNKNOWN ROLES → DENY
    # -----------------------------------------
    else:
        raise HTTPException(
            status_code=403,
            detail="You are not allowed to view logs"
        )

    # -----------------------------------------
    # FETCH LOGS
    # -----------------------------------------
    cursor = (
        activityLogsCol
            .find(query)
            .sort("timestamp", -1)
            .limit(noOfLogs)
    )

    logs = await cursor.to_list(noOfLogs)

    for log in logs:
        if "_id" in log:
            log["_id"] = str(log["_id"])
        if "userId" in log and isinstance(log["userId"], ObjectId):
            log["userId"] = str(log["userId"])
        if "organizationId" in log and isinstance(log["organizationId"], ObjectId):
            log["organizationId"] = str(log["organizationId"])

    return JSONResponse(
        status_code=200,
        content=jsonable_encoder({
            "requestedLogs": noOfLogs,
            "returnedLogs": len(logs),
            "includedLogTypes": IMPORTANT_LOG_TYPES,
            "logs": logs
        })
    )

def validatePassword(pw: str) -> bool:
    """
    Password must be at least:
    - 8 characters
    - 1 uppercase letter
    - 1 number
    - 1 special character
    """
    import re
    if len(pw) < 8:
        return False
    if not re.search(r"[A-Z]", pw):
        return False
    if not re.search(r"[0-9]", pw):
        return False
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", pw):
        return False
    return True

@app.post("/auth/resetPassword")
async def resetPassword(
    body: dict = Body(...),
    authUser: dict = Depends(requireAuth)  # logged-in user
):
    email = body.get("email", "").lower().strip()
    # phone = body.get("phone", "").strip()
    currentPassword = body.get("currentPassword", "").strip()
    newPassword = body.get("newPassword", "").strip()

    if not email or not currentPassword or not newPassword:
        await logActivity(
            authUser,
            "Password Reset Failed",
            "Missing required fields",
            "Error"
        )
        raise HTTPException(status_code=400, detail="All fields are required")

    # -----------------------------------------------------
    # SECURITY RULE: Only logged-in user can reset their own password
    # -----------------------------------------------------
    if authUser.get("email", "").lower().strip() != email:
        await logActivity(
            authUser,
            "Password Reset Failed",
            f"Unauthorized attempt to reset password for {email}",
            "Error"
        )
        raise HTTPException(
            status_code=403,
            detail="You can only change your own password"
        )

    # Fetch user
    user = await usersCol.find_one({"email": email})
    if not user:
        await logActivity(
            authUser,
            "Password Reset Failed",
            f"User not found: {email}",
            "Error"
        )
        raise HTTPException(status_code=404, detail="User not found")

    # Phone match (phone or phoneNumber)
    # storedPhone = user.get("phone") or user.get("phoneNumber")
    # if not storedPhone or str(storedPhone).strip() != str(phone).strip():
    #     await logActivity(
    #         authUser,
    #         "Password Reset Failed",
    #         "Phone number does not match",
    #         "Error"
    #     )
    #     raise HTTPException(status_code=400, detail="Phone number does not match")

    # Current password match
    if user.get("password") != currentPassword:
        await logActivity(
            authUser,
            "Password Reset Failed",
            "Current password incorrect",
            "Error"
        )
        raise HTTPException(status_code=400, detail="Current password is incorrect")

    # Validate new password
    if not validatePassword(newPassword):
        await logActivity(
            authUser,
            "Password Reset Failed",
            "Password does not meet strength requirements",
            "Error"
        )
        raise HTTPException(
            status_code=400,
            detail="Password must be at least 8 chars, include 1 uppercase, 1 number and 1 special character"
        )

    # Update password
    await usersCol.update_one(
        {"_id": user["_id"]},
        {"$set": {"password": newPassword}}
    )

    # Send email
    try:
        send_password_reset_email(
            toEmail=email,
            userName=user.get("userName", "User"),
            userId=str(user.get("_id")),
            newPassword=newPassword
        )
        emailStatus = "Email sent successfully"
    except Exception as e:
        print("Email sending failed:", str(e))
        emailStatus = f"Email sending failed: {str(e)}"

    # Log successful reset
    await logActivity(
        authUser,
        "Password Reset",
        f"Password changed for user {email}. {emailStatus}",
        "Success"
    )

    return {
        "message": "Password updated and email sent successfully"
    }



@app.post("/secure/uploadLogo")
async def uploadLogo(
    file: UploadFile = File(...),
    imageName: str = Form(None),   # <---- NEW
    user: dict = Depends(requireAuth)
):
    # Validate file type
    ext = file.filename.split(".")[-1].lower()
    if ext not in ["jpg", "jpeg", "png"]:
        await logActivity(
            user,
            "Upload Logo Failed",
            f"Invalid file format ({ext})",
            "Error"
        )
        raise HTTPException(status_code=400, detail="Only JPG/PNG files allowed")

    # If no imageName provided → auto-generate unique name
    if not imageName:
        imageName = f"logo_{user.get('_id')}_{int(datetime.now().timestamp())}"

    try:
        # Upload with custom name
        uploadResult = cloudinary.uploader.upload(
            file.file,
            folder="bgvapp/logos",
            public_id=imageName,          # <----- THIS SETS THE CUSTOM NAME
            overwrite=True,               # Replace if already exists
            resource_type="image"
        )

        logoUrl = uploadResult.get("secure_url")

        await logActivity(
            user,
            "Upload Logo",
            f"Uploaded logo with name '{imageName}'",
            "Success"
        )

        return {
            "message": "Logo uploaded successfully",
            "logoUrl": logoUrl,
            "fileName": imageName
        }

    except Exception as e:
        await logActivity(
            user,
            "Upload Logo Failed",
            f"Cloudinary Error: {str(e)}",
            "Error"
        )
        raise HTTPException(status_code=500, detail=f"Cloudinary upload failed: {str(e)}")



@app.post("/secure/ai_resume_selection")
async def ai_resume_selection(
    jd: str = Form(...),
    resumes: list[UploadFile] = File(...),
    user: dict = Depends(requireAuth)
):
    if len(resumes) == 0:
        raise HTTPException(status_code=400, detail="No resumes uploaded")
    if len(resumes) > 100:
        raise HTTPException(status_code=400, detail="Maximum 100 resumes allowed")

    # FIXED CALL (correct order)
    topFive, pipelineRunId = await generate_resume_embeddings_and_rank(
        resumes,
        jd
    )

    return {
        "message": "AI Resume Selection Completed",
        "pipelineRunId": pipelineRunId,
        "topFiveResumes": topFive
    }



# =================================================================
#  ACCESS CONTROL (FULL)
# =================================================================
async def verify_certificate_access(user: dict, meta: dict):
    role = user.get("role")
    userOrgId = user.get("organizationId")
    accessibleOrgs = user.get("accessibleOrganizations", [])
    candidateOrgId = str(meta["organizationId"])
    createdByEmail = meta["createdBy"]

    # SUPER ADMIN — access all
    if role in ["SUPER_ADMIN" , "SUPER_SPOC"]:
        return True

    # SUPER ADMIN HELPER — only assigned orgs
    if role == "SUPER_ADMIN_HELPER":
        return candidateOrgId in accessibleOrgs

    # ORG HR / ORG SPOC — only own org
    if role in ["ORG_HR", "SPOC"]:
        return candidateOrgId == str(userOrgId)

    # HELPER — only candidates they added
    if role == "HELPER":
        return createdByEmail == user.get("email")

    return False


# =================================================================
#  AGGREGATION PIPELINE (FULL)
# =================================================================
async def fetch_certificate_payload(candidateId: str):
    pipeline = [
        {
            "$match": {
                "$or": [
                    {"_id": ObjectId(candidateId)},
                    {"_id": candidateId}
                ]
            }
        },

        {
            "$lookup": {
                "from": "verifications",
                "let": {"cid": {"$toString": "$_id"}},
                "pipeline": [
                    {
                        "$match": {
                            "$expr": {"$eq": ["$candidateId", "$$cid"]}
                        }
                    }
                ],
                "as": "verification"
            }
        },
        {"$unwind": "$verification"},

        {
            "$lookup": {
                "from": "organizations",
                "let": {"oid": "$verification.organizationId"},
                "pipeline": [
                    {
                        "$match": {
                            "$expr": {"$eq": [{"$toString": "$_id"}, "$$oid"]}
                        }
                    }
                ],
                "as": "organization"
            }
        },
        {
            "$unwind": {
                "path": "$organization",
                "preserveNullAndEmptyArrays": True
            }
        },

        {
            "$lookup": {
                "from": "users",
                "localField": "createdBy",
                "foreignField": "email",
                "as": "creator"
            }
        },
        {
            "$unwind": {
                "path": "$creator",
                "preserveNullAndEmptyArrays": True
            }
        },

        {
            "$project": {
                "_id": {"$toString": "$_id"},

                "candidate": {
                    "firstName": 1,
                    "lastName": 1,
                    "email": 1,
                    "phone": 1,
                    "address": 1,
                    "aadhaarNumber": 1,
                    "panNumber": 1,
                    "passportNumber": 1,
                    "dateOfBirth": 1,
                    "status": 1,
                    "createdAt": 1
                },

                "createdBy": {
                    "email": "$creator.email",
                    "name": "$creator.name",
                    "role": "$creator.role"
                },

                "verification": {
                    "verificationId": {"$toString": "$verification._id"},
                    "initiatedBy": "$verification.initiatedBy",
                    "initiatedAt": "$verification.initiatedAt",
                    "initiationType": "$verification.initiationType",
                    "organizationId": "$verification.organizationId",
                    "organizationName": "$verification.organizationName",
                    "stages": "$verification.stages",
                    "overallStatus": "$verification.overallStatus",
                    "currentStage": "$verification.currentStage",
                    "completedAt": "$verification.completedAt"
                },

                "organization": {
                    "name": "$organization.organizationName",
                    "logo": "$organization.logo",
                    "address": "$organization.address",
                    "contact": "$organization.contact"
                }
            }
        }
    ]

    data = await candidatesCol.aggregate(pipeline).to_list(1)
    return data[0] if data else None


# =================================================================
#  FINAL ENDPOINT (FULL WORKING)
# =================================================================
@app.get("/secure/certificate/{candidateId}")
async def getCertificateData(candidateId: str, user: dict = Depends(requireAuth)):

    data = await fetch_certificate_payload(candidateId)
    if not data:
        raise HTTPException(status_code=404, detail="Candidate not found")

    allowed = await verify_certificate_access(
        user,
        {
            "organizationId": data["verification"]["organizationId"],
            "createdBy": data["createdBy"]["email"]
        }
    )

    if not allowed:
        raise HTTPException(status_code=403, detail="Access denied")

    return JSONResponse(
        status_code=200,
        content={"success": True, "certificate": data}
    )


# -------------------------------
# Health Check
# -------------------------------
@app.get("/health")
async def health():
    return {"status": "ok"}


from fastapi import UploadFile, File, Body, Depends, HTTPException
from bson import ObjectId
import cloudinary.uploader
from utils.ticket_utils import get_assignee, now
from utils.email_utils import send_ticket_email


# ----------------------------------------------------------
# CREATE TICKET
# ----------------------------------------------------------
import json
from fastapi import Form, File, UploadFile

@app.post("/secure/createticket")
async def createTicket(
    body: str = Form(...),
    attachments: list[UploadFile] = File(None),
    user: dict = Depends(requireAuth)
):
    print("Logged in user:", user)
    assignee = await get_assignee(user, usersCol)
    print("Assignee:", assignee)

    data = json.loads(body)

    title = data.get("title")
    description = data.get("description")
    category = data.get("category")
    priority = data.get("priority", "MEDIUM")


    if not title or not description:
        raise HTTPException(400, "Title and description required")

    orgId = str(user.get("organizationId"))

    # Auto assignment
    assignee = await get_assignee(user, usersCol)
    if not assignee:
        raise HTTPException(500, "Unable to auto-assign ticket")

    # Upload attachments
    uploaded_files = []
    if attachments:
        for f in attachments:
            upl = cloudinary.uploader.upload(
                f.file,
                folder="bgvapp/tickets"
            )
            uploaded_files.append({
                "url": upl["secure_url"],
                "fileName": f.filename,
                "uploadedBy": user.get("email"),
                "uploadedAt": now()
            })

    ticketDoc = {
        "title": title,
        "description": description,
        "category": category,
        "priority": priority,

        "createdBy": user.get("email"),
        "createdById": str(user.get("_id")),
        "createdByRole": user.get("role"),
        "organizationId": orgId,

        "status": "OPEN",

        "assignedTo": assignee.get("email"),
        "assignedToId": str(assignee.get("_id")),
        "assignedToRole": assignee.get("role"),

        "attachments": uploaded_files,
        "comments": [],

        "createdAt": now(),
        "updatedAt": now()
    }

    res = await ticketsCol.insert_one(ticketDoc)
    ticketId = str(res.inserted_id)

    # email notify assignee
    send_ticket_email(
        assignee["email"],
        f"New Ticket Assigned - #{ticketId}",
        f"You have been assigned a ticket.\n\nTitle: {title}\n\nDescription:\n{description}"
    )

    await logActivity(user, "Ticket Created", f"Created ticket #{ticketId}", "Success")

    return {"message": "Ticket created", "ticketId": ticketId}

## access your tickets
@app.get("/secure/tickets/my")
async def getMyTickets(user: dict = Depends(requireAuth)):
    cursor = ticketsCol.find({"createdBy": user.get("email")}).sort("createdAt", -1)
    data = await cursor.to_list(None)

    for t in data:
        t["_id"] = str(t["_id"])

    return {"tickets": data}


@app.get("/secure/tickets/org")
async def getOrgTickets(user: dict = Depends(requireAuth)):
    """Get all the tickets over the org"""
    orgId = str(user.get("organizationId"))

    cursor = ticketsCol.find({"organizationId": orgId}).sort("createdAt", -1)
    data = await cursor.to_list(None)

    for t in data:
        t["_id"] = str(t["_id"])

    return {"tickets": data}


@app.get("/secure/tickets/all")
async def getAllTickets(user: dict = Depends(requireAuth)):
    """Get all the tickets over the allorg"""
    if user.get("role") not in ["SUPER_ADMIN", "SUPER_SPOC"]:
        raise HTTPException(403, "Not authorized")

    cursor = ticketsCol.find({}).sort("createdAt", -1)
    data = await cursor.to_list(None)

    for t in data:
        t["_id"] = str(t["_id"])

    return {"tickets": data}


@app.get("/secure/tickets/{ticketId}")
async def getTicket(ticketId: str, user: dict = Depends(requireAuth)):
    ticket = await ticketsCol.find_one({"_id": ObjectId(ticketId)})
    if not ticket:
        raise HTTPException(404, "Ticket not found")

    # Check org access
    if str(ticket["organizationId"]) != str(user["organizationId"]) and user.get("role") not in ["SUPER_ADMIN", "SUPER_SPOC"]:
        raise HTTPException(403, "Not allowed to access this ticket")

    ticket["_id"] = str(ticket["_id"])
    return ticket


@app.post("/secure/tickets/{ticketId}/attachment")
async def uploadTicketAttachment(
    ticketId: str,
    file: UploadFile = File(...),
    user: dict = Depends(requireAuth)
):
    ticket = await ticketsCol.find_one({"_id": ObjectId(ticketId)})
    if not ticket:
        raise HTTPException(404, "Ticket not found")

    # Org boundary check
    if str(ticket["organizationId"]) != str(user["organizationId"]):
        raise HTTPException(403, "Cannot upload attachment to ticket of another org")

    # Upload file
    upl = cloudinary.uploader.upload(
        file.file,
        folder=f"bgvapp/tickets/{ticketId}"
    )

    attachmentObj = {
        "url": upl["secure_url"],
        "fileName": file.filename,
        "uploadedBy": user.get("email"),
        "uploadedAt": now()
    }

    await ticketsCol.update_one(
        {"_id": ObjectId(ticketId)},
        {"$push": {"attachments": attachmentObj}}
    )

    await logActivity(
        user,
        "Ticket Attachment Uploaded",
        f"Attachment added to ticket #{ticketId}",
        "Success"
    )

    return {
        "message": "Attachment uploaded",
        "url": upl["secure_url"]
    }


@app.post("/secure/tickets/{ticketId}/comment")
async def addComment(ticketId: str, body: dict = Body(...), user: dict = Depends(requireAuth)):
    message = body.get("message")
    if not message:
        raise HTTPException(400, "Comment cannot be empty")

    ticket = await ticketsCol.find_one({"_id": ObjectId(ticketId)})
    if not ticket:
        raise HTTPException(404, "Ticket not found")

    comment = {
        "commentBy": user.get("email"),
        "commentByRole": user.get("role"),
        "message": message,
        "timestamp": now(),
        "attachments": []
    }

    await ticketsCol.update_one(
        {"_id": ObjectId(ticketId)},
        {"$push": {"comments": comment}, "$set": {"updatedAt": now()}}
    )

    send_ticket_email(
        ticket["assignedTo"],
        f"New Comment on Ticket #{ticketId}",
        f"{user.get('email')} commented:\n\n{message}"
    )

    await logActivity(user, "Ticket Comment Added", f"Commented on ticket #{ticketId}", "Success")

    return {"message": "Comment added"}

@app.post("/secure/tickets/{ticketId}/status")
async def updateStatus(ticketId: str, body: dict = Body(...), user: dict = Depends(requireAuth)):
    newStatus = body.get("status")

    if newStatus not in ["OPEN", "IN_PROGRESS", "RESOLVED", "CLOSED", "REOPENED"]:
        raise HTTPException(400, "Invalid status")

    ticket = await ticketsCol.find_one({"_id": ObjectId(ticketId)})
    if not ticket:
        raise HTTPException(404, "Ticket not found")

    role = user.get("role")

    if role == "HELPER":
        raise HTTPException(403, "HELPER cannot change status")

    await ticketsCol.update_one(
        {"_id": ObjectId(ticketId)},
        {"$set": {"status": newStatus, "updatedAt": now()}}
    )

    send_ticket_email(
        ticket["createdBy"],
        f"Ticket #{ticketId} Status Updated",
        f"Status changed to {newStatus}"
    )

    await logActivity(user, "Ticket Status Updated", f"#{ticketId} → {newStatus}", "Success")

    return {"message": "Status updated"}


@app.post("/secure/tickets/{ticketId}/assign")
async def assignTicket(ticketId: str, body: dict = Body(...), user: dict = Depends(requireAuth)):
    # Allowed roles
    if user.get("role") not in ["SPOC", "ORG_HR", "SUPER_ADMIN", "SUPER_SPOC"]:
        raise HTTPException(403, "Not authorized")

    # Fetch ticket
    ticket = await ticketsCol.find_one({"_id": ObjectId(ticketId)})
    if not ticket:
        raise HTTPException(404, "Ticket not found")

    ticketOrgId = str(ticket.get("organizationId"))

    newAssigneeEmail = body.get("assignee")
    if not newAssigneeEmail:
        raise HTTPException(400, "Assignee email is required")

    # Fetch new assignee
    assignee = await usersCol.find_one({"email": newAssigneeEmail})
    if not assignee:
        raise HTTPException(404, "User not found")

    # 🔥 CHECK ORG MATCH — IMPORTANT
    if str(assignee.get("organizationId")) != ticketOrgId:
        raise HTTPException(403, "Cannot assign ticket outside the organization")

    # Update ticket
    await ticketsCol.update_one(
        {"_id": ObjectId(ticketId)},
        {
            "$set": {
                "assignedTo": assignee["email"],
                "assignedToId": str(assignee["_id"]),
                "assignedToRole": assignee["role"],
                "updatedAt": now()
            }
        }
    )

    # Email notification
    send_ticket_email(
        assignee["email"],
        f"You have been assigned Ticket #{ticketId}",
        f"You have been assigned a new ticket. Please check your dashboard."
    )

    await logActivity(
        user,
        "Ticket Reassigned",
        f"Ticket #{ticketId} assigned to {assignee['email']}",
        "Success"
    )

    return {"message": "Ticket assigned"}


@app.post("/secure/tickets/{ticketId}/close")
async def closeTicket(
    ticketId: str,
    body: dict = Body(...),
    user: dict = Depends(requireAuth)
):
    if user.get("role") not in ["ORG_HR", "SPOC", "SUPER_ADMIN", "SUPER_SPOC"]:
        raise HTTPException(403, "Not authorized")

    reason = body.get("reason", "No reason provided")

    ticket = await ticketsCol.find_one({"_id": ObjectId(ticketId)})
    if not ticket:
        raise HTTPException(404, "Ticket not found")

    # org restriction
    if str(ticket["organizationId"]) != str(user["organizationId"]):
        raise HTTPException(403, "Not allowed to close ticket of another org")

    await ticketsCol.update_one(
        {"_id": ObjectId(ticketId)},
        {
            "$set": {
                "status": "CLOSED",
                "closedReason": reason,
                "closedAt": now(),
                "updatedAt": now()
            }
        }
    )

    await logActivity(
        user,
        "Ticket Closed",
        f"Ticket #{ticketId} closed. Reason: {reason}",
        "Success"
    )

    return { "message": "Ticket closed" }

@app.post("/secure/tickets/{ticketId}/reopen")
async def reopenTicket(
    ticketId: str,
    body: dict = Body(...),
    user: dict = Depends(requireAuth)
):
    reason = body.get("reason", "No reason provided")

    ticket = await ticketsCol.find_one({"_id": ObjectId(ticketId)})
    if not ticket:
        raise HTTPException(404, "Ticket not found")

    # org restriction
    if str(ticket["organizationId"]) != str(user["organizationId"]):
        raise HTTPException(403, "Not allowed to reopen ticket of another org")

    await ticketsCol.update_one(
        {"_id": ObjectId(ticketId)},
        {
            "$set": {
                "status": "REOPENED",
                "reopenReason": reason,
                "reopenedAt": now(),
                "updatedAt": now()
            }
        }
    )

    await logActivity(
        user,
        "Ticket Reopened",
        f"Ticket #{ticketId} reopened. Reason: {reason}",
        "Success"
    )

    return { "message": "Ticket reopened" }
