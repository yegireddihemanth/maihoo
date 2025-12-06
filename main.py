
from fastapi import FastAPI, HTTPException, Request, Response, Depends, Body
from pydantic import BaseModel
from motor.motor_asyncio import AsyncIOMotorClient
from fastapi.responses import JSONResponse
from datetime import datetime, timezone
from typing import List, Optional
import os, time, hmac, hashlib, base64, json, uuid
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
# AI utilities removed - new approach to be implemented
from utils.email_utils import *

# Load environment variables
from dotenv import load_dotenv
load_dotenv()

# -------------------------------
# AWS S3 Configuration
# -------------------------------
import boto3
from botocore.exceptions import ClientError

AWS_ACCESS_KEY_ID = os.getenv("AWS_ACCESS_KEY_ID")
AWS_SECRET_ACCESS_KEY = os.getenv("AWS_SECRET_ACCESS_KEY")
AWS_S3_BUCKET_NAME = os.getenv("AWS_S3_BUCKET_NAME")
AWS_REGION = os.getenv("AWS_REGION", "ap-south-2")

# Debug: Print what was loaded
print("\n" + "="*60)
print("🔍 AWS CREDENTIALS DEBUG")
print("="*60)
print(f"Access Key ID: {AWS_ACCESS_KEY_ID[:10]}...{AWS_ACCESS_KEY_ID[-4:] if AWS_ACCESS_KEY_ID else 'None'}")
print(f"Secret Key: {AWS_SECRET_ACCESS_KEY[:10]}...{AWS_SECRET_ACCESS_KEY[-4:] if AWS_SECRET_ACCESS_KEY else 'None'}")
print(f"Bucket Name: {AWS_S3_BUCKET_NAME}")
print(f"Region: {AWS_REGION}")
print("="*60 + "\n")

# Initialize S3 client
s3_client = None
if AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY and AWS_S3_BUCKET_NAME:
    try:
        s3_client = boto3.client(
            's3',
            aws_access_key_id=AWS_ACCESS_KEY_ID,
            aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
            region_name=AWS_REGION
        )
        print(f"✅ S3 client initialized for bucket: {AWS_S3_BUCKET_NAME}")
    except Exception as e:
        print(f"⚠️ Failed to initialize S3 client: {e}")
else:
    print("⚠️ S3 credentials not configured")

async def upload_to_s3(file_content: bytes, file_name: str, folder_path: str) -> str:
    """
    Upload file to S3 bucket
    
    Args:
        file_content: File bytes
        file_name: Name of the file
        folder_path: Folder path in S3 (e.g., "TechCorp/John_Doe")
    
    Returns:
        S3 URL of uploaded file
    """
    if not s3_client:
        raise Exception("S3 client not initialized")
    
    try:
        # Construct S3 key (path)
        s3_key = f"{folder_path}/{file_name}"
        
        # Upload file
        s3_client.put_object(
            Bucket=AWS_S3_BUCKET_NAME,
            Key=s3_key,
            Body=file_content,
            ContentType='application/pdf' if file_name.endswith('.pdf') else 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
        )
        
        # Construct S3 URL
        s3_url = f"https://{AWS_S3_BUCKET_NAME}.s3.{AWS_REGION}.amazonaws.com/{s3_key}"
        
        print(f"✅ Uploaded to S3: {s3_url}")
        return s3_url
        
    except ClientError as e:
        print(f"❌ S3 upload error: {e}")
        raise Exception(f"Failed to upload to S3: {str(e)}")

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
    "https://deserted-karla-soughfully.ngrok-free.dev",
    "https://bgv-ey1e.onrender.com",
    "*"
    
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,  # ✅ Changed from allow_origin_regex to allow_origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["set-cookie", "Set-Cookie"]  # Added Set-Cookie for Safari
)

# Safari/iOS Cookie Fix Middleware
@app.middleware("http")
async def safari_cookie_fix(request: Request, call_next):
    response = await call_next(request)
    
    # Add headers to help Safari accept cookies
    origin = request.headers.get("origin")
    if origin and origin in origins:
        response.headers["Access-Control-Allow-Origin"] = origin
        response.headers["Access-Control-Allow-Credentials"] = "true"
        response.headers["Vary"] = "Origin"
    
    return response

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
        domain=None  # Let browser handle domain automatically
    )
    
    # Also set cookie in response headers for Safari/iOS compatibility
    response.headers["Set-Cookie"] = (
        f"{cookieName}={token}; "
        f"Max-Age={cookieMaxAge}; "
        f"Path=/; "
        f"{'Secure; ' if cookieSecure else ''}"
        f"HttpOnly; "
        f"SameSite={cookieSameSite}"
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
        
        # 🔥 NEW: Add initiatedByName by looking up the user
        initiated_by_email = v.get("initiatedBy")
        initiated_by_name = "Unknown"
        
        if initiated_by_email:
            try:
                initiator_user = await usersCol.find_one({"email": initiated_by_email})
                if initiator_user:
                    initiated_by_name = initiator_user.get("userName", initiated_by_email)
                else:
                    initiated_by_name = initiated_by_email  # Fallback to email if user not found
            except Exception as e:
                print(f"Error looking up initiator {initiated_by_email}: {e}")
                initiated_by_name = initiated_by_email
        
        v["initiatedByName"] = initiated_by_name

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
async def modifyCandidate(
    operation: str = Form(...),  # "edit" or "delete"
    candidateId: str = Form(...),
    organizationId: str = Form(...),
    # Edit fields (all optional)
    firstName: str = Form(None),
    middleName: str = Form(None),
    lastName: str = Form(None),
    email: str = Form(None),
    phone: str = Form(None),
    aadhaarNumber: str = Form(None),
    panNumber: str = Form(None),
    address: str = Form(None),
    dob: str = Form(None),
    passportNumber: str = Form(None),
    uanNumber: str = Form(None),
    bankAccountNumber: str = Form(None),
    fatherName: str = Form(None),
    gender: str = Form(None),
    district: str = Form(None),
    state: str = Form(None),
    pincode: str = Form(None),
    resume: UploadFile = File(None),  # Optional resume upload
    user: dict = Depends(requireAuth)
):
    """
    Modify (EDIT / DELETE) a candidate with role-based access control.
    
    For EDIT: Provide operation="edit" + fields to update + optional resume file
    For DELETE: Provide operation="delete" only
    """

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

        # Build updates dict from form fields
        updates = {}
        if firstName is not None: updates["firstName"] = firstName
        if middleName is not None: updates["middleName"] = middleName
        if lastName is not None: updates["lastName"] = lastName
        if email is not None: updates["email"] = email
        if phone is not None: updates["phone"] = phone
        if aadhaarNumber is not None: updates["aadhaarNumber"] = aadhaarNumber
        if panNumber is not None: updates["panNumber"] = panNumber
        if address is not None: updates["address"] = address
        if dob is not None: updates["dob"] = dob
        if passportNumber is not None: updates["passportNumber"] = passportNumber
        if uanNumber is not None: updates["uanNumber"] = uanNumber
        if bankAccountNumber is not None: updates["bankAccountNumber"] = bankAccountNumber
        if fatherName is not None: updates["fatherName"] = fatherName
        if gender is not None: updates["gender"] = gender
        if district is not None: updates["district"] = district
        if state is not None: updates["state"] = state
        if pincode is not None: updates["pincode"] = pincode

        # Handle resume upload to S3
        s3_upload_error = None
        if resume:
            try:
                print(f"📄 Resume file received for update: {resume.filename}")
                
                # Validate file type
                ext = resume.filename.split(".")[-1].lower()
                if ext not in ["pdf", "docx"]:
                    raise HTTPException(status_code=400, detail="Only PDF/DOCX files are supported for resume")
                
                # Read file content
                file_content = await resume.read()
                
                # Get org name
                org = await orgsCol.find_one({"_id": ObjectId(organizationId)})
                orgName = org.get("organizationName") if org else "Unknown"
                
                # Get candidate name (use existing or updated)
                first = firstName if firstName else candidate.get("firstName")
                last = lastName if lastName else candidate.get("lastName")
                
                # Create S3 folder path
                folder_path = f"{orgName}/{first}_{last}".replace(" ", "_")
                file_name = f"{first}_{last}_resume.{ext}".replace(" ", "_")
                
                # Upload to S3
                resumePath = await upload_to_s3(file_content, file_name, folder_path)
                updates["resumePath"] = resumePath
                print(f"✅ Resume uploaded to S3: {resumePath}")
                
            except HTTPException:
                raise
            except Exception as e:
                s3_upload_error = str(e)
                print(f"⚠️ S3 upload failed: {e}")

        if len(updates) == 0:
            raise HTTPException(400, "No fields provided to update")

        # Apply update
        await candidatesCol.update_one(
            {"_id": candObjId},
            {"$set": updates}
        )

        await logActivity(
            user,
            "Edit Candidate",
            f"Updated candidate {candidateId}: {', '.join(updates.keys())}",
            "Success"
        )

        response_message = "Candidate updated successfully"
        if "resumePath" in updates:
            response_message += " with resume uploaded to S3"
        elif s3_upload_error:
            response_message += f" (Warning: Resume upload failed - {s3_upload_error})"

        return {
            "message": response_message,
            "updatedFields": list(updates.keys()),
            "resumeUploaded": "resumePath" in updates,
            "s3UploadError": s3_upload_error
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
async def addCandidate(
    firstName: str = Form(...),
    middleName: str = Form(None),
    lastName: str = Form(...),
    phone: str = Form(...),
    aadhaarNumber: str = Form(...),
    panNumber: str = Form(...),
    address: str = Form(...),
    email: str = Form(...),
    fatherName: str = Form(...),
    dob: str = Form(...),
    gender: str = Form(...),
    uanNumber: str = Form(None),
    district: str = Form(...),
    state: str = Form(...),
    pincode: str = Form(...),
    organizationId: str = Form(None),
    resume: UploadFile = File(None),
    user: dict = Depends(requireAuth)
):
    role = user.get("role")
    creatorEmail = user.get("email")
    accessibleOrgs = user.get("accessibleOrganizations", [])
    orgId = None
    orgName = None
    
    # Fields are now from Form parameters (not body)
    inputOrgId = organizationId
    candidateEmail = email

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
    # UPLOAD RESUME TO S3 (if provided)
    # ---------------------------------------------
    resumePath = None
    s3_upload_error = None
    
    if resume:
        try:
            print(f"📄 Resume file received: {resume.filename}")
            
            # Validate file type
            ext = resume.filename.split(".")[-1].lower()
            if ext not in ["pdf", "docx"]:
                raise HTTPException(status_code=400, detail="Only PDF/DOCX files are supported for resume")
            
            # Read file content
            file_content = await resume.read()
            
            # Create S3 folder path: {orgName}/{firstName}_{lastName}/
            folder_path = f"{orgName}/{firstName}_{lastName}".replace(" ", "_")
            
            # Create file name: {firstName}_{lastName}_resume.{ext}
            file_name = f"{firstName}_{lastName}_resume.{ext}".replace(" ", "_")
            
            # Upload to S3
            resumePath = await upload_to_s3(file_content, file_name, folder_path)
            print(f"✅ Resume uploaded to S3: {resumePath}")
            
        except HTTPException:
            raise
        except Exception as e:
            # Log error but don't fail candidate creation
            s3_upload_error = str(e)
            print(f"⚠️ S3 upload failed: {e}")
            print(f"⚠️ Continuing with candidate creation without resume")

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
    
    # Add resumePath if S3 upload succeeded
    if resumePath:
        candidateDoc["resumePath"] = resumePath

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
    
    # Build response message
    response_message = "Candidate added successfully"
    if resumePath:
        response_message += " with resume uploaded to S3"
    elif s3_upload_error:
        response_message += f" (Warning: Resume upload failed - {s3_upload_error})"

    return JSONResponse(
        status_code=201,
        content=jsonable_encoder({
            "message": response_message,
            "candidate": savedCandidate,
            "resumeUploaded": resumePath is not None,
            "resumePath": resumePath,
            "s3UploadError": s3_upload_error
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



# AI resume selection endpoint removed - new approach to be implemented



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

# OLD ENDPOINT REMOVED - Use POST /secure/ticket/create instead

# OLD ENDPOINTS REMOVED - Use the following instead:
# GET /secure/ticket/list?assignedToMe=true (replaces /tickets/my)
# GET /secure/ticket/list (replaces /tickets/org and /tickets/all with role-based filtering)
# GET /secure/ticket/{ticketId} (replaces /tickets/{ticketId})


@app.post("/secure/ticket/{ticketId}/attachment")
async def uploadTicketAttachment(
    ticketId: str,
    file: UploadFile = File(...),
    user: dict = Depends(requireAuth)
):
    ticket = await ticketsCol.find_one({"ticketId": ticketId})
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
        {"ticketId": ticketId},
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


# OLD ENDPOINTS REMOVED - Use the following instead:
# POST /secure/ticket/{ticketId}/comment (replaces /tickets/{ticketId}/comment)
# PUT /secure/ticket/{ticketId}/status (replaces POST /tickets/{ticketId}/status)


@app.post("/secure/ticket/{ticketId}/close")
async def closeTicket(
    ticketId: str,
    body: dict = Body(...),
    user: dict = Depends(requireAuth)
):
    reason = body.get("reason", "No reason provided")

    ticket = await ticketsCol.find_one({"ticketId": ticketId})
    if not ticket:
        raise HTTPException(404, "Ticket not found")

    # 🔥 FIXED: Enhanced authorization logic
    userRole = user.get("role")
    userEmail = user.get("email")
    userOrgId = str(user.get("organizationId", ""))
    ticketOrgId = str(ticket.get("organizationId", ""))
    
    # Check if user can close this ticket
    canClose = False
    
    # 1. SUPER_ADMIN and SUPER_SPOC can close any ticket (global access)
    if userRole in ["SUPER_ADMIN", "SUPER_SPOC"]:
        canClose = True
    
    # 2. ORG_HR and SPOC can close tickets from their own organization
    elif userRole in ["ORG_HR", "SPOC"]:
        if userOrgId == ticketOrgId:
            canClose = True
    
    # 3. Assigned user can close their assigned tickets
    elif userEmail == ticket.get("assignedToEmail"):
        canClose = True
    
    # 4. Ticket creator can close their own tickets
    elif userEmail == ticket.get("createdBy"):
        canClose = True
    
    if not canClose:
        raise HTTPException(403, f"Not authorized to close this ticket. Role: {userRole}")

    await ticketsCol.update_one(
        {"ticketId": ticketId},
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

@app.post("/secure/ticket/{ticketId}/reopen")
async def reopenTicket(
    ticketId: str,
    body: dict = Body(...),
    user: dict = Depends(requireAuth)
):
    reason = body.get("reason", "No reason provided")

    ticket = await ticketsCol.find_one({"ticketId": ticketId})
    if not ticket:
        raise HTTPException(404, "Ticket not found")

    # 🔥 FIXED: Enhanced authorization logic (same as close ticket)
    userRole = user.get("role")
    userEmail = user.get("email")
    userOrgId = str(user.get("organizationId", ""))
    ticketOrgId = str(ticket.get("organizationId", ""))
    
    # Check if user can reopen this ticket
    canReopen = False
    
    # 1. SUPER_ADMIN and SUPER_SPOC can reopen any ticket (global access)
    if userRole in ["SUPER_ADMIN", "SUPER_SPOC"]:
        canReopen = True
    
    # 2. ORG_HR and SPOC can reopen tickets from their own organization
    elif userRole in ["ORG_HR", "SPOC"]:
        if userOrgId == ticketOrgId:
            canReopen = True
    
    # 3. Assigned user can reopen their assigned tickets
    elif userEmail == ticket.get("assignedToEmail"):
        canReopen = True
    
    # 4. Ticket creator can reopen their own tickets
    elif userEmail == ticket.get("createdBy"):
        canReopen = True
    
    if not canReopen:
        raise HTTPException(403, f"Not authorized to reopen this ticket. Role: {userRole}")

    await ticketsCol.update_one(
        {"ticketId": ticketId},
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


# ============================================================
#                VERIFICATION CONSENT SYSTEM
# ============================================================

import secrets
from datetime import datetime, timedelta
from utils.email_utils import send_verification_consent_email

# ------------------------------
# Send Verification Consent Email
# ------------------------------
@app.post("/secure/verification/{candidateId}/send-consent")
async def sendVerificationConsent(
    candidateId: str,
    body: dict = Body(...),
    user: dict = Depends(requireAuth)
):
    """
    Send consent email to candidate before starting backend verification.
    
    Request Body:
    {
        "verificationChecks": [
            {
                "name": "Employment Verification",
                "description": "Verify employment history and job titles"
            },
            {
                "name": "Education Verification", 
                "description": "Verify educational qualifications and degrees"
            }
        ],
        "consentUrl": "https://your-frontend.com/consent" // Optional
    }
    """
    
    # Authorization check
    if user.get("role") not in ["SUPER_ADMIN", "SUPER_SPOC", "ORG_HR", "SPOC", "SUPER_ADMIN_HELPER"]:
        raise HTTPException(403, "Not authorized to send consent emails")
    
    # Validate candidate ID
    try:
        candidate_obj_id = ObjectId(candidateId)
    except:
        raise HTTPException(400, "Invalid candidate ID")
    
    # Fetch candidate
    candidate = await candidatesCol.find_one({"_id": candidate_obj_id})
    if not candidate:
        raise HTTPException(404, "Candidate not found")
    
    # Check organization access
    candidate_org_id = str(candidate.get("organizationId", ""))
    user_org_id = str(user.get("organizationId", ""))
    user_role = user.get("role")
    
    # Organization access validation
    has_access = False
    if user_role in ["SUPER_ADMIN", "SUPER_SPOC"]:
        has_access = True
    elif user_role == "SUPER_ADMIN_HELPER":
        accessible_orgs = user.get("accessibleOrganizations", [])
        has_access = candidate_org_id in [str(org) for org in accessible_orgs]
    elif user_role in ["ORG_HR", "SPOC"]:
        has_access = candidate_org_id == user_org_id
    
    if not has_access:
        raise HTTPException(403, "Not authorized to access this candidate")
    
    # Get request data - verification checks are now optional
    verification_checks = body.get("verificationChecks", [])
    
    # If no checks provided, use default verification checks
    if not verification_checks:
        verification_checks = [
            {
                "name": "Identity Verification",
                "description": "Verify identity documents and personal information"
            },
            {
                "name": "Employment Verification", 
                "description": "Verify employment history and job titles"
            },
            {
                "name": "Education Verification",
                "description": "Verify educational qualifications and degrees"
            },
            {
                "name": "Reference Check",
                "description": "Contact provided references to verify character and work performance"
            }
        ]
    
    # Check if consent already given
    if candidate.get("consentAcknowledged") == True:
        return {
            "message": "Consent already provided by candidate",
            "consentStatus": "ALREADY_GIVEN",
            "consentDate": candidate.get("consentDate")
        }
    
    # Generate consent token
    consent_token = secrets.token_urlsafe(32)
    expires_at = datetime.utcnow() + timedelta(hours=48)  # 48 hours expiry
    
    # Update candidate with consent token
    await candidatesCol.update_one(
        {"_id": candidate_obj_id},
        {
            "$set": {
                "consentToken": consent_token,
                "consentTokenExpiry": expires_at.isoformat(),
                "consentRequested": True,
                "consentRequestedAt": datetime.utcnow().isoformat(),
                "consentRequestedBy": user.get("email"),
                "verificationChecksRequested": verification_checks,
                "updatedAt": datetime.utcnow().isoformat()
            }
        }
    )
    
    # Get organization name
    org_name = candidate.get("organizationName", "Unknown Organization")
    
    # Send consent email
    try:
        # Construct candidate name from firstName and lastName
        candidate_name = f"{candidate.get('firstName', '')} {candidate.get('lastName', '')}".strip()
        if not candidate_name:
            candidate_name = candidate.get("email", "Candidate")
        
        send_verification_consent_email(
            to_email=candidate.get("email"),
            candidate_name=candidate_name,
            organization_name=org_name,
            verification_checks=verification_checks,
            consent_token=consent_token,
            expires_at=expires_at.strftime("%Y-%m-%d %H:%M:%S UTC")
        )
        
        # Log activity
        await logActivity(
            user,
            "Verification Consent Sent",
            f"Consent email sent to {candidate.get('email')} for candidate {candidateId}",
            "Success"
        )
        
        return {
            "message": "Verification consent email sent successfully",
            "candidateId": candidateId,
            "candidateEmail": candidate.get("email"),
            "consentToken": consent_token,
            "expiresAt": expires_at.isoformat(),
            "checksRequested": len(verification_checks)
        }
        
    except Exception as e:
        # Log error
        await logActivity(
            user,
            "Verification Consent Failed",
            f"Failed to send consent email to {candidate.get('email')}: {str(e)}",
            "Error"
        )
        raise HTTPException(500, f"Failed to send consent email: {str(e)}")


# ------------------------------
# Get Consent Details (Public - No Auth Required)
# ------------------------------
@app.get("/public/verification-consent/{token}")
async def getConsentDetails(token: str):
    """
    Get consent details for candidate using token (public endpoint for consent page).
    """
    
    # Find candidate by consent token
    candidate = await candidatesCol.find_one({
        "consentToken": token,
        "consentTokenExpiry": {"$gt": datetime.utcnow().isoformat()}
    })
    
    if not candidate:
        raise HTTPException(404, "Invalid or expired consent token")
    
    # Check if consent already given
    if candidate.get("consentAcknowledged") == True:
        return {
            "status": "ALREADY_CONSENTED",
            "message": "Consent has already been provided for this verification",
            "consentDate": candidate.get("consentDate")
        }
    
    # Construct candidate name from firstName and lastName
    candidate_name = f"{candidate.get('firstName', '')} {candidate.get('lastName', '')}".strip()
    if not candidate_name:
        candidate_name = candidate.get("email", "Unknown")
    
    return {
        "candidateId": str(candidate["_id"]),
        "candidateName": candidate_name,
        "candidateEmail": candidate.get("email"),
        "organizationName": candidate.get("organizationName"),
        "verificationChecks": candidate.get("verificationChecksRequested", []),
        "consentRequestedAt": candidate.get("consentRequestedAt"),
        "consentRequestedBy": candidate.get("consentRequestedBy"),
        "tokenExpiresAt": candidate.get("consentTokenExpiry"),
        "status": "PENDING_CONSENT"
    }


# ------------------------------
# Submit Consent (Public - No Auth Required)
# ------------------------------
@app.post("/public/verification-consent/{token}/submit")
async def submitConsent(token: str, body: dict = Body(...)):
    """
    Submit consent response from candidate.
    
    Request Body:
    {
        "consentGiven": true,  // Required: true/false
        "candidateSignature": "John Doe",  // Optional
        "ipAddress": "192.168.1.1",  // Optional
        "userAgent": "Mozilla/5.0..."  // Optional
    }
    """
    
    consent_given = body.get("consentGiven")
    if consent_given is None:
        raise HTTPException(400, "consentGiven field is required (true/false)")
    
    # Find candidate by consent token
    candidate = await candidatesCol.find_one({
        "consentToken": token,
        "consentTokenExpiry": {"$gt": datetime.utcnow().isoformat()}
    })
    
    if not candidate:
        raise HTTPException(404, "Invalid or expired consent token")
    
    # Check if consent already given
    if candidate.get("consentAcknowledged") == True:
        return {
            "status": "ALREADY_CONSENTED",
            "message": "Consent has already been provided for this verification"
        }
    
    consent_date = datetime.utcnow().isoformat()
    
    # Update candidate with consent response
    update_data = {
        "consentAcknowledged": consent_given,
        "consentDate": consent_date,
        "consentSubmittedAt": consent_date,
        "updatedAt": consent_date
    }
    
    # Clear consent token after submission
    update_data["consentToken"] = None
    update_data["consentTokenExpiry"] = None
    
    await candidatesCol.update_one(
        {"_id": candidate["_id"]},
        {"$set": update_data}
    )
    
    # Log the consent submission
    await logActivity(
        {"email": "system", "role": "SYSTEM"},
        "Verification Consent Submitted",
        f"Candidate {candidate.get('email')} {'gave' if consent_given else 'denied'} consent for verification",
        "Success"
    )
    
    # Construct candidate name from firstName and lastName
    candidate_name = f"{candidate.get('firstName', '')} {candidate.get('lastName', '')}".strip()
    if not candidate_name:
        candidate_name = candidate.get("email", "Unknown")
    
    if consent_given:
        return {
            "status": "CONSENT_GIVEN",
            "message": "Thank you! Your consent has been recorded. Verification process can now begin.",
            "consentDate": consent_date,
            "candidateName": candidate_name
        }
    else:
        return {
            "status": "CONSENT_DENIED", 
            "message": "Your response has been recorded. Verification process will not proceed without consent.",
            "consentDate": consent_date,
            "candidateName": candidate_name
        }


# ------------------------------
# Check Consent Status (Internal)
# ------------------------------
@app.get("/secure/verification/{candidateId}/consent-status")
async def getConsentStatus(candidateId: str, user: dict = Depends(requireAuth)):
    """
    Check consent status for a candidate (for internal use before starting verification).
    """
    
    # Authorization check
    if user.get("role") not in ["SUPER_ADMIN", "SUPER_SPOC", "ORG_HR", "SPOC", "SUPER_ADMIN_HELPER"]:
        raise HTTPException(403, "Not authorized")
    
    # Validate candidate ID
    try:
        candidate_obj_id = ObjectId(candidateId)
    except:
        raise HTTPException(400, "Invalid candidate ID")
    
    # Fetch candidate
    candidate = await candidatesCol.find_one({"_id": candidate_obj_id})
    if not candidate:
        raise HTTPException(404, "Candidate not found")
    
    # Check organization access (same logic as send consent)
    candidate_org_id = str(candidate.get("organizationId", ""))
    user_org_id = str(user.get("organizationId", ""))
    user_role = user.get("role")
    
    has_access = False
    if user_role in ["SUPER_ADMIN", "SUPER_SPOC"]:
        has_access = True
    elif user_role == "SUPER_ADMIN_HELPER":
        accessible_orgs = user.get("accessibleOrganizations", [])
        has_access = candidate_org_id in [str(org) for org in accessible_orgs]
    elif user_role in ["ORG_HR", "SPOC"]:
        has_access = candidate_org_id == user_org_id
    
    if not has_access:
        raise HTTPException(403, "Not authorized to access this candidate")
    
    # Determine consent status
    consent_status = "NOT_REQUESTED"
    if candidate.get("consentRequested"):
        if candidate.get("consentAcknowledged") == True:
            consent_status = "CONSENT_GIVEN"
        elif candidate.get("consentAcknowledged") == False:
            consent_status = "CONSENT_DENIED"
        else:
            # Check if token expired
            token_expiry = candidate.get("consentTokenExpiry")
            if token_expiry and datetime.fromisoformat(token_expiry) < datetime.utcnow():
                consent_status = "TOKEN_EXPIRED"
            else:
                consent_status = "PENDING_CONSENT"
    
    # Construct candidate name from firstName and lastName
    candidate_name = f"{candidate.get('firstName', '')} {candidate.get('lastName', '')}".strip()
    if not candidate_name:
        candidate_name = candidate.get("email", "Unknown")
    
    return {
        "candidateId": candidateId,
        "candidateName": candidate_name,
        "candidateEmail": candidate.get("email"),
        "consentStatus": consent_status,
        "consentRequested": candidate.get("consentRequested", False),
        "consentRequestedAt": candidate.get("consentRequestedAt"),
        "consentRequestedBy": candidate.get("consentRequestedBy"),
        "consentAcknowledged": candidate.get("consentAcknowledged"),
        "consentDate": candidate.get("consentDate"),
        "consentSignature": candidate.get("consentSignature"),
        "verificationChecksRequested": candidate.get("verificationChecksRequested", []),
        "canStartVerification": consent_status == "CONSENT_GIVEN"
    }


# Removed duplicate verification overview endpoint - using existing /secure/getVerifications instead


# ============================================================
#                TICKET MANAGEMENT SYSTEM
# ============================================================

from utils.ticket_utils import (
    get_assignee, 
    calculate_sla_deadline, 
    notify_team, 
    generate_ticket_id,
    TICKET_CATEGORIES
)

# ------------------------------
# Get Available Ticket Categories
# ------------------------------
@app.get("/secure/ticket/categories")
async def getTicketCategories(user: dict = Depends(requireAuth)):
    """Return available ticket categories for UI dropdown"""
    
    categories = []
    for key, info in TICKET_CATEGORIES.items():
        categories.append({
            "value": key,
            "label": info["label"],
            "description": info["description"],
            "priority": info["priority"],
            "sla_hours": info["sla_hours"]
        })
    
    return {"categories": categories}


# ------------------------------
# Create Ticket
# ------------------------------
@app.post("/secure/ticket/create")
async def createTicket(body: dict = Body(...), user: dict = Depends(requireAuth)):
    """
    Create a support ticket with smart routing.
    
    Body:
    {
        "subject": "Cannot login to system",
        "description": "Getting 401 error when trying to login",
        "category": "IT_ISSUE",  // IT_ISSUE, VERIFICATION_ISSUE, HR_QUERY, etc.
        "priority": "HIGH",      // LOW, MEDIUM, HIGH, CRITICAL
        "attachments": []        // Optional file URLs
    }
    """
    
    subject = body.get("subject")
    description = body.get("description")
    category = body.get("category", "OTHER")
    priority = body.get("priority", "MEDIUM")
    attachments = body.get("attachments", [])
    
    if not subject or not description:
        raise HTTPException(status_code=400, detail="subject and description are required")
    
    if category not in TICKET_CATEGORIES:
        raise HTTPException(status_code=400, detail=f"Invalid category. Must be one of: {list(TICKET_CATEGORIES.keys())}")
    
    if priority not in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]:
        raise HTTPException(status_code=400, detail="Invalid priority")
    
    # Get user details
    role = user.get("role")
    userEmail = user.get("email")
    userName = user.get("userName")
    userOrgId = user.get("organizationId")
    
    # Fetch organization name
    orgName = None
    if userOrgId:
        try:
            org = await orgsCol.find_one({"_id": ObjectId(userOrgId)})
            if org:
                orgName = org.get("organizationName")
        except:
            pass
    
    # ✅ NEW WORKFLOW: ALL tickets assigned to BOTH SUPER_ADMIN AND SUPER_SPOC
    # Find all SUPER_ADMIN and SUPER_SPOC users
    superUsers = await usersCol.find({
        "role": {"$in": ["SUPER_ADMIN", "SUPER_SPOC"]},
        "isActive": True
    }).to_list(length=None)
    
    if not superUsers:
        # ❌ No SUPER_ADMIN or SUPER_SPOC available
        categoryLabel = TICKET_CATEGORIES.get(category, {}).get("label", category)
        raise HTTPException(
            status_code=503,
            detail=f"No administrators available to handle {categoryLabel} tickets. "
                   f"Please contact system administrator."
        )
    
    # Build assignees list (both SUPER_ADMIN and SUPER_SPOC)
    assignees = []
    assigneeEmails = []
    assigneeNames = []
    
    for admin in superUsers:
        assignees.append({
            "userId": str(admin["_id"]),
            "email": admin.get("email"),
            "name": admin.get("userName"),
            "role": admin.get("role")
        })
        assigneeEmails.append(admin.get("email"))
        assigneeNames.append(admin.get("userName"))
    
    # For backward compatibility, use first admin as primary assignee
    primaryAssignee = superUsers[0]
    assigneeId = str(primaryAssignee["_id"])
    assigneeEmail = primaryAssignee.get("email")
    assigneeName = primaryAssignee.get("userName")
    assigneeRole = primaryAssignee.get("role")
    
    # Calculate SLA deadline
    slaDeadline = calculate_sla_deadline(category, priority)
    
    # Generate ticket ID
    ticketId = generate_ticket_id()
    
    now = datetime.now(timezone.utc).isoformat()
    
    # Create ticket document
    ticketDoc = {
        "ticketId": ticketId,
        "subject": subject,
        "description": description,
        "category": category,
        "priority": priority,
        "status": "OPEN",
        "createdBy": userEmail,
        "createdByName": userName,
        "createdByRole": role,
        "organizationId": userOrgId,
        "organizationName": orgName,
        "assignedTo": assigneeId,  # Primary assignee (backward compatibility)
        "assignedToEmail": assigneeEmail,
        "assignedToName": assigneeName,
        "assignedToRole": assigneeRole,
        "assignees": assignees,  # ✅ NEW: List of all assignees
        "assigneeEmails": assigneeEmails,  # ✅ NEW: List of all assignee emails
        "attachments": attachments,
        "comments": [],
        "statusHistory": [{
            "status": "OPEN",
            "changedBy": userEmail,
            "changedAt": now,
            "comment": "Ticket created"
        }],
        "createdAt": now,
        "updatedAt": now,
        "slaDeadline": slaDeadline,
        "resolvedAt": None,
        "resolution": None
    }
    
    # Insert ticket
    result = await ticketsCol.insert_one(ticketDoc)
    
    # Log activity
    await logActivity(
        user,
        "Ticket Created",
        f"Ticket {ticketId} created: {subject} (Category: {category}, Priority: {priority})",
        "Success"
    )
    
    # Send email to ALL assignees (SUPER_ADMIN and SUPER_SPOC)
    for assignee in assignees:
        try:
            send_ticket_email(
                assignee["email"],
                f"[{priority}] New Ticket for Review: {subject}",
                f"""
Hi {assignee["name"]},

A new ticket has been created and requires your review and assignment:

Ticket ID: {ticketId}
Category: {category}
Priority: {priority}
Created By: {userName} ({userEmail})
Organization: {orgName or 'N/A'}

Subject: {subject}

Description:
{description}

SLA Deadline: {slaDeadline}

Please review this ticket and assign it to the appropriate support team member.

Assigned to: {', '.join(assigneeNames)}

Thanks,
BGVApp Support System
"""
            )
        except Exception as e:
            print(f"Failed to send email to {assignee['email']}: {e}")
    
    # Send email notification to assigned team for awareness
    try:
        await notify_team(category, ticketDoc, orgsCol)
    except Exception as e:
        print(f"Failed to send team notification: {e}")
    
    # Convert ObjectId to string for JSON response
    ticketResponse = {
        "_id": str(result.inserted_id),
        "ticketId": ticketId,
        "subject": subject,
        "description": description,
        "category": category,
        "priority": priority,
        "status": "OPEN",
        "createdBy": userEmail,
        "createdByName": userName,
        "createdByRole": role,
        "organizationId": str(userOrgId) if userOrgId else None,
        "organizationName": orgName,
        "assignedTo": assigneeId,
        "assignedToEmail": assigneeEmail,
        "assignedToName": assigneeName,
        "assignedToRole": assigneeRole,
        "assignees": assignees,  # ✅ NEW: List of all assignees
        "assigneeEmails": assigneeEmails,  # ✅ NEW: List of all assignee emails
        "attachments": attachments,
        "comments": [],
        "statusHistory": ticketDoc["statusHistory"],
        "createdAt": now,
        "updatedAt": now,
        "slaDeadline": slaDeadline,
        "resolvedAt": None,
        "resolution": None
    }
    
    return {
        "message": "Ticket created successfully and assigned for review",
        "ticketId": ticketId,
        "assignedTo": ", ".join(assigneeNames),  # Show all assignees
        "assignees": assignees,  # ✅ NEW: Full assignee details
        "slaDeadline": slaDeadline,
        "note": f"Ticket assigned to {len(assignees)} administrator(s) for review and reassignment to appropriate support team",
        "ticket": ticketResponse
    }


# ------------------------------
# Get Tickets (with role-based filtering)
# ------------------------------
@app.get("/secure/ticket/list")
async def getTickets(
    status: Optional[str] = Query(None),
    category: Optional[str] = Query(None),
    priority: Optional[str] = Query(None),
    assignedToMe: Optional[bool] = Query(False, description="Show only tickets assigned to me"),
    user: dict = Depends(requireAuth)
):
    """
    Get tickets based on user role with smart filtering:
    - SUPER_ADMIN/SUPER_SPOC: All tickets
    - SUPER_ADMIN_HELPER: Tickets from accessible orgs
    - IT_SUPPORT: IT tickets assigned to them or from accessible orgs
    - VERIFICATION_SUPPORT: Verification tickets from accessible orgs
    - SPOC/ORG_HR: Tickets from their org
    - HELPER: Only tickets they created
    
    Query Params:
    - status: Filter by status (OPEN, IN_PROGRESS, RESOLVED, CLOSED)
    - category: Filter by category (IT_ISSUE, VERIFICATION_ISSUE, etc.)
    - priority: Filter by priority (LOW, MEDIUM, HIGH, CRITICAL)
    - assignedToMe: Show only tickets assigned to current user
    """
    
    role = user.get("role")
    userEmail = user.get("email")
    userId = str(user.get("_id"))
    userOrgId = user.get("organizationId")
    accessible = user.get("accessibleOrganizations", [])
    
    # Build query
    query = {}
    
    # ================================================================
    # ROLE-BASED FILTERING
    # ================================================================
    
    if role in ["SUPER_ADMIN", "SUPER_SPOC"]:
        # See all tickets (no filter)
        pass
    
    elif role == "SUPER_ADMIN_HELPER":
        # See tickets from accessible orgs OR assigned to them
        if accessible:
            query["$or"] = [
                {"organizationId": {"$in": [str(x) for x in accessible]}},
                {"assignedToEmail": userEmail}  # ✅ Can see tickets assigned to them
            ]
        else:
            # No accessible orgs = only see tickets assigned to them
            query["assignedToEmail"] = userEmail
    
    elif role == "IT_SUPPORT":
        # ✅ NEW: IT Support sees only IT-related tickets
        query["category"] = "IT_ISSUE"
        
        # From accessible orgs OR assigned to them
        if accessible:
            query["$or"] = [
                {"organizationId": {"$in": [str(x) for x in accessible]}},
                {"assignedToEmail": userEmail}
            ]
        else:
            query["assignedToEmail"] = userEmail
    
    elif role == "VERIFICATION_SUPPORT":
        # ✅ NEW: Verification Support sees only verification tickets
        query["category"] = "VERIFICATION_ISSUE"
        
        if accessible:
            query["organizationId"] = {"$in": [str(x) for x in accessible]}
        else:
            query["assignedToEmail"] = userEmail
    
    elif role == "GENERAL_SUPPORT":
        # ✅ NEW: General Support sees all categories
        if accessible:
            query["organizationId"] = {"$in": [str(x) for x in accessible]}
        else:
            query["assignedToEmail"] = userEmail
    
    elif role in ["SPOC", "ORG_HR"]:
        # See tickets from their org
        query["organizationId"] = userOrgId
    
    elif role == "HELPER":
        # See only tickets they created
        query["createdBy"] = userEmail
    
    else:
        raise HTTPException(status_code=403, detail="Not authorized")
    
    # ================================================================
    # ADDITIONAL FILTERS
    # ================================================================
    
    # Filter by assigned to me (check both old and new format)
    if assignedToMe:
        query["$or"] = [
            {"assignedToEmail": userEmail},  # Old format (single assignee)
            {"assigneeEmails": {"$in": [userEmail]}}  # New format (multiple assignees)
        ]
    
    # Filter by status
    if status:
        query["status"] = status.upper()
    
    # Filter by category (if not already set by role)
    if category and "category" not in query:
        query["category"] = category.upper()
    
    # Filter by priority
    if priority:
        query["priority"] = priority.upper()
    
    # ================================================================
    # FETCH TICKETS
    # ================================================================
    
    tickets_cursor = ticketsCol.find(query).sort("createdAt", -1)
    tickets = []
    
    async for ticket in tickets_cursor:
        ticket["_id"] = str(ticket["_id"])
        tickets.append(ticket)
    
    await logActivity(
        user,
        "View Tickets",
        f"{userEmail} ({role}) viewed {len(tickets)} tickets with filters: {query}",
        "Success"
    )
    
    return {
        "total": len(tickets),
        "tickets": tickets,
        "filters": {
            "role": role,
            "assignedToMe": assignedToMe,
            "status": status,
            "category": category,
            "priority": priority
        }
    }


# ------------------------------
# Get Single Ticket
# ------------------------------
@app.get("/secure/ticket/{ticketId}")
async def getTicket(ticketId: str, user: dict = Depends(requireAuth)):
    """Get ticket details with authorization check"""
    
    ticket = await ticketsCol.find_one({"ticketId": ticketId})
    
    if not ticket:
        raise HTTPException(status_code=404, detail="Ticket not found")
    
    # Authorization check
    role = user.get("role")
    userEmail = user.get("email")
    userOrgId = user.get("organizationId")
    accessible = user.get("accessibleOrganizations", [])
    
    allowed = False
    
    if role in ["SUPER_ADMIN", "SUPER_SPOC"]:
        allowed = True
    elif role == "SUPER_ADMIN_HELPER":
        if ticket.get("organizationId") in [str(x) for x in accessible]:
            allowed = True
    elif role in ["SPOC", "ORG_HR"]:
        if ticket.get("organizationId") == userOrgId:
            allowed = True
    elif role == "HELPER":
        if ticket.get("createdBy") == userEmail or ticket.get("assignedToEmail") == userEmail:
            allowed = True
    
    if not allowed:
        raise HTTPException(status_code=403, detail="Not authorized to view this ticket")
    
    ticket["_id"] = str(ticket["_id"])
    return ticket


# ------------------------------
# Update Ticket Status
# ------------------------------
@app.put("/secure/ticket/{ticketId}/status")
async def updateTicketStatus(
    ticketId: str,
    body: dict = Body(...),
    user: dict = Depends(requireAuth)
):
    """
    Update ticket status.
    
    Body:
    {
        "status": "IN_PROGRESS" | "RESOLVED" | "CLOSED" | "REOPENED",
        "comment": "Working on this issue",
        "resolution": "Fixed by restarting server"  // Required for RESOLVED
    }
    """
    
    newStatus = body.get("status")
    comment = body.get("comment", "")
    resolution = body.get("resolution")
    
    if not newStatus:
        raise HTTPException(status_code=400, detail="status is required")
    
    if newStatus not in ["OPEN", "IN_PROGRESS", "RESOLVED", "CLOSED", "REOPENED"]:
        raise HTTPException(status_code=400, detail="Invalid status")
    
    if newStatus == "RESOLVED" and not resolution:
        raise HTTPException(status_code=400, detail="resolution is required for RESOLVED status")
    
    # Find ticket
    ticket = await ticketsCol.find_one({"ticketId": ticketId})
    if not ticket:
        raise HTTPException(status_code=404, detail="Ticket not found")
    
    # Authorization: Only assignee or admins can update
    role = user.get("role")
    userEmail = user.get("email")
    accessible = user.get("accessibleOrganizations", [])
    
    allowed = False
    
    # SUPER_ADMIN / SUPER_SPOC → full access
    if role in ["SUPER_ADMIN", "SUPER_SPOC"]:
        allowed = True
    
    # Assigned to this user → can update (check both formats)
    elif (ticket.get("assignedToEmail") == userEmail or 
          userEmail in ticket.get("assigneeEmails", [])):
        allowed = True
    
    # SPOC / ORG_HR → can update tickets in their org
    elif role in ["SPOC", "ORG_HR"] and ticket.get("organizationId") == user.get("organizationId"):
        allowed = True
    
    # ✅ NEW: IT_SUPPORT → can update IT tickets from accessible orgs
    elif role == "IT_SUPPORT":
        if ticket.get("category") == "IT_ISSUE":
            if not accessible or ticket.get("organizationId") in [str(x) for x in accessible]:
                allowed = True
    
    # ✅ NEW: VERIFICATION_SUPPORT → can update verification tickets
    elif role == "VERIFICATION_SUPPORT":
        if ticket.get("category") == "VERIFICATION_ISSUE":
            if not accessible or ticket.get("organizationId") in [str(x) for x in accessible]:
                allowed = True
    
    # ✅ NEW: GENERAL_SUPPORT → can update any ticket from accessible orgs
    elif role == "GENERAL_SUPPORT":
        if not accessible or ticket.get("organizationId") in [str(x) for x in accessible]:
            allowed = True
    
    # ✅ NEW: SUPER_ADMIN_HELPER → can update tickets assigned to them
    elif role == "SUPER_ADMIN_HELPER":
        if (ticket.get("assignedToEmail") == userEmail or 
            userEmail in ticket.get("assigneeEmails", [])):
            allowed = True
    
    if not allowed:
        raise HTTPException(status_code=403, detail="Only assigned user or admins can update ticket")
    
    # Update ticket
    now = datetime.now(timezone.utc).isoformat()
    
    # Build update operations
    setData = {
        "status": newStatus,
        "updatedAt": now
    }
    
    if newStatus == "RESOLVED":
        setData["resolvedAt"] = now
        setData["resolution"] = resolution
    
    # Perform update with both $set and $push
    await ticketsCol.update_one(
        {"ticketId": ticketId},
        {
            "$set": setData,
            "$push": {
                "statusHistory": {
                    "status": newStatus,
                    "changedBy": userEmail,
                    "changedAt": now,
                    "comment": comment
                }
            }
        }
    )
    
    # Log activity
    await logActivity(
        user,
        "Ticket Status Updated",
        f"Ticket {ticketId} status changed to {newStatus}",
        "Success"
    )
    
    # Send email to creator
    try:
        send_ticket_email(
            ticket.get("createdBy"),
            f"Ticket {ticketId} Status Updated: {newStatus}",
            f"""
Hi {ticket.get("createdByName")},

Your ticket has been updated:

Ticket ID: {ticketId}
Subject: {ticket.get("subject")}
New Status: {newStatus}
Updated By: {user.get("userName")} ({userEmail})

Comment: {comment}

{f"Resolution: {resolution}" if resolution else ""}

Thanks,
BGVApp Support Team
"""
        )
    except Exception as e:
        print(f"Failed to send status update email: {e}")
    
    return {"message": "Ticket status updated successfully"}


# ------------------------------
# Add Comment to Ticket
# ------------------------------
@app.post("/secure/ticket/{ticketId}/comment")
async def addTicketComment(
    ticketId: str,
    body: dict = Body(...),
    user: dict = Depends(requireAuth)
):
    """Add a comment to a ticket"""
    
    comment = body.get("comment")
    
    if not comment:
        raise HTTPException(status_code=400, detail="comment is required")
    
    # Find ticket
    ticket = await ticketsCol.find_one({"ticketId": ticketId})
    if not ticket:
        raise HTTPException(status_code=404, detail="Ticket not found")
    
    # ✅ NEW AUTHORIZATION: Only specific roles can comment
    role = user.get("role")
    userEmail = user.get("email")
    
    allowed = False
    
    # 1. SUPER_ADMIN / SUPER_SPOC → can comment on any ticket
    if role in ["SUPER_ADMIN", "SUPER_SPOC"]:
        allowed = True
    
    # 2. Ticket creator (ORG_HR/HELPER who created it) → can comment
    elif ticket.get("createdBy") == userEmail:
        allowed = True
    
    # 3. Currently assigned user → can comment (check both formats)
    elif (ticket.get("assignedToEmail") == userEmail or 
          userEmail in ticket.get("assigneeEmails", [])):
        allowed = True
    
    # 4. ORG_HR/SPOC from same organization → can comment
    elif role in ["SPOC", "ORG_HR"] and ticket.get("organizationId") == user.get("organizationId"):
        allowed = True
    
    # ❌ All other users cannot comment
    if not allowed:
        raise HTTPException(status_code=403, detail="Only ticket creator, assignee, or organization admins can comment")
    
    # Add comment
    now = datetime.now(timezone.utc).isoformat()
    
    commentObj = {
        "comment": comment,
        "commentedBy": userEmail,
        "commentedByName": user.get("userName"),
        "commentedByRole": role,
        "commentedAt": now
    }
    
    await ticketsCol.update_one(
        {"ticketId": ticketId},
        {
            "$push": {"comments": commentObj},
            "$set": {"updatedAt": now}
        }
    )
    
    # Log activity
    await logActivity(
        user,
        "Ticket Comment Added",
        f"Comment added to ticket {ticketId}",
        "Success"
    )
    
    return {"message": "Comment added successfully", "comment": commentObj}


# ------------------------------
# Reassign Ticket
# ------------------------------
@app.put("/secure/ticket/{ticketId}/reassign")
async def reassignTicket(
    ticketId: str,
    body: dict = Body(...),
    user: dict = Depends(requireAuth)
):
    """Reassign ticket to another user (admin only)"""
    
    newAssigneeEmail = body.get("assignedToEmail")
    reason = body.get("reason", "")
    
    if not newAssigneeEmail:
        raise HTTPException(status_code=400, detail="assignedToEmail is required")
    
    # Find ticket first
    ticket = await ticketsCol.find_one({"ticketId": ticketId})
    if not ticket:
        raise HTTPException(status_code=404, detail="Ticket not found")
    
    # ✅ NEW: Admins OR assigned person can reassign
    role = user.get("role")
    userEmail = user.get("email")
    isAssignee = ticket.get("assignedToEmail") == userEmail
    
    if role not in ["SUPER_ADMIN", "SUPER_SPOC", "SPOC", "ORG_HR"] and not isAssignee:
        raise HTTPException(status_code=403, detail="Only admins or the assigned person can reassign tickets")
    
    # Find new assignee
    newAssignee = await usersCol.find_one({"email": newAssigneeEmail, "isActive": True})
    if not newAssignee:
        raise HTTPException(status_code=404, detail="Assignee not found or inactive")
    
    # ✅ Check if new assignee has access to ticket's organization
    ticketOrgId = ticket.get("organizationId")
    assigneeRole = newAssignee.get("role")
    assigneeAccessibleOrgs = newAssignee.get("accessibleOrganizations", [])
    
    # SUPER_ADMIN and SUPER_SPOC have access to all orgs
    if assigneeRole not in ["SUPER_ADMIN", "SUPER_SPOC"]:
        # For other roles, check if they have access to this org
        if assigneeRole == "SUPER_ADMIN_HELPER":
            if ticketOrgId not in [str(x) for x in assigneeAccessibleOrgs]:
                raise HTTPException(
                    status_code=403,
                    detail=f"User '{newAssigneeEmail}' does not have access to organization '{ticket.get('organizationName')}'. "
                           f"Please add this organization to their accessibleOrganizations."
                )
        elif assigneeRole in ["SPOC", "ORG_HR", "HELPER"]:
            # Must be from the same organization
            if str(newAssignee.get("organizationId")) != ticketOrgId:
                raise HTTPException(
                    status_code=403,
                    detail=f"User '{newAssigneeEmail}' belongs to a different organization and cannot be assigned this ticket."
                )
    
    # 🔥 NEW: Category-based role validation
    ticketCategory = ticket.get("category", "OTHER")
    categoryInfo = TICKET_CATEGORIES.get(ticketCategory, TICKET_CATEGORIES["OTHER"])
    targetTeam = categoryInfo["assignTo"]
    
    # Define role mappings for each team category
    TEAM_ROLE_MAPPING = {
        "IT_TEAM": ["SUPER_ADMIN", "SUPER_SPOC", "SUPER_ADMIN_HELPER", "IT_SUPPORT", "TECHNICAL_SUPPORT", "HELPER"],
        "VERIFICATION_TEAM": ["SUPER_ADMIN", "SUPER_SPOC", "SUPER_ADMIN_HELPER", "VERIFICATION_SPECIALIST", "ORG_HR", "HELPER"],
        "HR_TEAM": ["SUPER_ADMIN", "SUPER_SPOC", "SUPER_ADMIN_HELPER", "HR_SPECIALIST", "ORG_HR", "HELPER"],
        "FINANCE_TEAM": ["SUPER_ADMIN", "SUPER_SPOC", "SUPER_ADMIN_HELPER", "FINANCE_SPECIALIST", "SPOC", "ORG_HR"],
        "PRODUCT_TEAM": ["SUPER_ADMIN", "SUPER_SPOC", "SUPER_ADMIN_HELPER", "PRODUCT_MANAGER", "SPOC"],
        "DEV_TEAM": ["SUPER_ADMIN", "SUPER_SPOC", "SUPER_ADMIN_HELPER", "DEVELOPER", "TECHNICAL_LEAD", "SPOC"],
        "SUPPORT_TEAM": ["SUPER_ADMIN", "SUPER_SPOC", "SUPER_ADMIN_HELPER", "SUPPORT_SPECIALIST", "ORG_HR", "HELPER"]
    }
    
    # Check if assignee role is valid for the ticket category
    allowedRoles = TEAM_ROLE_MAPPING.get(targetTeam, ["SUPER_ADMIN", "SUPER_SPOC", "SUPER_ADMIN_HELPER", "ORG_HR", "HELPER"])
    
    if assigneeRole not in allowedRoles:
        raise HTTPException(
            status_code=403,
            detail=f"User role '{assigneeRole}' is not authorized to handle {categoryInfo['label']} tickets. "
                   f"This ticket requires one of these roles: {', '.join(allowedRoles)}. "
                   f"Please assign to a user with appropriate role for {targetTeam}."
        )
    
    # Update ticket with new assignee
    now = datetime.now(timezone.utc).isoformat()
    
    # Build new assignee object
    newAssigneeObj = {
        "userId": str(newAssignee["_id"]),
        "email": newAssignee.get("email"),
        "name": newAssignee.get("userName"),
        "role": newAssignee.get("role")
    }
    
    await ticketsCol.update_one(
        {"ticketId": ticketId},
        {
            "$set": {
                # Single assignee fields (for backward compatibility)
                "assignedTo": str(newAssignee["_id"]),
                "assignedToEmail": newAssignee.get("email"),
                "assignedToName": newAssignee.get("userName"),
                "assignedToRole": newAssignee.get("role"),
                # 🔥 NEW: Update assignees array to reflect new assignee
                "assignees": [newAssigneeObj],
                "assigneeEmails": [newAssignee.get("email")],
                "updatedAt": now
            },
            "$push": {
                "statusHistory": {
                    "status": "REASSIGNED",
                    "changedBy": user.get("email"),
                    "changedAt": now,
                    "comment": f"Reassigned to {newAssignee.get('userName')}. Reason: {reason}"
                }
            }
        }
    )
    
    # Log activity
    await logActivity(
        user,
        "Ticket Reassigned",
        f"Ticket {ticketId} reassigned to {newAssigneeEmail}",
        "Success"
    )
    
    # Send email to new assignee
    try:
        send_ticket_email(
            newAssigneeEmail,
            f"Ticket {ticketId} Assigned to You",
            f"""
Hi {newAssignee.get("userName")},

A ticket has been reassigned to you:

Ticket ID: {ticketId}
Subject: {ticket.get("subject")}
Category: {ticket.get("category")}
Priority: {ticket.get("priority")}
Reassigned By: {user.get("userName")}

Reason: {reason}

Please review and respond.

Thanks,
BGVApp Support System
"""
        )
    except Exception as e:
        print(f"Failed to send reassignment email: {e}")
    
    return {"message": "Ticket reassigned successfully"}


# ------------------------------
# Get Available Assignees for Ticket
# ------------------------------
@app.get("/secure/ticket/{ticketId}/available-assignees")
async def getAvailableAssignees(ticketId: str, user: dict = Depends(requireAuth)):
    """
    Get list of users who can be assigned to this ticket based on category and organization access.
    Only SUPER_ADMIN and SUPER_SPOC can access this endpoint.
    """
    
    # Authorization check
    if user.get("role") not in ["SUPER_ADMIN", "SUPER_SPOC"]:
        raise HTTPException(403, "Only SUPER_ADMIN and SUPER_SPOC can view available assignees")

    # Fetch ticket
    ticket = await ticketsCol.find_one({"ticketId": ticketId})
    if not ticket:
        raise HTTPException(404, "Ticket not found")

    ticketOrgId = ticket.get("organizationId")
    ticketCategory = ticket.get("category", "OTHER")
    
    # Get category info
    categoryInfo = TICKET_CATEGORIES.get(ticketCategory, TICKET_CATEGORIES["OTHER"])
    targetTeam = categoryInfo["assignTo"]
    
    # Define role mappings for each team category
    TEAM_ROLE_MAPPING = {
        "IT_TEAM": ["SUPER_ADMIN", "SUPER_SPOC", "SUPER_ADMIN_HELPER", "IT_SUPPORT", "TECHNICAL_SUPPORT", "HELPER"],
        "VERIFICATION_TEAM": ["SUPER_ADMIN", "SUPER_SPOC", "SUPER_ADMIN_HELPER", "VERIFICATION_SPECIALIST", "ORG_HR", "HELPER"],
        "HR_TEAM": ["SUPER_ADMIN", "SUPER_SPOC", "SUPER_ADMIN_HELPER", "HR_SPECIALIST", "ORG_HR", "HELPER"],
        "FINANCE_TEAM": ["SUPER_ADMIN", "SUPER_SPOC", "SUPER_ADMIN_HELPER", "FINANCE_SPECIALIST", "SPOC", "ORG_HR"],
        "PRODUCT_TEAM": ["SUPER_ADMIN", "SUPER_SPOC", "SUPER_ADMIN_HELPER", "PRODUCT_MANAGER", "SPOC"],
        "DEV_TEAM": ["SUPER_ADMIN", "SUPER_SPOC", "SUPER_ADMIN_HELPER", "DEVELOPER", "TECHNICAL_LEAD", "SPOC"],
        "SUPPORT_TEAM": ["SUPER_ADMIN", "SUPER_SPOC", "SUPER_ADMIN_HELPER", "SUPPORT_SPECIALIST", "ORG_HR", "HELPER"]
    }
    
    allowedRoles = TEAM_ROLE_MAPPING.get(targetTeam, ["SUPER_ADMIN", "SUPER_SPOC", "SUPER_ADMIN_HELPER", "ORG_HR", "HELPER"])
    
    # Build query for finding eligible users
    userQuery = {
        "role": {"$in": allowedRoles},
        "isActive": True
    }
    
    # Find users with appropriate roles
    allEligibleUsers = await usersCol.find(userQuery).to_list(length=None)
    
    # Filter by organization access
    availableUsers = []
    
    for user_doc in allEligibleUsers:
        userRole = user_doc.get("role")
        userOrgId = str(user_doc.get("organizationId", ""))
        userAccessibleOrgs = [str(x) for x in user_doc.get("accessibleOrganizations", [])]
        
        # Check organization access
        hasOrgAccess = False
        
        if userRole in ["SUPER_ADMIN", "SUPER_SPOC"]:
            # SUPER_ADMIN and SUPER_SPOC have access to all orgs
            hasOrgAccess = True
        elif userRole == "SUPER_ADMIN_HELPER":
            # Must have this org in accessibleOrganizations
            hasOrgAccess = ticketOrgId in userAccessibleOrgs
        elif userRole in ["SPOC", "ORG_HR", "HELPER"]:
            # 🔥 FIXED: Only include BGV support staff, not regular client org users
            # Regular client org users should handle tickets through their own workflow
            # Only BGV central support staff should be assignable by SUPER_ADMIN
            
            # Define BGV central organization ID (where support staff belong)
            BGV_CENTRAL_ORG_ID = "68ffb000e4b2a7e23ccf1e50"  # Update this to your BGV org ID
            
            # Only include users who are BGV support staff (from central org)
            # AND have access to the ticket's organization
            if userOrgId == BGV_CENTRAL_ORG_ID:
                # BGV support staff - check if they have access to ticket's org
                if hasattr(user_doc, 'accessibleOrganizations') and user_doc.get('accessibleOrganizations'):
                    # Support staff with specific org access
                    hasOrgAccess = ticketOrgId in userAccessibleOrgs
                else:
                    # Support staff from same org as ticket (if BGV is handling their own tickets)
                    hasOrgAccess = userOrgId == ticketOrgId
            else:
                # Regular client org users - exclude from SUPER_ADMIN assignable list
                hasOrgAccess = False
        
        if hasOrgAccess:
            availableUsers.append({
                "userId": str(user_doc["_id"]),
                "email": user_doc["email"],
                "name": user_doc.get("userName", user_doc["email"]),
                "role": user_doc["role"],
                "organizationId": userOrgId,
                "phoneNumber": user_doc.get("phoneNumber", ""),
                "accessibleOrganizations": userAccessibleOrgs if userRole == "SUPER_ADMIN_HELPER" else []
            })
    
    return {
        "ticketId": ticketId,
        "category": categoryInfo["label"],
        "targetTeam": targetTeam,
        "allowedRoles": allowedRoles,
        "availableAssignees": availableUsers,
        "organizationId": ticketOrgId,
        "organizationName": ticket.get("organizationName", "Unknown")
    }

# ---------------------------------------------------
# 📌 Internal Verification Endpoints
# ---------------------------------------------------

@app.post("/secure/updateInternalVerification")
async def updateInternalVerification(body: dict = Body(...), user: dict = Depends(requireAuth)):
    """
    Update internal verification check status manually through UI
    
    Body:
    {
        "verificationId": "...",
        "stage": "primary|secondary|final",
        "checkName": "address_verification|education_check_manual|supervisory_check|employment_history_manual",
        "status": "COMPLETED|FAILED",
        "remarks": "manual verification notes",
        "attachments": [...] // optional
    }
    """
    
    verificationId = body.get("verificationId")
    stage = body.get("stage")
    checkName = body.get("checkName")
    status = body.get("status")
    remarks = body.get("remarks", "")
    attachments = body.get("attachments", [])
    
    if not all([verificationId, stage, checkName, status]):
        raise HTTPException(status_code=400, detail="verificationId, stage, checkName, and status are required")
    
    if status not in ["COMPLETED", "FAILED"]:
        raise HTTPException(status_code=400, detail="Status must be COMPLETED or FAILED")
    
    # Internal verification checks that can be manually updated
    internal_checks = [
        "address_verification",
        "education_check_manual", 
        "supervisory_check",
        "employment_history_manual"
    ]
    
    if checkName not in internal_checks:
        raise HTTPException(status_code=400, detail=f"Check {checkName} is not an internal verification check")
    
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
    
    # Role-based access control
    role = user.get("role")
    userEmail = user.get("email", "").lower().strip()
    userOrgId = str(user.get("organizationId"))
    accessible = [str(x) for x in user.get("accessibleOrganizations", [])]
    
    allowed = False
    
    if role in ["SUPER_ADMIN", "SUPER_SPOC"]:
        allowed = True
    elif role == "SPOC" and ("@bgv.local" in userEmail or "bgvapp.in" in userEmail):
        allowed = True
    elif role == "SUPER_ADMIN_HELPER":
        if verificationOrgId in accessible:
            allowed = True
    elif role in ["ORG_HR", "SPOC"]:
        if verificationOrgId == userOrgId:
            allowed = True
    elif role == "HELPER":
        if verificationOrgId == userOrgId:
            # Check if user created the candidate or is assigned to verification
            candidate = await candidatesCol.find_one({"_id": ObjectId(candidateId)})
            if (candidate and candidate.get("createdBy", "").lower().strip() == userEmail) or \
               str(ver.get("assignedTo")) == str(user.get("_id")):
                allowed = True
    
    if not allowed:
        raise HTTPException(status_code=403, detail="You are not authorized to update this verification")
    
    # Find and update the specific check
    stages = ver.get("stages", {})
    stageChecks = stages.get(stage, [])
    
    checkFound = False
    for i, check in enumerate(stageChecks):
        if isinstance(check, dict) and check.get("check") == checkName:
            # Update the check
            stageChecks[i]["status"] = status
            stageChecks[i]["remarks"] = remarks
            stageChecks[i]["submittedAt"] = datetime.now(timezone.utc).isoformat()
            stageChecks[i]["updatedBy"] = userEmail
            if attachments:
                stageChecks[i]["attachments"] = attachments
            checkFound = True
            break
    
    if not checkFound:
        raise HTTPException(status_code=404, detail=f"Check {checkName} not found in stage {stage}")
    
    # Update the verification document
    await verificationsCol.update_one(
        {"_id": verObjId},
        {"$set": {f"stages.{stage}": stageChecks}}
    )
    
    # ✅ CHECK IF STAGE IS COMPLETE AND UPDATE OVERALL STATUS
    verification = await verificationsCol.find_one({"_id": verObjId})
    current_stage = verification.get("currentStage")
    stage_checks = verification.get("stages", {}).get(current_stage, [])
    
    # Check if all checks in current stage are COMPLETED
    all_completed = all(
        check.get("status") == "COMPLETED" 
        for check in stage_checks
    )
    
    if all_completed:
        # Determine next stage or mark as complete
        if current_stage == "primary":
            next_stage = "secondary"
        elif current_stage == "secondary":
            next_stage = "final"
        elif current_stage == "final":
            # All stages complete - mark verification as COMPLETED
            await verificationsCol.update_one(
                {"_id": verObjId},
                {"$set": {
                    "overallStatus": "COMPLETED",
                    "completedAt": datetime.now(timezone.utc).isoformat()
                }}
            )
            
            # Update candidate status
            await candidatesCol.update_one(
                {"_id": ObjectId(candidateId)},
                {"$set": {"status": "VERIFIED"}}
            )
            next_stage = None
        else:
            next_stage = None
        
        # Move to next stage if applicable
        if next_stage and next_stage in verification.get("stages", {}):
            await verificationsCol.update_one(
                {"_id": verObjId},
                {"$set": {"currentStage": next_stage}}
            )
    
    # Log activity
    await logActivity(
        user,
        "Internal Verification Updated",
        f"Updated {checkName} in {stage} stage to {status}",
        "Success"
    )
    
    return JSONResponse(
        status_code=200,
        content={
            "message": f"Internal verification {checkName} updated successfully",
            "verificationId": verificationId,
            "stage": stage,
            "checkName": checkName,
            "status": status,
            "updatedBy": userEmail,
            "updatedAt": datetime.now(timezone.utc).isoformat()
        }
    )


@app.get("/secure/getInternalVerificationDetails/{verificationId}")
async def getInternalVerificationDetails(verificationId: str, user: dict = Depends(requireAuth)):
    """
    Get details of internal verification checks for manual review
    """
    
    try:
        verObjId = ObjectId(verificationId)
    except:
        raise HTTPException(status_code=400, detail="Invalid verificationId")
    
    ver = await verificationsCol.find_one({"_id": verObjId})
    if not ver:
        raise HTTPException(status_code=404, detail="Verification not found")
    
    verificationOrgId = str(ver.get("organizationId"))
    candidateId = ver.get("candidateId")
    
    # Role-based access control (same as update endpoint)
    role = user.get("role")
    userEmail = user.get("email", "").lower().strip()
    userOrgId = str(user.get("organizationId"))
    accessible = [str(x) for x in user.get("accessibleOrganizations", [])]
    
    allowed = False
    
    if role in ["SUPER_ADMIN", "SUPER_SPOC"]:
        allowed = True
    elif role == "SPOC" and ("@bgv.local" in userEmail or "bgvapp.in" in userEmail):
        allowed = True
    elif role == "SUPER_ADMIN_HELPER":
        if verificationOrgId in accessible:
            allowed = True
    elif role in ["ORG_HR", "SPOC"]:
        if verificationOrgId == userOrgId:
            allowed = True
    elif role == "HELPER":
        if verificationOrgId == userOrgId:
            candidate = await candidatesCol.find_one({"_id": ObjectId(candidateId)})
            if (candidate and candidate.get("createdBy", "").lower().strip() == userEmail) or \
               str(ver.get("assignedTo")) == str(user.get("_id")):
                allowed = True
    
    if not allowed:
        raise HTTPException(status_code=403, detail="You are not authorized to view this verification")
    
    # Get candidate details
    candidate = await candidatesCol.find_one({"_id": ObjectId(candidateId)})
    if not candidate:
        raise HTTPException(status_code=404, detail="Candidate not found")
    
    # Extract internal verification checks
    internal_checks = [
        "address_verification",
        "education_check_manual", 
        "supervisory_check",
        "employment_history_manual"
    ]
    
    internalVerifications = {}
    
    for stageName, checks in ver.get("stages", {}).items():
        stageInternals = []
        for check in checks:
            if isinstance(check, dict):
                checkName = check.get("check")
                if checkName in internal_checks:
                    stageInternals.append({
                        "checkName": checkName,
                        "status": check.get("status", "NOT_STARTED"),
                        "remarks": check.get("remarks", ""),
                        "submittedAt": check.get("submittedAt"),
                        "updatedBy": check.get("updatedBy"),
                        "attachments": check.get("attachments", []),
                        "requiresManualVerification": True  # All checks require manual verification now
                    })
        
        if stageInternals:
            internalVerifications[stageName] = stageInternals
    
    return JSONResponse(
        status_code=200,
        content=jsonable_encoder({
            "verificationId": verificationId,
            "candidateId": candidateId,
            "candidateDetails": {
                "name": f"{candidate.get('firstName', '')} {candidate.get('lastName', '')}".strip(),
                "email": candidate.get("email"),
                "phone": candidate.get("phone"),
                "address": candidate.get("address"),
                "district": candidate.get("district"),
                "state": candidate.get("state"),
                "pincode": candidate.get("pincode")
            },
            "organizationId": verificationOrgId,
            "organizationName": ver.get("organizationName"),
            "overallStatus": ver.get("overallStatus"),
            "currentStage": ver.get("currentStage"),
            "internalVerifications": internalVerifications
        })
    )


@app.post("/secure/uploadEducationCertificate")
async def uploadEducationCertificate(
    candidateId: str = Form(...),
    file: UploadFile = File(...),
    user: dict = Depends(requireAuth)
):
    """
    Upload education certificate for AI verification
    """
    
    if not file.filename.lower().endswith(('.pdf', '.docx')):
        raise HTTPException(status_code=400, detail="Only PDF and DOCX files are allowed")
    
    try:
        candidateObjId = ObjectId(candidateId)
    except:
        raise HTTPException(status_code=400, detail="Invalid candidateId")
    
    candidate = await candidatesCol.find_one({"_id": candidateObjId})
    if not candidate:
        raise HTTPException(status_code=404, detail="Candidate not found")
    
    candidateOrgId = str(candidate.get("organizationId"))
    
    # Role-based access control
    role = user.get("role")
    userEmail = user.get("email", "").lower().strip()
    userOrgId = str(user.get("organizationId"))
    accessible = [str(x) for x in user.get("accessibleOrganizations", [])]
    
    allowed = False
    
    if role in ["SUPER_ADMIN", "SUPER_SPOC"]:
        allowed = True
    elif role == "SPOC" and ("@bgv.local" in userEmail or "bgvapp.in" in userEmail):
        allowed = True
    elif role == "SUPER_ADMIN_HELPER":
        if candidateOrgId in accessible:
            allowed = True
    elif role in ["ORG_HR", "SPOC"]:
        if candidateOrgId == userOrgId:
            allowed = True
    elif role == "HELPER":
        if candidateOrgId == userOrgId and candidate.get("createdBy", "").lower().strip() == userEmail:
            allowed = True
    
    if not allowed:
        raise HTTPException(status_code=403, detail="You are not authorized to upload files for this candidate")
    
    # Save file (you may want to implement proper file storage)
    import os
    upload_dir = "uploads/education_certificates"
    os.makedirs(upload_dir, exist_ok=True)
    
    file_extension = file.filename.split('.')[-1]
    filename = f"{candidateId}_education_cert_{int(datetime.now().timestamp())}.{file_extension}"
    file_path = os.path.join(upload_dir, filename)
    
    with open(file_path, "wb") as buffer:
        content = await file.read()
        buffer.write(content)
    
    # Update candidate with certificate path
    await candidatesCol.update_one(
        {"_id": candidateObjId},
        {"$set": {"educationCertificatePath": file_path}}
    )
    
    await logActivity(
        user,
        "Education Certificate Uploaded",
        f"Uploaded certificate for candidate {candidateId}",
        "Success"
    )
    
    return JSONResponse(
        status_code=200,
        content={
            "message": "Education certificate uploaded successfully",
            "candidateId": candidateId,
            "filename": filename,
            "filePath": file_path
        }
    )


# ------------------------------------------------
# 📌 AI CV VALIDATION ENDPOINT
# ------------------------------------------------

@app.post("/secure/ai_cv_validation")
async def ai_cv_validation(
    verificationId: str = Form(...),
    panNumber: str = Form(None),  # Optional - PAN to check UAN
    hasUan: str = Form(None),  # Optional - "yes"/"no" to manually specify UAN status
    resume: UploadFile = File(None),  # Optional - upload file directly
    user: dict = Depends(requireAuth)
):
    """
    AI CV Authenticity Validation - Check resume for abnormalities, overlaps, and inconsistencies
    NO JD required - pure authenticity check
    
    Parameters:
    - verificationId: The verification record ID
    - panNumber: Candidate's PAN number (optional - will check if UAN exists)
    - hasUan: Manual override - "yes" or "no" (optional - skips API call if provided)
    - resume: Optional resume file upload (PDF/DOCX)
    
    Resume Source Priority:
    1. If 'resume' file provided → use uploaded file (temp storage)
    2. Else → fetch from candidate.resumePath (supports both local path and S3 URL)
    """
    
    try:
        # Verify verification record exists and user has access
        verificationObjId = ObjectId(verificationId)
        verification = await verificationsCol.find_one({"_id": verificationObjId})
        
        if not verification:
            raise HTTPException(status_code=404, detail="Verification record not found")
        
        # Get candidate details
        candidateId = verification.get("candidateId")
        candidate = await candidatesCol.find_one({"_id": ObjectId(candidateId)})
        
        if not candidate:
            raise HTTPException(status_code=404, detail="Candidate not found")
        
        # Determine resume source: uploaded file or database (local/S3)
        resumePath = None
        temp_file_path = None
        is_s3_url = False
        
        if resume:
            # Option 1: Resume file uploaded directly
            print(f"📄 Using uploaded resume file: {resume.filename}")
            ext = resume.filename.split(".")[-1].lower()
            if ext not in ["pdf", "docx"]:
                raise HTTPException(status_code=400, detail="Only PDF/DOCX files are supported")
            
            # Save temporarily
            import tempfile
            temp_file_path = f"/tmp/temp_resume_{candidateId}.{ext}"
            with open(temp_file_path, "wb") as f:
                f.write(await resume.read())
            resumePath = temp_file_path
            print(f"✅ Saved to temp: {temp_file_path}")
        else:
            # Option 2: Fetch from candidate.resumePath (local or S3)
            resumePath = candidate.get("resumePath")
            if not resumePath:
                raise HTTPException(status_code=400, detail="No resume provided and candidate has no resume in database. Please upload resume.")
            
            # Check if it's an S3 URL
            if resumePath.startswith("http://") or resumePath.startswith("https://") or resumePath.startswith("s3://"):
                is_s3_url = True
                print(f"📄 Resume is S3 URL: {resumePath}")
                
                # Download from S3 using boto3 (with credentials)
                try:
                    # Extract S3 key from URL - handle multiple formats
                    # Format 1: https://bucket.s3.region.amazonaws.com/key
                    # Format 2: https://s3.region.amazonaws.com/bucket/key
                    
                    if ".amazonaws.com/" in resumePath:
                        # Split by .amazonaws.com/ and get the part after it
                        parts = resumePath.split(".amazonaws.com/")
                        if len(parts) > 1:
                            s3_key = parts[1]
                        else:
                            raise Exception(f"Invalid S3 URL format: {resumePath}")
                    else:
                        raise Exception(f"Not a valid S3 URL: {resumePath}")
                    
                    print(f"🔍 Extracted S3 key: {s3_key}")
                    
                    ext = resumePath.split(".")[-1].lower()
                    if ext not in ["pdf", "docx"]:
                        ext = "pdf"  # default
                    
                    temp_file_path = f"/tmp/s3_resume_{candidateId}.{ext}"
                    
                    # Download from S3 using boto3
                    if s3_client:
                        print(f"📥 Downloading from S3: bucket={AWS_S3_BUCKET_NAME}, key={s3_key}")
                        s3_client.download_file(AWS_S3_BUCKET_NAME, s3_key, temp_file_path)
                        resumePath = temp_file_path
                        print(f"✅ Downloaded from S3 using boto3: {temp_file_path}")
                    else:
                        raise Exception("S3 client not initialized. Check AWS credentials in environment variables.")
                        
                except Exception as s3_error:
                    print(f"❌ S3 download error: {s3_error}")
                    print(f"❌ Resume URL: {resumePath}")
                    print(f"❌ Bucket: {AWS_S3_BUCKET_NAME}, Region: {AWS_REGION}")
                    raise HTTPException(status_code=400, detail=f"Failed to fetch resume from S3: {str(s3_error)}")
            else:
                # Local file path
                print(f"📄 Using local resume path: {resumePath}")
        
        candidateOrgId = str(candidate.get("organizationId"))
        
        # Role-based access control
        role = user.get("role")
        userEmail = user.get("email", "").lower().strip()
        userOrgId = str(user.get("organizationId"))
        accessible = [str(x) for x in user.get("accessibleOrganizations", [])]
        
        allowed = False
        
        if role in ["SUPER_ADMIN", "SUPER_SPOC"]:
            allowed = True
        elif role == "SPOC" and ("@bgv.local" in userEmail or "bgvapp.in" in userEmail):
            allowed = True
        elif role == "SUPER_ADMIN_HELPER":
            if candidateOrgId in accessible:
                allowed = True
        elif role in ["ORG_HR", "SPOC"]:
            if candidateOrgId == userOrgId:
                allowed = True
        elif role == "HELPER":
            if candidateOrgId == userOrgId and candidate.get("createdBy", "").lower().strip() == userEmail:
                allowed = True
        
        if not allowed:
            raise HTTPException(status_code=403, detail="You are not authorized to perform AI CV validation for this candidate")
        
        # Step 1: Extract CV text
        from utils.ai_utils import extract_text_from_pdf, extract_text_from_docx, validate_cv_authenticity
        
        ext = resumePath.split(".")[-1].lower()
        cv_text = ""
        
        if ext == "pdf":
            with open(resumePath, 'rb') as f:
                cv_text = extract_text_from_pdf(f)
        elif ext == "docx":
            cv_text = extract_text_from_docx(resumePath)
        else:
            raise HTTPException(status_code=400, detail=f"Unsupported resume format: {ext}")
        
        if not cv_text or len(cv_text.strip()) < 50:
            raise HTTPException(status_code=400, detail="Could not extract meaningful text from resume")
        
        # Step 2: Check if candidate has UAN (indicates formal employment)
        from apis import verify_pan_to_uan
        
        candidate_type = "UNKNOWN"
        uan_num = None
        has_uan_bool = False
        uan_verification_note = ""
        
        # Option 1: Manual override (no API call)
        if hasUan and hasUan.lower() in ["yes", "no"]:
            has_uan_bool = hasUan.lower() == "yes"
            if has_uan_bool:
                candidate_type = "EXPERIENCED_WITH_UAN"
                uan_verification_note = "✅ UAN status manually confirmed: YES. Candidate has formal employment."
                print(f"✅ Manual override: Candidate HAS UAN")
            else:
                candidate_type = "EXPERIENCED_NO_UAN"
                uan_verification_note = "⚠️ UAN status manually confirmed: NO. Candidate has no formal EPFO record."
                print(f"⚠️ Manual override: Candidate has NO UAN")
        
        # Option 2: Check UAN via API
        elif panNumber:
            print(f"🔍 Checking UAN for PAN: {panNumber}")
            
            try:
                uan_status, uan_result = await verify_pan_to_uan(panNumber)
                
                if uan_status == "COMPLETED":
                    uan_num = uan_result.get("uan_number") or uan_result.get("uan")
                    
                    if uan_num:
                        has_uan_bool = True
                        candidate_type = "EXPERIENCED_WITH_UAN"
                        uan_verification_note = f"✅ UAN verified via API: {uan_num}. Candidate has formal employment history registered with EPFO."
                        print(f"✅ UAN found: {uan_num} - Candidate has formal employment record")
                    else:
                        candidate_type = "EXPERIENCED_NO_UAN"
                        uan_verification_note = "⚠️ No UAN found via API. Candidate may be fresher, freelancer, or worked in unorganized sector."
                        print(f"⚠️ No UAN found - Candidate has no formal EPFO record")
                else:
                    print(f"⚠️ UAN check failed: {uan_result}")
                    candidate_type = "UNKNOWN"
                    uan_verification_note = "❌ UAN verification failed due to API error."
                    
            except Exception as uan_error:
                print(f"❌ UAN check error: {uan_error}")
                candidate_type = "UNKNOWN"
                uan_verification_note = "❌ UAN verification failed due to network error."
        
        # Option 3: No UAN check
        else:
            print(f"⚠️ No PAN or hasUan provided - skipping UAN verification")
            uan_verification_note = "⚠️ UAN verification skipped (no PAN or manual status provided)."
        
        # Determine candidate type from CV if still unknown
        if candidate_type == "UNKNOWN":
            if "experience" in cv_text.lower() or "worked" in cv_text.lower() or "company" in cv_text.lower():
                candidate_type = "EXPERIENCED_NO_UAN"
            else:
                candidate_type = "FRESHER"
            print(f"📋 Determined candidate type from CV: {candidate_type}")
        
        # Step 3: Perform AI authenticity validation
        print(f"🔍 Starting AI CV authenticity validation for verification {verificationId}")
        print(f"📊 Candidate Type: {candidate_type}")
        print(f"📊 Has UAN: {has_uan_bool}")
        
        # Pass UAN status to AI for credibility assessment
        validation_result = await validate_cv_authenticity(cv_text, has_uan_bool, candidate_type, uan_verification_note)
        
        if not validation_result:
            raise HTTPException(status_code=500, detail="AI validation failed to return results")
        
        # Find the ai_cv_validation check in the verification stages
        stages = verification.get("stages", {})
        updated = False
        
        for stage_name, checks in stages.items():
            for check in checks:
                if check.get("checkName") == "ai_cv_validation" or check.get("check") == "ai_cv_validation":
                    # Update the check with AI results but keep PENDING status
                    check.update({
                        "status": "PENDING",  # Keep PENDING for manual review
                        "aiAnalysisCompleted": True,  # Flag that AI analysis is done
                        "aiAnalysisAt": datetime.now(timezone.utc),
                        "aiAnalysisBy": user.get("email"),
                        "candidateType": candidate_type,
                        "uanNumber": uan_num,
                        "hasUan": has_uan_bool,
                        "uanVerificationNote": uan_verification_note,
                        "aiAnalysis": {
                            "authenticity_score": validation_result.get("authenticity_score", 0),
                            "candidate_profile": validation_result.get("candidate_profile", {}),
                            "positive_findings": validation_result.get("positive_findings", []),
                            "negative_findings": validation_result.get("negative_findings", []),
                            "education_analysis": validation_result.get("education_analysis", {}),
                            "employment_analysis": validation_result.get("employment_analysis", {}),
                            "timeline_analysis": validation_result.get("timeline_analysis", {}),
                            "red_flags": validation_result.get("red_flags", []),
                            "recommendation": validation_result.get("recommendation", "REVIEW_REQUIRED"),
                            "summary": validation_result.get("summary", ""),
                            "validation_id": str(uuid.uuid4()),
                            "timestamp": datetime.now(timezone.utc).isoformat(),
                            "method": "OpenAI-GPT4o-mini-Authenticity"
                        },
                        "remarks": f"AI authenticity check completed. Score: {validation_result.get('authenticity_score', 0)}/100. Type: {candidate_type}. Recommendation: {validation_result.get('recommendation', 'REVIEW_REQUIRED')}. Awaiting manual review."
                    })
                    updated = True
                    break
            if updated:
                break
        
        if not updated:
            raise HTTPException(status_code=400, detail="AI CV validation check not found in verification stages")
        
        # Save updated verification
        await verificationsCol.update_one(
            {"_id": verificationObjId},
            {"$set": {"stages": stages}}
        )
        
        # Log activity
        await logActivity(
            user,
            "AI CV Authenticity Check Completed",
            f"AI authenticity check completed for {candidate.get('firstName', '')} {candidate.get('lastName', '')} (Score: {validation_result.get('authenticity_score', 0)}/100, Type: {candidate_type}). Awaiting manual review.",
            "Success"
        )
        
        # Build response message
        response_message = "AI CV authenticity check completed successfully. Please review and submit."
        if not uan_num and candidate_type == "EXPERIENCED_NO_UAN":
            response_message += " Note: UAN could not be fetched (network issue or not available). Analysis based on CV content only."
        
        return JSONResponse(
            status_code=200,
            content=jsonable_encoder({
                "message": response_message,
                "verificationId": verificationId,
                "candidateName": f"{candidate.get('firstName', '')} {candidate.get('lastName', '')}".strip(),
                "candidateType": candidate_type,
                "uanNumber": uan_num,
                "hasUan": has_uan_bool,
                "uanVerificationNote": uan_verification_note,
                "analysis": {
                    "authenticity_score": validation_result.get("authenticity_score", 0),
                    "recommendation": validation_result.get("recommendation", "REVIEW_REQUIRED"),
                    "candidate_profile": validation_result.get("candidate_profile", {}),
                    "positive_findings": validation_result.get("positive_findings", []),
                    "negative_findings": validation_result.get("negative_findings", []),
                    "education_analysis": validation_result.get("education_analysis", {}),
                    "employment_analysis": validation_result.get("employment_analysis", {}),
                    "timeline_analysis": validation_result.get("timeline_analysis", {}),
                    "red_flags": validation_result.get("red_flags", []),
                    "summary": validation_result.get("summary", "")
                }
            })
        )
        
    except HTTPException:
        raise
    except Exception as e:
        import traceback
        error_details = traceback.format_exc()
        print(f"❌ AI CV Validation Error: {str(e)}")
        print(f"📋 Full traceback:\n{error_details}")
        
        await logActivity(
            user,
            "AI CV Validation Failed",
            f"Failed to complete AI CV validation: {str(e)}",
            "Error"
        )
        raise HTTPException(status_code=500, detail=f"AI CV validation failed: {str(e)}")
    finally:
        # Cleanup temporary file if it was created
        try:
            if 'temp_file_path' in locals() and temp_file_path:
                import os
                if os.path.exists(temp_file_path):
                    os.remove(temp_file_path)
                    print(f"🗑️ Cleaned up temporary file: {temp_file_path}")
        except Exception as cleanup_error:
            print(f"⚠️ Failed to cleanup temp file: {cleanup_error}")


@app.get("/secure/ai_cv_validation_results/{verificationId}")
async def get_ai_cv_validation_results(
    verificationId: str,
    user: dict = Depends(requireAuth)
):
    """
    Get AI CV authenticity validation results for a verification record
    """
    try:
        verificationObjId = ObjectId(verificationId)
        verification = await verificationsCol.find_one({"_id": verificationObjId})
        
        if not verification:
            raise HTTPException(status_code=404, detail="Verification record not found")
        
        # Get candidate details for access control
        candidateId = verification.get("candidateId")
        candidate = await candidatesCol.find_one({"_id": ObjectId(candidateId)})
        
        if not candidate:
            raise HTTPException(status_code=404, detail="Candidate not found")
        
        candidateOrgId = str(candidate.get("organizationId"))
        
        # Role-based access control
        role = user.get("role")
        userEmail = user.get("email", "").lower().strip()
        userOrgId = str(user.get("organizationId"))
        accessible = [str(x) for x in user.get("accessibleOrganizations", [])]
        
        allowed = False
        
        if role in ["SUPER_ADMIN", "SUPER_SPOC"]:
            allowed = True
        elif role == "SPOC" and ("@bgv.local" in userEmail or "bgvapp.in" in userEmail):
            allowed = True
        elif role == "SUPER_ADMIN_HELPER":
            if candidateOrgId in accessible:
                allowed = True
        elif role in ["ORG_HR", "SPOC"]:
            if candidateOrgId == userOrgId:
                allowed = True
        elif role == "HELPER":
            if candidateOrgId == userOrgId and candidate.get("createdBy", "").lower().strip() == userEmail:
                allowed = True
        
        if not allowed:
            raise HTTPException(status_code=403, detail="You are not authorized to view AI CV validation results for this candidate")
        
        # Find AI CV validation results
        stages = verification.get("stages", {})
        ai_results = None
        check_data = None
        
        for stage_name, checks in stages.items():
            for check in checks:
                if check.get("checkName") == "ai_cv_validation" or check.get("check") == "ai_cv_validation":
                    ai_results = check.get("aiAnalysis")
                    check_data = check
                    break
            if ai_results:
                break
        
        if not ai_results:
            raise HTTPException(status_code=404, detail="AI CV validation results not found. Please run the validation first.")
        
        return JSONResponse(
            status_code=200,
            content=jsonable_encoder({
                "verificationId": verificationId,
                "candidateName": f"{candidate.get('firstName', '')} {candidate.get('lastName', '')}".strip(),
                "candidateEmail": candidate.get("email", ""),
                "candidateType": check_data.get("candidateType", "UNKNOWN"),
                "uanNumber": check_data.get("uanNumber"),
                "employmentHistoryFetched": check_data.get("employmentHistoryFetched", False),
                "aiAnalysis": ai_results,
                "status": check_data.get("status", "PENDING"),
                "remarks": check_data.get("remarks", "")
            })
        )
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get AI CV validation results: {str(e)}")


@app.post("/secure/submit_ai_cv_validation")
async def submit_ai_cv_validation(
    verificationId: str = Form(...),
    final_status: str = Form(...),  # "COMPLETED" or "FAILED"
    staff_remarks: str = Form(""),
    user: dict = Depends(requireAuth)
):
    """
    Submit final decision for AI CV authenticity validation after reviewing AI analysis
    
    Parameters:
    - verificationId: The verification record ID
    - final_status: "COMPLETED" or "FAILED" 
    - staff_remarks: Additional remarks from staff review
    """
    
    if final_status not in ["COMPLETED", "FAILED"]:
        raise HTTPException(status_code=400, detail="final_status must be 'COMPLETED' or 'FAILED'")
    
    try:
        verificationObjId = ObjectId(verificationId)
        verification = await verificationsCol.find_one({"_id": verificationObjId})
        
        if not verification:
            raise HTTPException(status_code=404, detail="Verification record not found")
        
        # Get candidate details for access control
        candidateId = verification.get("candidateId")
        candidate = await candidatesCol.find_one({"_id": ObjectId(candidateId)})
        
        if not candidate:
            raise HTTPException(status_code=404, detail="Candidate not found")
        
        candidateOrgId = str(candidate.get("organizationId"))
        
        # Role-based access control (same as other endpoints)
        role = user.get("role")
        userEmail = user.get("email", "").lower().strip()
        userOrgId = str(user.get("organizationId"))
        accessible = [str(x) for x in user.get("accessibleOrganizations", [])]
        
        allowed = False
        
        if role in ["SUPER_ADMIN", "SUPER_SPOC"]:
            allowed = True
        elif role == "SPOC" and ("@bgv.local" in userEmail or "bgvapp.in" in userEmail):
            allowed = True
        elif role == "SUPER_ADMIN_HELPER":
            if candidateOrgId in accessible:
                allowed = True
        elif role in ["ORG_HR", "SPOC"]:
            if candidateOrgId == userOrgId:
                allowed = True
        elif role == "HELPER":
            if candidateOrgId == userOrgId and candidate.get("createdBy", "").lower().strip() == userEmail:
                allowed = True
        
        if not allowed:
            raise HTTPException(status_code=403, detail="You are not authorized to submit AI CV validation for this candidate")
        
        # Find and update the AI CV validation check
        stages = verification.get("stages", {})
        updated = False
        
        for stage_name, checks in stages.items():
            for check in checks:
                if check.get("checkName") == "ai_cv_validation" or check.get("check") == "ai_cv_validation":
                    # Verify AI analysis was completed
                    if not check.get("aiAnalysisCompleted"):
                        raise HTTPException(status_code=400, detail="AI analysis must be completed before submission")
                    
                    # Update with final status and staff decision
                    ai_score = check.get("aiAnalysis", {}).get("authenticity_score", 0)
                    ai_recommendation = check.get("aiAnalysis", {}).get("recommendation", "REVIEW_REQUIRED")
                    candidate_type = check.get("candidateType", "UNKNOWN")
                    
                    final_remarks = f"AI Authenticity Score: {ai_score}/100, Type: {candidate_type}, AI Recommendation: {ai_recommendation}"
                    if staff_remarks:
                        final_remarks += f". Staff Review: {staff_remarks}"
                    
                    check.update({
                        "status": final_status,
                        "submittedAt": datetime.now(timezone.utc),
                        "updatedBy": user.get("email"),
                        "staffRemarks": staff_remarks,
                        "finalDecision": final_status,
                        "remarks": final_remarks
                    })
                    updated = True
                    break
            if updated:
                break
        
        if not updated:
            raise HTTPException(status_code=400, detail="AI CV validation check not found or not ready for submission")
        
        # Save updated verification
        await verificationsCol.update_one(
            {"_id": verificationObjId},
            {"$set": {"stages": stages}}
        )
        
        # ✅ CHECK IF STAGE IS COMPLETE AND UPDATE OVERALL STATUS
        verification = await verificationsCol.find_one({"_id": verificationObjId})
        current_stage = verification.get("currentStage")
        stage_checks = verification.get("stages", {}).get(current_stage, [])
        
        # Check if all checks in current stage are COMPLETED
        all_completed = all(
            check.get("status") == "COMPLETED" 
            for check in stage_checks
        )
        
        if all_completed:
            # Determine next stage or mark as complete
            if current_stage == "primary":
                next_stage = "secondary"
            elif current_stage == "secondary":
                next_stage = "final"
            elif current_stage == "final":
                # All stages complete - mark verification as COMPLETED
                await verificationsCol.update_one(
                    {"_id": verificationObjId},
                    {"$set": {
                        "overallStatus": "COMPLETED",
                        "completedAt": datetime.now(timezone.utc).isoformat()
                    }}
                )
                
                # Update candidate status
                await candidatesCol.update_one(
                    {"_id": ObjectId(candidateId)},
                    {"$set": {"status": "VERIFIED"}}
                )
                next_stage = None
            else:
                next_stage = None
            
            # Move to next stage if applicable
            if next_stage and next_stage in verification.get("stages", {}):
                await verificationsCol.update_one(
                    {"_id": verificationObjId},
                    {"$set": {"currentStage": next_stage}}
                )
        
        # Log activity
        await logActivity(
            user,
            f"AI CV Authenticity Validation {final_status}",
            f"Staff submitted AI CV authenticity validation as {final_status} for candidate {candidate.get('firstName', '')} {candidate.get('lastName', '')}",
            "Success"
        )
        
        return JSONResponse(
            status_code=200,
            content=jsonable_encoder({
                "message": f"AI CV authenticity validation submitted as {final_status} successfully",
                "verificationId": verificationId,
                "candidateName": f"{candidate.get('firstName', '')} {candidate.get('lastName', '')}".strip(),
                "finalStatus": final_status,
                "staffRemarks": staff_remarks
            })
        )
        
    except HTTPException:
        raise
    except Exception as e:
        await logActivity(
            user,
            "AI CV Validation Submission Failed",
            f"Failed to submit AI CV validation: {str(e)}",
            "Error"
        )
        raise HTTPException(status_code=500, detail=f"Failed to submit AI CV validation: {str(e)}")


# ------------------------------------------------
# 📌 INVOICE GENERATION - SIMPLE VERSION
# ------------------------------------------------

@app.post("/secure/generate_invoice")
async def generate_invoice(
    verificationId: str = Form(...),
    user: dict = Depends(requireAuth)
):
    """
    Generate invoice for completed checks
    Fetches prices from organization's pricing configuration
    """
    
    try:
        # Get verification
        verification = await verificationsCol.find_one({"_id": ObjectId(verificationId)})
        if not verification:
            raise HTTPException(status_code=404, detail="Verification not found")
        
        # Get organization with pricing
        organizationId = verification.get("organizationId")
        organizationsCol = db["organizations"]
        organization = await organizationsCol.find_one({"_id": ObjectId(organizationId)})
        
        if not organization:
            raise HTTPException(status_code=404, detail="Organization not found")
        
        # Get candidate
        candidateId = verification.get("candidateId")
        candidate = await candidatesCol.find_one({"_id": ObjectId(candidateId)})
        
        # Role-based access control
        role = user.get("role")
        userEmail = user.get("email", "").lower().strip()
        userOrgId = str(user.get("organizationId"))
        accessible = [str(x) for x in user.get("accessibleOrganizations", [])]
        
        allowed = False
        
        # 1. SUPER_ADMIN or SUPER_SPOC - can access all organizations
        if role in ["SUPER_ADMIN", "SUPER_SPOC"]:
            allowed = True
        
        # 2. SPOC from main BGV org - can access all organizations
        elif role == "SPOC" and ("@bgv.local" in userEmail or "bgvapp.in" in userEmail):
            allowed = True
        
        # 3. SUPER_ADMIN_HELPER - can access accessible organizations only
        elif role == "SUPER_ADMIN_HELPER":
            if str(organizationId) in accessible:
                allowed = True
        
        # 4. ORG_HR or ORG_SPOC - can access their own organization only
        elif role in ["ORG_HR", "SPOC"]:
            if str(organizationId) == userOrgId:
                allowed = True
        
        # 5. HELPER - can access candidates they created or verifications they initiated
        elif role == "HELPER":
            # Check if helper belongs to the same organization
            if str(organizationId) == userOrgId:
                # Check if helper created the candidate
                candidate_created_by = candidate.get("createdBy", "").lower().strip() if candidate else ""
                # Check if helper initiated the verification
                verification_initiated_by = verification.get("initiatedBy", "").lower().strip()
                
                if candidate_created_by == userEmail or verification_initiated_by == userEmail:
                    allowed = True
        
        if not allowed:
            raise HTTPException(
                status_code=403, 
                detail="You are not authorized to generate invoice for this verification"
            )
        
        # Get pricing from org services array
        services = organization.get("services", [])
        if not services:
            raise HTTPException(status_code=400, detail="Organization services/pricing not configured")
        
        # Build pricing map from services array
        pricing_map = {}
        for service in services:
            service_name = service.get("serviceName")
            service_price = service.get("price")
            if service_name and service_price:
                pricing_map[service_name] = float(service_price)
        
        # Collect completed checks and calculate total
        invoice_items = []
        total_amount = 0.0
        missing_prices = []
        
        stages = verification.get("stages", {})
        for stage_name, checks in stages.items():
            for check in checks:
                # Try both 'check' and 'checkName' fields
                check_name = check.get("check") or check.get("checkName")
                check_status = check.get("status")
                
                if not check_name:
                    continue  # Skip if no check name found
                
                # Only bill COMPLETED checks
                if check_status == "COMPLETED":
                    # Get price from pricing map
                    price = pricing_map.get(check_name)
                    
                    if price is None:
                        missing_prices.append(check_name)
                        continue  # Skip checks without configured price
                    
                    invoice_items.append({
                        "checkName": check_name,
                        "stage": stage_name,
                        "price": price,
                        "completedAt": check.get("submittedAt")
                    })
                    
                    total_amount += price
        
        # Warn if some checks don't have prices
        if missing_prices:
            print(f"⚠️ Warning: Prices not configured for checks: {missing_prices}")
        
        # Calculate tax (18% GST)
        tax = total_amount * 0.18
        grand_total = total_amount + tax
        
        # Build invoice
        invoice = {
            "invoiceNumber": f"INV-{datetime.now().strftime('%Y%m%d')}-{str(ObjectId(verificationId))[-6:]}",
            "invoiceDate": datetime.now(timezone.utc).isoformat(),
            "verificationId": verificationId,
            
            # Organization details
            "organization": {
                "organizationId": str(organizationId),
                "organizationName": organization.get("organizationName", "N/A"),
                "email": organization.get("email", "N/A"),
                "phone": organization.get("phone", "N/A"),
                "gstNumber": organization.get("gstNumber", "N/A")
            },
            
            # Candidate details
            "candidate": {
                "candidateId": str(candidateId),
                "candidateName": f"{candidate.get('firstName', '')} {candidate.get('lastName', '')}".strip() if candidate else "N/A",
                "email": candidate.get("email", "N/A") if candidate else "N/A",
                "phone": candidate.get("phone", "N/A") if candidate else "N/A"
            },
            
            # Invoice items (completed checks)
            "items": invoice_items,
            "totalItems": len(invoice_items),
            
            # Pricing
            "subtotal": round(total_amount, 2),
            "taxRate": 0.18,
            "tax": round(tax, 2),
            "grandTotal": round(grand_total, 2),
            "currency": "INR",
            
            # Warnings
            "warnings": missing_prices if missing_prices else None
        }
        
        # Save to database
        invoicesCol = db["invoices"]
        result = await invoicesCol.insert_one({
            **invoice,
            "createdAt": datetime.now(timezone.utc),
            "createdBy": user.get("email")
        })
        
        invoice["invoiceId"] = str(result.inserted_id)
        
        await logActivity(
            user,
            "Invoice Generated",
            f"Generated invoice for verification {verificationId} - Total: ₹{grand_total:.2f}",
            "Success"
        )
        
        return JSONResponse(status_code=200, content=jsonable_encoder(invoice))
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to generate invoice: {str(e)}")


# ------------------------------------------------
# 📌 FORGOT PASSWORD SYSTEM
# ------------------------------------------------

@app.post("/public/forgot-password")
async def forgot_password(
    email: str = Form(...)
):
    """
    Request password reset link
    Sends email with reset token
    """
    try:
        # Find user by email
        usersCol = db["users"]
        user = await usersCol.find_one({"email": email.lower().strip()})
        
        if not user:
            # Don't reveal if email exists or not (security)
            return JSONResponse(
                status_code=200,
                content={"message": "If the email exists, a password reset link has been sent"}
            )
        
        # Generate reset token (valid for 1 hour)
        reset_token = str(uuid.uuid4())
        reset_expiry = datetime.now(timezone.utc) + timedelta(hours=1)
        
        # Save reset token to user
        await usersCol.update_one(
            {"_id": user["_id"]},
            {
                "$set": {
                    "resetToken": reset_token,
                    "resetTokenExpiry": reset_expiry
                }
            }
        )
        
        # Build reset link
        reset_link = f"https://bgv-ey1e.onrender.com/reset-password?token={reset_token}"
        
        # Send email with reset link using Gmail API
        try:
            from utils.email_utils import _load_gmail_service
            from email.mime.text import MIMEText
            import base64
            
            email_body = f"""
Hi {user.get('userName', 'User')},

You requested to reset your password. Click the link below to reset:

{reset_link}

This link will expire in 1 hour.

If you didn't request this, please ignore this email.

Best regards,
BGV Team
"""
            
            # Create email MIME object
            message = MIMEText(email_body)
            message["to"] = email
            message["from"] = "me"
            message["subject"] = "Password Reset Request"
            
            # Gmail API requires base64url encoding
            raw = base64.urlsafe_b64encode(message.as_bytes()).decode()
            
            # Send via Gmail API
            service = _load_gmail_service()
            service.users().messages().send(userId="me", body={"raw": raw}).execute()
            
            print(f"✅ Password reset email sent to {email}")
            
        except Exception as e:
            print(f"❌ Failed to send reset email: {e}")
            # Continue anyway - don't reveal email sending failure
        
        return JSONResponse(
            status_code=200,
            content={"message": "If the email exists, a password reset link has been sent"}
        )
        
    except Exception as e:
        print(f"❌ Forgot password error: {e}")
        return JSONResponse(
            status_code=200,
            content={"message": "If the email exists, a password reset link has been sent"}
        )


@app.post("/public/reset-password")
async def reset_password(
    token: str = Form(...),
    email: str = Form(...),
    organizationId: str = Form(...),
    new_password: str = Form(...),
    confirm_password: str = Form(...)
):
    """
    Reset password with token validation
    Requires: token, email, organizationId, new password, confirm password
    """
    try:
        # Validate passwords match
        if new_password != confirm_password:
            raise HTTPException(status_code=400, detail="Passwords do not match")
        
        # Validate password strength (minimum 6 characters)
        if len(new_password) < 6:
            raise HTTPException(status_code=400, detail="Password must be at least 6 characters")
        
        # Find user by reset token
        usersCol = db["users"]
        user = await usersCol.find_one({
            "resetToken": token,
            "resetTokenExpiry": {"$gt": datetime.now(timezone.utc)}
        })
        
        if not user:
            raise HTTPException(status_code=400, detail="Invalid or expired reset token")
        
        # Verify email matches
        user_email = user.get("email", "") or ""
        if user_email.lower().strip() != email.lower().strip():
            raise HTTPException(status_code=400, detail="Email does not match")
        
        # Verify organizationId matches
        user_org_id = str(user.get("organizationId", ""))
        provided_org_id = organizationId.strip()
        
        if user_org_id != provided_org_id:
            raise HTTPException(status_code=400, detail="Organization ID does not match")
        
        # Update password and clear reset token
        await usersCol.update_one(
            {"_id": user["_id"]},
            {
                "$set": {
                    "password": new_password,  # In production, hash this password!
                    "updatedAt": datetime.now(timezone.utc)
                },
                "$unset": {
                    "resetToken": "",
                    "resetTokenExpiry": ""
                }
            }
        )
        
        # Log activity
        await logActivity(
            {"email": email, "role": user.get("role")},
            "Password Reset",
            f"Password reset successful for {email}",
            "Success"
        )
        
        return JSONResponse(
            status_code=200,
            content={
                "message": "Password reset successful. You can now login with your new password.",
                "email": email
            }
        )
        
    except HTTPException:
        raise
    except Exception as e:
        print(f"❌ Reset password error: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to reset password: {str(e)}")


# ------------------------------------------------
# 📌 AI EDUCATION VALIDATION ENDPOINT
# ------------------------------------------------

@app.post("/secure/ai_education_validation")
async def ai_education_validation(
    verificationId: str = Form(...),
    educationDocument: UploadFile = File(...),  # Required - education certificate/marksheet
    user: dict = Depends(requireAuth)
):
    """
    AI Education Document Validation - Extract and validate education information using OCR + AI
    
    Parameters:
    - verificationId: The verification record ID
    - educationDocument: Education certificate/marksheet (PDF/JPG/PNG)
    """
    
    temp_file_path = None
    
    try:
        # Verify verification record exists and user has access
        verificationObjId = ObjectId(verificationId)
        verification = await verificationsCol.find_one({"_id": verificationObjId})
        
        if not verification:
            raise HTTPException(status_code=404, detail="Verification record not found")
        
        # Get candidate details
        candidateId = verification.get("candidateId")
        candidate = await candidatesCol.find_one({"_id": ObjectId(candidateId)})
        
        if not candidate:
            raise HTTPException(status_code=404, detail="Candidate not found")
        
        candidateOrgId = str(candidate.get("organizationId"))
        
        # Role-based access control (same as CV validation)
        role = user.get("role")
        userEmail = user.get("email", "").lower().strip()
        userOrgId = str(user.get("organizationId"))
        accessible = [str(x) for x in user.get("accessibleOrganizations", [])]
        
        allowed = False
        
        if role in ["SUPER_ADMIN", "SUPER_SPOC"]:
            allowed = True
        elif role == "SPOC" and ("@bgv.local" in userEmail or "bgvapp.in" in userEmail):
            allowed = True
        elif role == "SUPER_ADMIN_HELPER":
            if candidateOrgId in accessible:
                allowed = True
        elif role in ["ORG_HR", "SPOC"]:
            if candidateOrgId == userOrgId:
                allowed = True
        elif role == "HELPER":
            if candidateOrgId == userOrgId and candidate.get("createdBy", "").lower().strip() == userEmail:
                allowed = True
        
        if not allowed:
            raise HTTPException(status_code=403, detail="You are not authorized to perform AI education validation for this candidate")
        
        # Validate file type
        ext = educationDocument.filename.split(".")[-1].lower()
        if ext not in ["pdf", "jpg", "jpeg", "png"]:
            raise HTTPException(status_code=400, detail="Only PDF, JPG, PNG files are supported for education documents")
        
        # Save file temporarily
        print(f"📄 Education document received: {educationDocument.filename}")
        temp_file_path = f"/tmp/education_doc_{candidateId}.{ext}"
        with open(temp_file_path, "wb") as f:
            f.write(await educationDocument.read())
        print(f"✅ Saved to temp: {temp_file_path}")
        
        # Extract text using OCR
        from utils.ai_utils import extract_text_with_ocr, validate_education_document
        
        print(f"🔍 Extracting text from education document using OCR...")
        document_text = extract_text_with_ocr(temp_file_path)
        
        if not document_text or len(document_text.strip()) < 20:
            raise HTTPException(status_code=400, detail="Could not extract meaningful text from document. Please ensure document is clear and readable.")
        
        print(f"✅ Extracted {len(document_text)} characters from document")
        
        # Validate using AI
        print(f"🎓 Starting AI education validation for verification {verificationId}")
        validation_result = await validate_education_document(document_text)
        
        if not validation_result:
            raise HTTPException(status_code=500, detail="AI validation failed to return results")
        
        # Find the ai_education_validation check in verification stages
        stages = verification.get("stages", {})
        updated = False
        
        for stage_name, checks in stages.items():
            for check in checks:
                if check.get("checkName") == "ai_education_validation" or check.get("check") == "ai_education_validation":
                    # Update the check with AI results but keep PENDING status
                    check.update({
                        "status": "PENDING",  # Keep PENDING for manual review
                        "aiAnalysisCompleted": True,
                        "aiAnalysisAt": datetime.now(timezone.utc),
                        "aiAnalysisBy": user.get("email"),
                        "aiAnalysis": {
                            "degree_type": validation_result.get("degree_type", ""),
                            "field_of_study": validation_result.get("field_of_study", ""),
                            "institution_name": validation_result.get("institution_name", ""),
                            "start_date": validation_result.get("start_date", ""),
                            "end_date": validation_result.get("end_date", ""),
                            "duration_years": validation_result.get("duration_years", 0),
                            "grade": validation_result.get("grade", ""),
                            "board_university": validation_result.get("board_university", ""),
                            "document_type": validation_result.get("document_type", ""),
                            "authenticity_score": validation_result.get("authenticity_score", 0),
                            "verification_status": validation_result.get("verification_status", ""),
                            "positive_findings": validation_result.get("positive_findings", []),
                            "red_flags": validation_result.get("red_flags", []),
                            "extracted_text_quality": validation_result.get("extracted_text_quality", ""),
                            "recommendation": validation_result.get("recommendation", "REVIEW_REQUIRED"),
                            "summary": validation_result.get("summary", ""),
                            "validation_id": str(uuid.uuid4()),
                            "timestamp": datetime.now(timezone.utc).isoformat(),
                            "method": "OpenAI-GPT4o-mini-OCR"
                        },
                        "remarks": f"AI education validation completed. Score: {validation_result.get('authenticity_score', 0)}/100. Recommendation: {validation_result.get('recommendation', 'REVIEW_REQUIRED')}. Awaiting manual review."
                    })
                    updated = True
                    break
            if updated:
                break
        
        if not updated:
            raise HTTPException(status_code=400, detail="AI education validation check not found in verification stages")
        
        # Save updated verification
        await verificationsCol.update_one(
            {"_id": verificationObjId},
            {"$set": {"stages": stages}}
        )
        
        # Log activity
        await logActivity(
            user,
            "AI Education Validation Completed",
            f"AI education validation completed for {candidate.get('firstName', '')} {candidate.get('lastName', '')} (Score: {validation_result.get('authenticity_score', 0)}/100). Awaiting manual review.",
            "Success"
        )
        
        return JSONResponse(
            status_code=200,
            content=jsonable_encoder({
                "message": "AI education validation completed successfully. Please review and submit.",
                "verificationId": verificationId,
                "candidateName": f"{candidate.get('firstName', '')} {candidate.get('lastName', '')}".strip(),
                "analysis": validation_result
            })
        )
        
    except HTTPException:
        raise
    except Exception as e:
        import traceback
        error_details = traceback.format_exc()
        print(f"❌ AI Education Validation Error: {str(e)}")
        print(f"📋 Full traceback:\n{error_details}")
        
        await logActivity(
            user,
            "AI Education Validation Failed",
            f"Failed to complete AI education validation: {str(e)}",
            "Error"
        )
        raise HTTPException(status_code=500, detail=f"AI education validation failed: {str(e)}")
    finally:
        # Cleanup temporary file
        try:
            if 'temp_file_path' in locals() and temp_file_path:
                import os
                if os.path.exists(temp_file_path):
                    os.remove(temp_file_path)
                    print(f"🗑️ Cleaned up temporary file: {temp_file_path}")
        except Exception as cleanup_error:
            print(f"⚠️ Failed to cleanup temp file: {cleanup_error}")


@app.get("/secure/ai_education_validation_results/{verificationId}")
async def get_ai_education_validation_results(
    verificationId: str,
    user: dict = Depends(requireAuth)
):
    """
    Get AI education validation results for a verification record
    """
    try:
        verificationObjId = ObjectId(verificationId)
        verification = await verificationsCol.find_one({"_id": verificationObjId})
        
        if not verification:
            raise HTTPException(status_code=404, detail="Verification record not found")
        
        # Get candidate details for access control
        candidateId = verification.get("candidateId")
        candidate = await candidatesCol.find_one({"_id": ObjectId(candidateId)})
        
        if not candidate:
            raise HTTPException(status_code=404, detail="Candidate not found")
        
        candidateOrgId = str(candidate.get("organizationId"))
        
        # Role-based access control
        role = user.get("role")
        userEmail = user.get("email", "").lower().strip()
        userOrgId = str(user.get("organizationId"))
        accessible = [str(x) for x in user.get("accessibleOrganizations", [])]
        
        allowed = False
        
        if role in ["SUPER_ADMIN", "SUPER_SPOC"]:
            allowed = True
        elif role == "SPOC" and ("@bgv.local" in userEmail or "bgvapp.in" in userEmail):
            allowed = True
        elif role == "SUPER_ADMIN_HELPER":
            if candidateOrgId in accessible:
                allowed = True
        elif role in ["ORG_HR", "SPOC"]:
            if candidateOrgId == userOrgId:
                allowed = True
        elif role == "HELPER":
            if candidateOrgId == userOrgId and candidate.get("createdBy", "").lower().strip() == userEmail:
                allowed = True
        
        if not allowed:
            raise HTTPException(status_code=403, detail="You are not authorized to view this verification")
        
        # Find ai_education_validation check
        stages = verification.get("stages", {})
        education_check = None
        
        for stage_name, checks in stages.items():
            for check in checks:
                if check.get("checkName") == "ai_education_validation" or check.get("check") == "ai_education_validation":
                    education_check = check
                    break
            if education_check:
                break
        
        if not education_check:
            raise HTTPException(status_code=404, detail="AI education validation check not found in verification")
        
        if not education_check.get("aiAnalysisCompleted"):
            raise HTTPException(status_code=400, detail="AI education validation has not been completed yet")
        
        return JSONResponse(
            status_code=200,
            content=jsonable_encoder({
                "verificationId": verificationId,
                "candidateName": f"{candidate.get('firstName', '')} {candidate.get('lastName', '')}".strip(),
                "candidateEmail": candidate.get("email", ""),
                "aiAnalysis": education_check.get("aiAnalysis", {}),
                "status": education_check.get("status", "PENDING"),
                "remarks": education_check.get("remarks", "")
            })
        )
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to retrieve education validation results: {str(e)}")


@app.post("/secure/submit_ai_education_validation")
async def submit_ai_education_validation(
    verificationId: str = Form(...),
    final_status: str = Form(...),  # "COMPLETED" or "FAILED"
    staff_remarks: str = Form(""),
    user: dict = Depends(requireAuth)
):
    """
    Submit final decision for AI education validation after reviewing AI analysis
    
    Parameters:
    - verificationId: The verification record ID
    - final_status: "COMPLETED" or "FAILED" 
    - staff_remarks: Additional remarks from staff review
    """
    
    if final_status not in ["COMPLETED", "FAILED"]:
        raise HTTPException(status_code=400, detail="final_status must be 'COMPLETED' or 'FAILED'")
    
    try:
        verificationObjId = ObjectId(verificationId)
        verification = await verificationsCol.find_one({"_id": verificationObjId})
        
        if not verification:
            raise HTTPException(status_code=404, detail="Verification record not found")
        
        # Get candidate details
        candidateId = verification.get("candidateId")
        candidate = await candidatesCol.find_one({"_id": ObjectId(candidateId)})
        
        if not candidate:
            raise HTTPException(status_code=404, detail="Candidate not found")
        
        candidateOrgId = str(candidate.get("organizationId"))
        
        # Role-based access control
        role = user.get("role")
        userEmail = user.get("email", "").lower().strip()
        userOrgId = str(user.get("organizationId"))
        accessible = [str(x) for x in user.get("accessibleOrganizations", [])]
        
        allowed = False
        
        if role in ["SUPER_ADMIN", "SUPER_SPOC"]:
            allowed = True
        elif role == "SPOC" and ("@bgv.local" in userEmail or "bgvapp.in" in userEmail):
            allowed = True
        elif role == "SUPER_ADMIN_HELPER":
            if candidateOrgId in accessible:
                allowed = True
        elif role in ["ORG_HR", "SPOC"]:
            if candidateOrgId == userOrgId:
                allowed = True
        elif role == "HELPER":
            if candidateOrgId == userOrgId and candidate.get("createdBy", "").lower().strip() == userEmail:
                allowed = True
        
        if not allowed:
            raise HTTPException(status_code=403, detail="You are not authorized to submit this validation")
        
        # Find ai_education_validation check
        stages = verification.get("stages", {})
        updated = False
        
        for stage_name, checks in stages.items():
            for check in checks:
                if check.get("checkName") == "ai_education_validation" or check.get("check") == "ai_education_validation":
                    # Check if AI analysis was completed
                    if not check.get("aiAnalysisCompleted"):
                        raise HTTPException(status_code=400, detail="AI analysis must be completed before submission")
                    
                    # Update status
                    check["status"] = final_status
                    check["submittedAt"] = datetime.now(timezone.utc)
                    check["submittedBy"] = user.get("email")
                    
                    # Append staff remarks to existing remarks
                    if staff_remarks:
                        existing_remarks = check.get("remarks", "")
                        check["remarks"] = f"{existing_remarks}\n\nStaff Review: {staff_remarks}"
                    
                    updated = True
                    break
            if updated:
                break
        
        if not updated:
            raise HTTPException(status_code=404, detail="AI education validation check not found")
        
        # Save updated verification
        await verificationsCol.update_one(
            {"_id": verificationObjId},
            {"$set": {"stages": stages}}
        )
        
        # ✅ CHECK IF STAGE IS COMPLETE AND UPDATE OVERALL STATUS
        verification = await verificationsCol.find_one({"_id": verificationObjId})
        current_stage = verification.get("currentStage")
        stage_checks = verification.get("stages", {}).get(current_stage, [])
        
        # Check if all checks in current stage are COMPLETED
        all_completed = all(
            check.get("status") == "COMPLETED" 
            for check in stage_checks
        )
        
        if all_completed:
            # Determine next stage or mark as complete
            if current_stage == "primary":
                next_stage = "secondary"
            elif current_stage == "secondary":
                next_stage = "final"
            elif current_stage == "final":
                # All stages complete - mark verification as COMPLETED
                await verificationsCol.update_one(
                    {"_id": verificationObjId},
                    {"$set": {
                        "overallStatus": "COMPLETED",
                        "completedAt": datetime.now(timezone.utc).isoformat()
                    }}
                )
                
                # Update candidate status
                await candidatesCol.update_one(
                    {"_id": ObjectId(candidateId)},
                    {"$set": {"status": "VERIFIED"}}
                )
                next_stage = None
            else:
                next_stage = None
            
            # Move to next stage if applicable
            if next_stage and next_stage in verification.get("stages", {}):
                await verificationsCol.update_one(
                    {"_id": verificationObjId},
                    {"$set": {"currentStage": next_stage}}
                )
        
        # Log activity
        await logActivity(
            user,
            "AI Education Validation Submitted",
            f"AI education validation submitted as {final_status} for {candidate.get('firstName', '')} {candidate.get('lastName', '')}",
            "Success"
        )
        
        return JSONResponse(
            status_code=200,
            content=jsonable_encoder({
                "message": f"AI education validation submitted as {final_status} successfully",
                "verificationId": verificationId,
                "candidateName": f"{candidate.get('firstName', '')} {candidate.get('lastName', '')}".strip(),
                "finalStatus": final_status,
                "staffRemarks": staff_remarks
            })
        )
        
    except HTTPException:
        raise
    except Exception as e:
        await logActivity(
            user,
            "AI Education Validation Submission Failed",
            f"Failed to submit AI education validation: {str(e)}",
            "Error"
        )
        raise HTTPException(status_code=500, detail=f"Failed to submit AI education validation: {str(e)}")


# ================================================
# 📌 AI RESUME SCREENING ENDPOINT
# ================================================

@app.post("/secure/ai_resume_screening")
async def ai_resume_screening(
    jd_file: UploadFile = File(...),
    resume_files: List[UploadFile] = File(...),
    top_n: int = Form(5),
    user: dict = Depends(requireAuth)
):
    """
    AI-powered resume screening using OpenAI embeddings
    
    Parameters:
    - jd_file: Job description file (PDF/DOCX/TXT)
    - resume_files: List of resume files (up to 100, PDF/DOCX/TXT)
    - top_n: Number of best resumes to return (default: 5, max: 20)
    
    Returns:
    - Top N resumes ranked by match score
    - Detailed analysis for each: strengths, weaknesses, skills match, recommendation
    """
    
    # Import resume screening utilities
    from utils.resume_screening import screen_resumes
    
    # Validate inputs
    if not resume_files or len(resume_files) == 0:
        raise HTTPException(status_code=400, detail="No resume files uploaded")
    
    if len(resume_files) > 100:
        raise HTTPException(status_code=400, detail="Maximum 100 resumes allowed")
    
    if top_n < 1:
        raise HTTPException(status_code=400, detail="top_n must be at least 1")
    
    if top_n > 20:
        raise HTTPException(status_code=400, detail="top_n cannot exceed 20")
    
    # Validate JD file
    jd_filename = jd_file.filename.lower()
    if not (jd_filename.endswith('.pdf') or jd_filename.endswith('.docx') or 
            jd_filename.endswith('.doc') or jd_filename.endswith('.txt')):
        raise HTTPException(status_code=400, detail="JD file must be PDF, DOCX, or TXT")
    
    # Validate resume files
    for resume in resume_files:
        filename = resume.filename.lower()
        if not (filename.endswith('.pdf') or filename.endswith('.docx') or 
                filename.endswith('.doc') or filename.endswith('.txt')):
            raise HTTPException(
                status_code=400, 
                detail=f"Invalid file format: {resume.filename}. Only PDF, DOCX, and TXT allowed"
            )
    
    try:
        # Log activity
        await logActivity(
            user,
            "AI Resume Screening Started",
            f"Processing {len(resume_files)} resumes against JD: {jd_file.filename}",
            "Started"
        )
        
        # Read JD file
        jd_content = await jd_file.read()
        jd_tuple = (jd_content, jd_file.filename)
        
        # Read all resume files
        resume_tuples = []
        for resume in resume_files:
            content = await resume.read()
            resume_tuples.append((content, resume.filename))
        
        # Process resumes
        print(f"\n🚀 Starting resume screening: {len(resume_files)} resumes, top {top_n}")
        results = await screen_resumes(resume_tuples, jd_tuple, top_n)
        
        # Log success
        await logActivity(
            user,
            "AI Resume Screening Completed",
            f"Successfully screened {results['total_resumes_processed']} resumes. Top {len(results['top_resumes'])} returned.",
            "Success"
        )
        
        return JSONResponse(
            status_code=200,
            content={
                "message": "Resume screening completed successfully",
                "results": results,
                "user": user.get("email")
            }
        )
        
    except ValueError as e:
        await logActivity(
            user,
            "AI Resume Screening Failed",
            f"Validation error: {str(e)}",
            "Error"
        )
        raise HTTPException(status_code=400, detail=str(e))
    
    except Exception as e:
        await logActivity(
            user,
            "AI Resume Screening Failed",
            f"Error: {str(e)}",
            "Error"
        )
        raise HTTPException(status_code=500, detail=f"Resume screening failed: {str(e)}")


# ================================================
# 📌 ENHANCED AI RESUME SCREENING ENDPOINT
# ================================================

@app.post("/secure/ai_resume_screening_enhanced")
async def ai_resume_screening_enhanced(
    jd_file: UploadFile = File(...),
    resume_files: List[UploadFile] = File(...),
    top_n: int = Form(5),
    must_have_requirements: str = Form(""),  # Comma-separated list
    nice_to_have: str = Form(""),  # Comma-separated list
    min_embedding_score: float = Form(0.5),
    embedding_weight: float = Form(0.3),
    llm_weight: float = Form(0.7),
    user: dict = Depends(requireAuth)
):
    """
    Enhanced AI-powered resume screening with requirement checking and weighted scoring
    
    Parameters:
    - jd_file: Job description file (PDF/DOCX/TXT)
    - resume_files: List of resume files (up to 100, PDF/DOCX/TXT)
    - top_n: Number of best resumes to return (default: 5, max: 20)
    - must_have_requirements: Comma-separated critical requirements (e.g., "5+ years Python,AWS certification")
    - nice_to_have: Comma-separated preferred requirements (e.g., "Docker,Kubernetes")
    - min_embedding_score: Minimum similarity threshold (default: 0.5, range: 0-1)
    - embedding_weight: Weight for embedding score (default: 0.3, range: 0-1)
    - llm_weight: Weight for LLM score (default: 0.7, range: 0-1)
    
    Returns:
    - Top N resumes with enhanced analysis including requirement compliance
    """
    
    # Import enhanced screening utilities
    from utils.resume_screening_enhanced import screen_resumes_enhanced
    
    # Validate inputs
    if not resume_files or len(resume_files) == 0:
        raise HTTPException(status_code=400, detail="No resume files uploaded")
    
    if len(resume_files) > 100:
        raise HTTPException(status_code=400, detail="Maximum 100 resumes allowed")
    
    if top_n < 1:
        raise HTTPException(status_code=400, detail="top_n must be at least 1")
    
    if top_n > 20:
        raise HTTPException(status_code=400, detail="top_n cannot exceed 20")
    
    if min_embedding_score < 0 or min_embedding_score > 1:
        raise HTTPException(status_code=400, detail="min_embedding_score must be between 0 and 1")
    
    if embedding_weight < 0 or embedding_weight > 1:
        raise HTTPException(status_code=400, detail="embedding_weight must be between 0 and 1")
    
    if llm_weight < 0 or llm_weight > 1:
        raise HTTPException(status_code=400, detail="llm_weight must be between 0 and 1")
    
    if abs((embedding_weight + llm_weight) - 1.0) > 0.01:
        raise HTTPException(status_code=400, detail="embedding_weight + llm_weight must equal 1.0")
    
    # Validate JD file
    jd_filename = jd_file.filename.lower()
    if not (jd_filename.endswith('.pdf') or jd_filename.endswith('.docx') or 
            jd_filename.endswith('.doc') or jd_filename.endswith('.txt')):
        raise HTTPException(status_code=400, detail="JD file must be PDF, DOCX, or TXT")
    
    # Validate resume files
    for resume in resume_files:
        filename = resume.filename.lower()
        if not (filename.endswith('.pdf') or filename.endswith('.docx') or 
                filename.endswith('.doc') or filename.endswith('.txt')):
            raise HTTPException(
                status_code=400, 
                detail=f"Invalid file format: {resume.filename}. Only PDF, DOCX, and TXT allowed"
            )
    
    # Parse requirements
    must_have_list = [req.strip() for req in must_have_requirements.split(',') if req.strip()] if must_have_requirements else None
    nice_to_have_list = [req.strip() for req in nice_to_have.split(',') if req.strip()] if nice_to_have else None
    
    try:
        # Log activity
        await logActivity(
            user,
            "Enhanced AI Resume Screening Started",
            f"Processing {len(resume_files)} resumes with {len(must_have_list or [])} critical requirements",
            "Started"
        )
        
        # Read JD file
        jd_content = await jd_file.read()
        jd_tuple = (jd_content, jd_file.filename)
        
        # Read all resume files
        resume_tuples = []
        for resume in resume_files:
            content = await resume.read()
            resume_tuples.append((content, resume.filename))
        
        # Process resumes with enhanced screening
        print(f"\n🚀 Starting enhanced resume screening: {len(resume_files)} resumes, top {top_n}")
        results = await screen_resumes_enhanced(
            resume_tuples,
            jd_tuple,
            top_n,
            must_have_list,
            nice_to_have_list,
            min_embedding_score,
            embedding_weight,
            llm_weight
        )
        
        # Log success
        await logActivity(
            user,
            "Enhanced AI Resume Screening Completed",
            f"Successfully screened {results['total_resumes_processed']} resumes. Top {len(results['top_resumes'])} returned.",
            "Success"
        )
        
        return JSONResponse(
            status_code=200,
            content={
                "message": "Enhanced resume screening completed successfully",
                "results": results,
                "user": user.get("email")
            }
        )
        
    except ValueError as e:
        await logActivity(
            user,
            "Enhanced AI Resume Screening Failed",
            f"Validation error: {str(e)}",
            "Error"
        )
        raise HTTPException(status_code=400, detail=str(e))
    
    except Exception as e:
        await logActivity(
            user,
            "Enhanced AI Resume Screening Failed",
            f"Error: {str(e)}",
            "Error"
        )
        raise HTTPException(status_code=500, detail=f"Enhanced resume screening failed: {str(e)}")
