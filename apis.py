import asyncio
import aiohttp
from datetime import datetime, timezone
from motor.motor_asyncio import AsyncIOMotorClient
from bson import ObjectId
from utils.ai_utils import *
# ---------------------------------------------------
# 📌 Surepass Dummy Credentials (REPLACE THEM)
# ---------------------------------------------------
SUREPASS_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmcmVzaCI6ZmFsc2UsImlhdCI6MTc2MzgwMDM0NywianRpIjoiNjA5ZTZmOTctNTcxOS00MjA2LWEwZDAtMjc5ZmFiZTQ0ODQ1IiwidHlwZSI6ImFjY2VzcyIsImlkZW50aXR5IjoiZGV2LnRocmVzaGluZ0BzdXJlcGFzcy5pbyIsIm5iZiI6MTc2MzgwMDM0NywiZXhwIjoyMzk0NTIwMzQ3LCJlbWFpbCI6InRocmVzaGluZ0BzdXJlcGFzcy5pbyIsInRlbmFudF9pZCI6Im1haW4iLCJ1c2VyX2NsYWltcyI6eyJzY29wZXMiOlsidXNlciJdfX0.h90UBZtuKinYF4kjsJ8sGjDR0rtAXNDsDpJwS3bQAEw"
SUREPASS_CUSTOMER_ID = ""

# ---------------------------------------------------
# 📌 MongoDB
# ---------------------------------------------------
mongoUri = "mongodb+srv://maihoo:akonpopStar%40143@maihoo.ztaytqd.mongodb.net/?appName=maihoo"
mongoDbName = "bgv_core"

client = AsyncIOMotorClient(mongoUri)
db = client[mongoDbName]

verificationsCol = db["verifications"]
candidatesCol = db["candidates"]
activityLogsCol = db["activityLogs"]   # <-- REQUIRED FOR LOGGING

# ---------------------------------------------------
# 📌 Resume Validation Check  (FULL – NO REMOVALS)
# ---------------------------------------------------
# ---------------------------------------------------
# RESUME VALIDATION CHECK (uses your ollama model)
# ---------------------------------------------------
async def verify_resume_validation(candidate: dict):
    """
    1. Loads resume file path from candidate.resumePath  
    2. Extracts text using ai_utils extractors  
    3. Sends extracted resume text to LLaMA validator  
    4. Returns COMPLETED or FAILED  
    """

    from utils.ai_utils import extract_text_from_pdf, extract_text_from_docx, llm_resume_validator

    resumePath = candidate.get("resumePath")
    if not resumePath:
        return "FAILED", "Resume not uploaded"

    ext = resumePath.split(".")[-1].lower()

    try:
        # -----------------------------------
        # Extract resume text
        # -----------------------------------
        if ext == "pdf":
            extractedText = extract_text_from_pdf(resumePath)
        elif ext == "docx":
            extractedText = extract_text_from_docx(resumePath)
        else:
            return "FAILED", f"Unsupported file type: {ext}"

        if not extractedText or len(extractedText.strip()) < 20:
            return "FAILED", "Could not extract any meaningful text"

        # -----------------------------------
        # Validate resume using LLaMA
        # -----------------------------------
        validation = await llm_resume_validator(extractedText)

        # validation = {
        #     "status": "VALID" | "INVALID",
        #     "issues": [...],
        #     "explanation": "..."
        # }

        if validation.get("status") == "VALID":
            return "COMPLETED", {
                "message": "Resume validation passed",
                "details": validation
            }

        else:
            return "FAILED", {
                "message": "Resume validation failed",
                "details": validation
            }

    except Exception as e:
        return "FAILED", f"Resume validation error: {str(e)}"


# ---------------------------------------------------
# 📌 HTTP utility
# ---------------------------------------------------
async def post_json(url: str, headers: dict, payload: dict):
    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(url, json=payload, headers=headers, timeout=60) as resp:
                data = await resp.json()
                success = resp.status == 200 and data.get("success", False)
                status = "COMPLETED" if success else "FAILED"
                remarks = data if not success else data.get("data", data)

                return status, remarks

    except Exception as e:
        return "FAILED", f"API Error: {e}"


# ---------------------------------------------------
# 📌 Verification Functions (FULL CODE — ONLY FIXED PAN/AADHAAR)
# ---------------------------------------------------
async def verify_pan_aadhaar_seeding(pan_number: str, aadhaar_number: str):
    url = "https://kyc-api.surepass.io/api/v1/pan/aadhaar-pan-link-check"
    headers = {"Authorization": f"Bearer {SUREPASS_TOKEN}", "Content-Type": "application/json"}
    payload = {
        "pan_number": pan_number,
        "aadhaar_number": aadhaar_number
    }
    return await post_json(url, headers, payload)

async def verify_pan(pan_number: str):
    url = "https://kyc-api.surepass.io/api/v1/pan/pan"
    headers = {"Authorization": f"Bearer {SUREPASS_TOKEN}", "Content-Type": "application/json"}
    payload = {"id_number": pan_number}
    return await post_json(url, headers, payload)

async def verify_employment_history(uan_number: str):
    url = "https://kyc-api.surepass.io/api/v1/income/employment-history-uan-v2"
    headers = {"Authorization": f"Bearer {SUREPASS_TOKEN}", "Content-Type": "application/json"}
    payload = {"id_number": uan_number}
    return await post_json(url, headers, payload)

async def verify_pan_to_uan(pan_number: str):
    url = "https://kyc-api.surepass.io/api/v1/pan/pan-to-uan"
    headers = {"Authorization": f"Bearer {SUREPASS_TOKEN}", "Content-Type": "application/json"}
    payload = {"pan_number": pan_number}
    return await post_json(url, headers, payload)

async def verify_credit_report(candidate: dict):
    url = "https://kyc-api.surepass.io/api/v1/credit-report-cibil/fetch-report"
    headers = {"Authorization": f"Bearer {SUREPASS_TOKEN}", "Content-Type": "application/json"}
    payload = {
        "mobile": candidate.get("phone"),
        "pan": candidate.get("panNumber"),
        "name": f"{candidate.get('firstName')} {candidate.get('lastName')}",
        "gender": "male",
        "consent": "Y"
    }
    return await post_json(url, headers, payload)

async def verify_court_record(candidate: dict):
    url = "https://kyc-api.surepass.io/api/v1/ecourts/ecourt-search-v2"
    headers = {"Authorization": f"Bearer {SUREPASS_TOKEN}", "Content-Type": "application/json"}
    payload = {
        "name": f"{candidate.get('firstName')} {candidate.get('lastName')}",
        "father_name": "",
        "address": candidate.get("address", ""),
        "year": "",
        "state": ""
    }
    return await post_json(url, headers, payload)


# ---------------------------------------------------
# 📌 Internal Verification Functions (Manual/AI)
# ---------------------------------------------------
async def verify_address_manual(candidate: dict):
    """
    Internal address verification - manual check only
    Returns PENDING status as this requires manual verification through UI
    """
    return "PENDING", {
        "message": "Address verification pending manual review",
        "candidateAddress": candidate.get("address", ""),
        "district": candidate.get("district", ""),
        "state": candidate.get("state", ""),
        "pincode": candidate.get("pincode", ""),
        "requiresManualVerification": True
    }

async def verify_education_manual(candidate: dict):
    """
    Education check manual offline - requires manual research and verification
    Returns PENDING status as this requires manual verification through UI
    """
    return "PENDING", {
        "message": "Education verification pending manual offline research",
        "candidateName": f"{candidate.get('firstName', '')} {candidate.get('lastName', '')}".strip(),
        "requiresManualVerification": True,
        "instructions": "Manually verify education credentials through institution contact or online verification"
    }

async def verify_education_ai(candidate: dict):
    """
    Education check AI - OCR/PDF extraction + LLM validation
    Processes education certificates using AI
    """
    from utils.ai_utils import extract_text_from_pdf, extract_text_from_docx, llm_education_validator
    
    # Look for education certificate path (you may need to add this field to candidate schema)
    educationCertPath = candidate.get("educationCertificatePath")
    if not educationCertPath:
        return "FAILED", "Education certificate not uploaded"

    ext = educationCertPath.split(".")[-1].lower()

    try:
        # Extract text from certificate
        if ext == "pdf":
            extractedText = extract_text_from_pdf(educationCertPath)
        elif ext == "docx":
            extractedText = extract_text_from_docx(educationCertPath)
        else:
            return "FAILED", f"Unsupported certificate file type: {ext}"

        if not extractedText or len(extractedText.strip()) < 20:
            return "FAILED", "Could not extract meaningful text from certificate"

        # Validate using LLM (you'll need to implement this in ai_utils.py)
        validation = await llm_education_validator(extractedText, candidate)

        if validation.get("status") == "VALID":
            return "COMPLETED", {
                "message": "Education certificate validation passed",
                "details": validation,
                "extractedText": extractedText[:500] + "..." if len(extractedText) > 500 else extractedText
            }
        else:
            return "FAILED", {
                "message": "Education certificate validation failed",
                "details": validation,
                "extractedText": extractedText[:500] + "..." if len(extractedText) > 500 else extractedText
            }

    except Exception as e:
        return "FAILED", f"Education AI validation error: {str(e)}"

async def verify_supervisory_check(candidate: dict):
    """
    Supervisory check - manual phone call to past organization
    Returns PENDING status as this requires manual phone verification
    """
    return "PENDING", {
        "message": "Supervisory check pending manual phone verification",
        "candidateName": f"{candidate.get('firstName', '')} {candidate.get('lastName', '')}".strip(),
        "candidatePhone": candidate.get("phone", ""),
        "requiresManualVerification": True,
        "instructions": "Contact candidate's previous organization for employment verification via phone call"
    }

async def verify_employment_history_manual(candidate: dict):
    """
    Employment history manual offline verification
    Returns PENDING status as this requires manual verification through UI
    """
    return "PENDING", {
        "message": "Employment history verification pending manual offline check",
        "candidateName": f"{candidate.get('firstName', '')} {candidate.get('lastName', '')}".strip(),
        "requiresManualVerification": True,
        "instructions": "Manually verify employment history through previous employers, documents, or references"
    }


# ---------------------------------------------------
# 📌 Dispatcher (FULL — ONLY FIXED pan_aadhaar)
# ---------------------------------------------------
def validate_fields(check_type, candidate):
    required = {
        "pan_aadhaar_seeding": ["aadhaarNumber", "panNumber"],
        "pan_verification": ["panNumber"],
        "employment_history": ["uanNumber"],
        "verify_pan_to_uan": ["panNumber"],
        "credit_report": ["phone", "panNumber", "firstName", "lastName"],
        "court_record": ["firstName", "lastName", "address"],
        "resume_validation": ["resumePath"],  # resume must already be uploaded
        
        # Internal verification checks
        "address_verification": ["address"],  # basic address required
        "education_check_manual": ["firstName", "lastName"],  # basic name required
        "education_check_ai": ["educationCertificatePath"],  # certificate file required
        "supervisory_check": ["firstName", "lastName"],  # basic name required
        "employment_history_manual": ["firstName", "lastName"]  # basic name required
    }

    fields = required.get(check_type, [])
    for field in fields:
        if not candidate.get(field):
            return False, field
    return True, None


async def run_verification(check_type: str, candidate: dict):
    check_type = check_type.lower().strip()

    ok, missing_field = validate_fields(check_type, candidate)
    if not ok:
        return "SKIPPED", f"Missing required field: {missing_field}"

    if check_type == "pan_aadhaar_seeding":
        return await verify_pan_aadhaar_seeding(
            candidate.get("panNumber"),
            candidate.get("aadhaarNumber")
        )

    if check_type == "pan_verification":
        return await verify_pan(candidate.get("panNumber"))

    if check_type == "employment_history":
        return await verify_employment_history(candidate.get("uanNumber"))

    if check_type == "verify_pan_to_uan":
        return await verify_pan_to_uan(candidate.get("panNumber"))

    if check_type == "credit_report":
        return await verify_credit_report(candidate)

    if check_type == "court_record":
        return await verify_court_record(candidate)
    
    if check_type == "resume_validation":
        return await verify_resume_validation(candidate)
    
    # Internal verification checks
    if check_type == "address_verification":
        return await verify_address_manual(candidate)
    
    if check_type == "education_check_manual":
        return await verify_education_manual(candidate)
    
    if check_type == "education_check_ai":
        return await verify_education_ai(candidate)
    
    if check_type == "supervisory_check":
        return await verify_supervisory_check(candidate)
    
    if check_type == "employment_history_manual":
        return await verify_employment_history_manual(candidate)

    return "FAILED", f"Unknown check type: {check_type}"
    


# ---------------------------------------------------
# 📌 Orchestrator (UNCHANGED — INCLUDED FULLY)
# ---------------------------------------------------
async def process_verification_record(verification):
    try:
        candidate = await candidatesCol.find_one({"_id": ObjectId(verification["candidateId"])})
        if not candidate:
            print(f"⚠ Candidate not found: {verification['_id']}")
            return

        await activityLogsCol.insert_one({
            "userId": str(verification.get("createdBy")),
            "organizationId": str(verification.get("organizationId")),
            "action": "Verification Started",
            "details": f"Candidate: {candidate.get('firstName')} {candidate.get('lastName')}",
            "timestamp": datetime.now(timezone.utc)
        })

        print(f"\n🚀 Starting verification for {candidate.get('firstName')}")

        for stage_name, checks in verification["stages"].items():

            await verificationsCol.update_one(
                {"_id": verification["_id"]},
                {"$set": {"currentStage": stage_name}}
            )

            print(f"➡ Stage: {stage_name}")

            for check in checks:
                check_name = check["check"]

                await verificationsCol.update_one(
                    {"_id": verification["_id"], f"stages.{stage_name}.check": check_name},
                    {"$set": {f"stages.{stage_name}.$.status": "IN_PROGRESS"}}
                )

                status, remarks = await run_verification(check_name, candidate)

                await activityLogsCol.insert_one({
                    "userId": str(verification.get("createdBy")),
                    "organizationId": str(verification.get("organizationId")),
                    "action": f"Verification Check: {check_name}",
                    "details": f"Status: {status}",
                    "timestamp": datetime.now(timezone.utc)
                })

                await verificationsCol.update_one(
                    {"_id": verification["_id"], f"stages.{stage_name}.check": check_name},
                    {"$set": {
                        f"stages.{stage_name}.$.status": status,
                        f"stages.{stage_name}.$.remarks": remarks
                    }}
                )

                print(f"   ✔ {check_name} → {status}")

            await asyncio.sleep(1)

        await verificationsCol.update_one(
            {"_id": verification["_id"]},
            {"$set": {
                "overallStatus": "COMPLETED",
                "completedAt": datetime.now(timezone.utc).isoformat()
            }}
        )

        await candidatesCol.update_one(
            {"_id": ObjectId(verification["candidateId"])},
            {"$set": {"status": "VERIFIED"}}
        )

        await activityLogsCol.insert_one({
            "userId": str(verification.get("createdBy")),
            "organizationId": str(verification.get("organizationId")),
            "action": "Verification Completed",
            "details": f"Candidate Verified: {candidate.get('firstName')}",
            "timestamp": datetime.now(timezone.utc)
        })

        print(f"🏁 Completed verification for {candidate.get('firstName')}")

    except Exception as e:
        print(f"❌ Orchestrator Error: {e}")
        await activityLogsCol.insert_one({
            "userId": str(verification.get("createdBy")),
            "organizationId": str(verification.get("organizationId")),
            "action": "Verification Failed",
            "details": str(e),
            "timestamp": datetime.now(timezone.utc)
        })
