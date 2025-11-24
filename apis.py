import asyncio
import aiohttp
from datetime import datetime, timezone
from motor.motor_asyncio import AsyncIOMotorClient
from bson import ObjectId

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
# 📌 Verification Functions (REAL CALLS)
# ---------------------------------------------------
# (UNCHANGED)
# ---------------------------------------------------
async def verify_pan_aadhaar_seeding(aadhaar_number: str):
    url = "https://kyc-api.surepass.io/api/v1/pan/aadhaar-pan-link-check"
    headers = {"Authorization": f"Bearer {SUREPASS_TOKEN}", "Content-Type": "application/json"}
    payload = {"aadhaar_number": aadhaar_number}
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
# 📌 Dispatcher (UNCHANGED)
# ---------------------------------------------------
def validate_fields(check_type, candidate):
    required = {
        "pan_aadhaar_seeding": ["aadhaarNumber"],
        "pan_verification": ["panNumber"],
        "employment_history": ["uanNumber"],
        "verify_pan_to_uan": ["panNumber"],
        "credit_report": ["phone", "panNumber", "firstName", "lastName"],
        "court_record": ["firstName", "lastName", "address"]
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
        return await verify_pan_aadhaar_seeding(candidate.get("pan"))

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

    return "FAILED", f"Unknown check type: {check_type}"


# ---------------------------------------------------
# 📌 Orchestrator — NOW WITH LOGGING (ONLY ADDED, NOTHING REMOVED)
# ---------------------------------------------------
async def process_verification_record(verification):
    try:
        candidate = await candidatesCol.find_one({"_id": ObjectId(verification["candidateId"])})
        if not candidate:
            print(f"⚠ Candidate not found: {verification['_id']}")
            return

        # 🔵 LOG: VERIFICATION STARTED
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

                # 🔵 LOG: EACH CHECK RESULT
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

        # UPDATE STATUS
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

        # 🔵 LOG: VERIFICATION COMPLETED
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

        # 🔴 LOG: VERIFICATION FAILED
        await activityLogsCol.insert_one({
            "userId": str(verification.get("createdBy")),
            "organizationId": str(verification.get("organizationId")),
            "action": "Verification Failed",
            "details": str(e),
            "timestamp": datetime.now(timezone.utc)
        })
