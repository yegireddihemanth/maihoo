import asyncio
import random
from datetime import datetime, timezone
from motor.motor_asyncio import AsyncIOMotorClient
from bson import ObjectId

# -----------------------
# 🧩 MongoDB Connection (Atlas)
# -----------------------
mongoUri = "mongodb+srv://maihoo:akonpopStar%40143@maihoo.ztaytqd.mongodb.net/?appName=maihoo"
mongoDbName = "bgv_core"

client = AsyncIOMotorClient(mongoUri)
db = client[mongoDbName]

verificationsCol = db["verifications"]
candidatesCol = db["candidates"]

# -----------------------
# 🧩 Utility
# -----------------------
async def simulate_processing(task_name: str, min_sec=2, max_sec=5):
    """Simulate API delay + random success/failure."""
    duration = random.randint(min_sec, max_sec)
    await asyncio.sleep(duration)
    success = random.choice([True, True, True, False])  # 75% success rate
    status = "COMPLETED" if success else "FAILED"
    remarks = f"{task_name} verification {'successful' if success else 'failed'} after {duration}s"
    return status, remarks


# -----------------------
# 🪪 Primary Checks
# -----------------------
async def verify_aadhaar(aadhaar_number: str):
    return await simulate_processing("Aadhaar")

async def verify_pan(pan_number: str):
    return await simulate_processing("PAN")

async def verify_bank_account(account_number: str = None):
    return await simulate_processing("Bank Account")

# -----------------------
# 🧾 Secondary Checks
# -----------------------
async def verify_uan(uan_number: str = None):
    return await simulate_processing("UAN / EPFO")

async def verify_fir(candidate_name: str):
    return await simulate_processing("FIR / Criminal Record")

async def verify_passport(passport_number: str = None):
    return await simulate_processing("Passport")

# -----------------------
# 🎓 Final Checks
# -----------------------
async def verify_education(candidate_name: str):
    return await simulate_processing("Education Verification")

async def verify_employment(candidate_name: str):
    return await simulate_processing("Employment Verification")

async def verify_cibil(candidate_name: str):
    return await simulate_processing("CIBIL / Credit Score")


# -----------------------
# 🚦 Dispatcher (Router)
# -----------------------
async def run_verification(check_type: str, candidate: dict):
    """Route to the correct verification function."""
    check_type = check_type.lower().replace(" ", "_")

    # --- Primary Stage ---
    if check_type in ["aadhaar", "aadhaar_verification"]:
        return await verify_aadhaar(candidate.get("aadhaarNumber"))
    elif check_type in ["pan", "pan_verification"]:
        return await verify_pan(candidate.get("panNumber"))
    elif check_type in ["bankaccount", "bank_account", "bank_account_verification", "bank"]:
        return await verify_bank_account()

    # --- Secondary Stage ---
    elif check_type in ["uan", "uan_verification"]:
        return await verify_uan()
    elif check_type in ["fir", "criminal", "criminal_record", "criminal_record_verification"]:
        return await verify_fir(candidate.get("firstName"))
    elif check_type in ["passport", "passport_verification", "passportcheck", "passport_check"]:
        return await verify_passport(candidate.get("passportNumber"))

    # --- Final Stage ---
    elif check_type in ["education", "education_verification", "degree", "degree_verification"]:
        return await verify_education(candidate.get("firstName"))
    elif check_type in ["employment", "employment_verification"]:
        return await verify_employment(candidate.get("firstName"))
    elif check_type in ["cibil", "cibil_report", "cibil_score"]:
        return await verify_cibil(candidate.get("firstName"))

    # ❌ Unknown type fallback
    else:
        return "FAILED", f"Unknown check type: {check_type}"


# ---------------------------------------------------
# 🧠 Verification Orchestrator for pending requests
# ---------------------------------------------------
async def process_verification_record(verification):
    """Run all stages (primary → secondary → final) sequentially."""
    try:
        candidate = await candidatesCol.find_one({"_id": ObjectId(verification["candidateId"])})
        if not candidate:
            print(f"⚠️ Candidate not found for verification {verification['_id']}")
            return

        print(f"\n🚀 Starting verification for {candidate.get('firstName')} ({verification['organizationName']})")

        for stage_name, checks in verification["stages"].items():
            print(f"➡️ Stage: {stage_name} ({len(checks)} checks)")

            # Mark current stage
            await verificationsCol.update_one(
                {"_id": verification["_id"]},
                {"$set": {"currentStage": stage_name}}
            )

            for check in checks:
                check_name = check["check"]
                print(f"   🔹 Running {check_name} ...")

                # Mark as IN_PROGRESS
                await verificationsCol.update_one(
                    {"_id": verification["_id"], f"stages.{stage_name}.check": check_name},
                    {"$set": {f"stages.{stage_name}.$.status": "IN_PROGRESS"}}
                )

                # Run simulated check
                status, remarks = await run_verification(check_name, candidate)

                # Update check result
                await verificationsCol.update_one(
                    {"_id": verification["_id"], f"stages.{stage_name}.check": check_name},
                    {"$set": {
                        f"stages.{stage_name}.$.status": status,
                        f"stages.{stage_name}.$.remarks": remarks
                    }}
                )

                print(f"      ✅ {check_name} → {status}")

            await asyncio.sleep(1)  # small delay between stages

        # Mark verification as complete
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

        print(f"🏁 Completed verification for {candidate.get('firstName')}")

    except Exception as e:
        print(f"❌ Error in verification process: {e}")
