# ai_app.py
from fastapi import FastAPI, Form, File, UploadFile, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from main import requireAuth
import os

# ------------ AI UTILS (your local LLaMA functions) ------------
from utils.ai_utils import (
    extract_text_from_pdf,
    extract_text_from_docx,
    extract_with_llama,
    llm_resume_validator
)

# ------------ APP INIT ------------
app = FastAPI(title="AI Engine App")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ==============================================================
# 🔥 AI RESUME SELECTION (already existing)
# ==============================================================
from main import generate_resume_embeddings_and_rank

@app.post("/secure/ai_resume_selection")
async def ai_resume_selection(
    jd: str = Form(...),
    resumes: list[UploadFile] = File(...),
):
    if len(resumes) == 0:
        raise HTTPException(status_code=400, detail="No resumes uploaded")

    if len(resumes) > 100:
        raise HTTPException(status_code=400, detail="Maximum 100 resumes allowed")

    topFive, pipelineRunId = await generate_resume_embeddings_and_rank(resumes, jd)

    return {
        "message": "AI Resume Selection Completed",
        "pipelineRunId": pipelineRunId,
        "topFiveResumes": topFive
    }


# ==============================================================
# ⭐ NEW: AI RESUME VALIDATION ENDPOINT
# ==============================================================

@app.post("/secure/ai_resume_validation")
async def ai_resume_validation(
    candidateId: str = Form(...),
    orgId: str = Form(...),
    resume: UploadFile = File(...)
):
    """
    Validates a resume using local LLaMA model:
    1. Extract text (PDF/DOCX)
    2. Analyze using LLaMA
    3. Return VALID | INVALID response

    NOTE: AUTH REMOVED (PUBLIC LIKE AI RESUME SELECTION)
    """

    # -----------------------------------------------------------
    # Validate file extension
    # -----------------------------------------------------------
    filename = resume.filename.lower()
    if not (filename.endswith(".pdf") or filename.endswith(".docx")):
        raise HTTPException(400, "Only PDF or DOCX files allowed")

    # -----------------------------------------------------------
    # Save temp file
    # -----------------------------------------------------------
    import os
    os.makedirs("/tmp/resumes", exist_ok=True)
    savePath = f"/tmp/resumes/{candidateId}_{filename}"

    with open(savePath, "wb") as f:
        f.write(await resume.read())

    # -----------------------------------------------------------
    # Extract text
    # -----------------------------------------------------------
    if filename.endswith(".pdf"):
        extractedText = extract_text_from_pdf(savePath)
    else:
        extractedText = extract_text_from_docx(savePath)

    if not extractedText or len(extractedText.strip()) < 20:
        raise HTTPException(400, "Resume extraction failed or text too short")

    # -----------------------------------------------------------
    # Run resume validation with LLaMA
    # -----------------------------------------------------------
    result = await llm_resume_validator(extractedText)

    if not result:
        raise HTTPException(500, "LLM returned no response")

    # -----------------------------------------------------------
    # Final Response
    # -----------------------------------------------------------
    return {
        "candidateId": candidateId,
        "orgId": orgId,
        "resumeFile": filename,
        "validation": result
    }
