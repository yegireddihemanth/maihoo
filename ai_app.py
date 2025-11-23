# ai_app.py
from fastapi import FastAPI, Form, File, UploadFile, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from main import generate_resume_embeddings_and_rank

app = FastAPI(title="AI Engine App")

# 🔥 FULL CORS FIX (NGROK → NGROK SAFE)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],        # allow all origins (ngrok requires this)
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.post("/secure/ai_resume_selection")
async def ai_resume_selection(
    jd: str = Form(...),
    resumes: list[UploadFile] = File(...),
):
    if len(resumes) == 0:
        raise HTTPException(status_code=400, detail="No resumes uploaded")

    if len(resumes) > 100:
        raise HTTPException(status_code=400, detail="Maximum 100 resumes allowed")

    # Use local AI engine
    topFive, pipelineRunId = await generate_resume_embeddings_and_rank(resumes, jd)

    return {
        "message": "AI Resume Selection Completed",
        "pipelineRunId": pipelineRunId,
        "topFiveResumes": topFive
    }
