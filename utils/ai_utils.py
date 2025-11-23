import PyPDF2
import docx
import uuid
from datetime import datetime
from pymongo import MongoClient
import torch
from sentence_transformers import util
import re

from ollama import Client

# ------------------------------------------------
# OLLAMA CLIENT
# ------------------------------------------------
ollama = Client()

LLM_MODEL = "llama3.2"
EMBED_MODEL = "nomic-embed-text"
EMB_DIM = 768  # force final embedding size


# ------------------------------------------------
# MONGO
# ------------------------------------------------
mongoUri = "mongodb+srv://maihoo:akonpopStar%40143@maihoo.ztaytqd.mongodb.net/?appName=maihoo"
client_mongo = MongoClient(mongoUri)
db = client_mongo["bgv_core"]
collection = db["resume_matches"]


# ------------------------------------------------
# TEXT EXTRACTORS
# ------------------------------------------------
def extract_text_from_pdf(file):
    try:
        pdf = PyPDF2.PdfReader(file)
        return "\n".join([(p.extract_text() or "") for p in pdf.pages])
    except:
        return ""


def extract_text_from_docx(file):
    try:
        doc = docx.Document(file)
        return "\n".join([p.text for p in doc.paragraphs])
    except:
        return ""


# ------------------------------------------------
# CLEAN LLaMA OUTPUT
# ------------------------------------------------
def clean_llama_output(text):
    if not text:
        return ""

    text = re.sub(r"\*\*|__", "", text)
    text = re.sub(r"[•\-*]\s*", "", text)
    text = re.sub(r"Here is.*?:", "", text, flags=re.I)
    text = re.sub(r"Here are.*?:", "", text, flags=re.I)
    text = re.sub(r"[#>\[\]\(\)]", "", text)

    return text.strip()


# ------------------------------------------------
# EXTRACTION PROMPT
# ------------------------------------------------
def build_prompt(text):
    return f"""
Extract ALL important technical and job-related information from the text.

Return ONLY ONE single plain text paragraph containing:
skills, tools, experience, frameworks, projects, job roles, domain, achievements.

NO bullet points.
NO markdown.
NO headings.
NO explanation.
ONE clean paragraph only.

TEXT:
{text}
"""


# ------------------------------------------------
# CALL LLaMA3 FOR EXTRACTION
# ------------------------------------------------
def extract_with_llama(text):
    try:
        if len(text) > 5000:
            text = text[:5000]

        print("\n🟣 LLM CALL STARTED")
        prompt = build_prompt(text)

        res = ollama.chat(
            model=LLM_MODEL,
            messages=[{"role": "user", "content": prompt}]
        )

        raw = res["message"]["content"]
        return clean_llama_output(raw)

    except Exception as e:
        print("❌ LLM ERROR:", e)
        return ""


# ------------------------------------------------
# EMBEDDINGS (PYTHON OLLAMA SDK ONLY)
# ------------------------------------------------
def fix_dim(v):
    if len(v) > EMB_DIM:
        return v[:EMB_DIM]
    if len(v) < EMB_DIM:
        return v + [0.0] * (EMB_DIM - len(v))
    return v


def get_embedding(text):
    try:
        print("\n🔵 GENERATING EMBEDDING USING OLLAMA PYTHON SDK")

        res = ollama.embeddings(
            model=EMBED_MODEL,
            prompt=text
        )

        vec = res["embedding"]
        print("Embedding size returned =", len(vec))

        fixed = fix_dim(vec)
        print("Final embedding size =", len(fixed))

        return fixed

    except Exception as e:
        print("❌ EMBEDDING ERROR:", e)
        return [0.0] * EMB_DIM


# ------------------------------------------------
# MAIN PIPELINE
# ------------------------------------------------
async def generate_resume_embeddings_and_rank(resumes, jd):

    runId = f"RUN_{uuid.uuid4()}"
    collection.insert_one({"pipelineRunId": runId, "createdAt": datetime.utcnow()})

    # ------------------ JD ------------------
    jd_extracted = extract_with_llama(jd)

    print("\n==============================")
    print("📘 JD EXTRACTED TEXT")
    print("==============================")
    print(jd_extracted[:1500], "\n")

    jd_vec = get_embedding(jd_extracted)

    results = []

    # ------------------ RESUMES ------------------
    for f in resumes:

        print("\n=============================================")
        print(f"📄 Processing Resume: {f.filename}")
        print("=============================================")

        if f.filename.lower().endswith(".pdf"):
            raw = extract_text_from_pdf(f.file)
        else:
            raw = extract_text_from_docx(f.file)

        resume_extracted = extract_with_llama(raw)

        print("\n==============================")
        print("📄 RESUME EXTRACTED TEXT")
        print("==============================")
        print(resume_extracted[:1500], "\n")

        resume_vec = get_embedding(resume_extracted)

        score = float(util.cos_sim(
            torch.tensor(jd_vec),
            torch.tensor(resume_vec)
        ))

        print(f"🔥 FINAL SIMILARITY SCORE = {score}")

        results.append({
            "fileName": f.filename,
            "similarity": score,
            "extracted": resume_extracted
        })

    results.sort(key=lambda x: x["similarity"], reverse=True)

    collection.update_one(
        {"pipelineRunId": runId},
        {"$set": {"finalTopFive": results[:5]}}
    )

    return results[:5], runId
