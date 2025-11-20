import PyPDF2
import docx
import uuid
from datetime import datetime
from pymongo import MongoClient
import json
import re
import torch
from sentence_transformers import util

# -----------------------------------------------------
# GOOGLE GEMINI CONFIG
# -----------------------------------------------------
from google import genai
from dotenv import load_dotenv
import os

# Load .env (important!)
load_dotenv()

GEMINI_KEY = os.getenv("GEMINI_API_KEY")

if not GEMINI_KEY:
    raise ValueError("GEMINI_API_KEY is missing! Set it in .env or Render environment variables.")

client = genai.Client(api_key=GEMINI_KEY)




# -----------------------------------------------------
# MongoDB Configuration
# -----------------------------------------------------
mongoUri = "mongodb+srv://maihoo:akonpopStar%40143@maihoo.ztaytqd.mongodb.net/?appName=maihoo"
mongoDbName = "bgv_core"

client_mongo = MongoClient(mongoUri)
db = client_mongo[mongoDbName]
collection = db["resume_matches"]


# -----------------------------------------------------
# TEXT EXTRACTION HELPERS
# -----------------------------------------------------
def extract_text_from_pdf(file):
    pdf = PyPDF2.PdfReader(file)
    text = ""
    for page in pdf.pages:
        try:
            text += (page.extract_text() or "") + "\n"
        except:
            continue
    return text


def extract_text_from_docx(file):
    doc = docx.Document(file)
    return "\n".join([p.text for p in doc.paragraphs])


# -----------------------------------------------------
# GEMINI EMBEDDING FUNCTION (MAIN CHANGE)
# -----------------------------------------------------
def get_embedding(text: str):
    """
    Converts text to a vector using Gemini embeddings.
    """
    try:
        resp = client.models.embed_content(
            model="gemini-embedding-001",
            contents=text
        )
        return resp.embeddings[0].values
    except Exception as e:
        print("Embedding Error:", e)
        return [0.0] * 768  # fail-safe vector size


# -----------------------------------------------------
# PROMPTS
# -----------------------------------------------------
def build_clean_prompt(text):
    return f"""
Extract ONLY:

- Technical skills
- Tools & technologies
- Programming languages
- Frameworks
- ML/AI terms
- Project titles
- Job roles
- Responsibilities
- Domain keywords

Copy EXACT text from the document.
NO rewriting.
NO summary.
Return ONE cleaned text block.

TEXT:
{text}

Return cleaned content only:
"""


def build_skill_prompt(text):
    return f"""
Extract only technical skills.
Return comma-separated.
No sentences.

TEXT:
{text}
"""


def build_domain_prompt(text):
    return f"""
Pick one domain only:

["Mechanical", "Software", "AI/ML", "Civil", "Electrical", "Electronics", "Business", "Other"]

TEXT:
{text}

Return one domain word:
"""


# -----------------------------------------------------
# GEMINI LLM WRAPPER
# -----------------------------------------------------
def call_llm(prompt):
    try:
        resp = client.models.generate_content(
            model="gemini-2.5-flash",
            contents=prompt
        )
        out = resp.text.strip()

        if not out:
            return ""
        if len(out) < 5:
            return ""

        return out
    except:
        return ""


# -----------------------------------------------------
# MAIN PIPELINE
# -----------------------------------------------------
async def generate_resume_embeddings_and_rank(resumes, jd):

    resumeData = []
    pipelineRunId = f"RUN_{uuid.uuid4()}"

    collection.insert_one({
        "pipelineRunId": pipelineRunId,
        "jdText": jd,
        "createdAt": datetime.utcnow(),
        "stepStatus": {
            "textExtraction": "pending",
            "cleaning": "pending",
            "skillExtraction": "pending",
            "domainClassification": "pending",
            "embeddingGeneration": "pending",
            "similarityCalculation": "pending"
        }
    })

    # ---------------- JD PROCESSING ----------------

    jd_clean = call_llm(build_clean_prompt(jd))
    if jd_clean == "":
        jd_clean = jd

    jd_skills = call_llm(build_skill_prompt(jd_clean))
    jd_domain = call_llm(build_domain_prompt(jd_clean))

    jd_skill_set = set([s.strip().lower() for s in jd_skills.split(",") if s.strip()])

    # ************* GEMINI EMBEDDING *************
    jd_vec = get_embedding(jd_clean)

    collection.update_one(
        {"pipelineRunId": pipelineRunId},
        {"$set": {
            "jdCleaned": jd_clean,
            "jdSkills": list(jd_skill_set),
            "jdDomain": jd_domain
        }}
    )

    # -------------- RESUMES ------------------------

    for file in resumes:

        filename = file.filename.lower()

        if filename.endswith(".pdf"):
            raw = extract_text_from_pdf(file.file)
        elif filename.endswith(".docx"):
            raw = extract_text_from_docx(file.file)
        else:
            continue

        clean_text = call_llm(build_clean_prompt(raw))
        if clean_text == "":
            clean_text = raw  # fallback

        resume_skills = call_llm(build_skill_prompt(clean_text))
        resume_domain = call_llm(build_domain_prompt(clean_text))

        skill_set = set([s.strip().lower() for s in resume_skills.split(",") if s.strip()])

        # ************* GEMINI EMBEDDING *************
        resume_vec = get_embedding(clean_text)

        # Convert to tensors for cosine similarity
        emb_score = float(util.cos_sim(
            torch.tensor(resume_vec),
            torch.tensor(jd_vec)
        ).item())

        # Skill overlap score
        if len(jd_skill_set) > 0:
            overlap = len(jd_skill_set.intersection(skill_set))
            skill_score = overlap / len(jd_skill_set)
        else:
            skill_score = 0

        # Domain Score
        domain_score = 1 if resume_domain.lower() == jd_domain.lower() else 0

        final_score = (0.6 * skill_score) + (0.25 * emb_score) + (0.15 * domain_score)

        resumeData.append({
            "fileName": file.filename,
            "finalScore": final_score,
            "cleaned": clean_text,
            "skills": list(skill_set),
            "domain": resume_domain,
            "embeddingScore": emb_score,
            "skillScore": skill_score,
            "domainScore": domain_score,
        })

    # Sort & save
    resumeData.sort(key=lambda x: x["finalScore"], reverse=True)
    topFive = resumeData[:5]

    collection.update_one(
        {"pipelineRunId": pipelineRunId},
        {"$set": {"finalTopFive": topFive}}
    )

    return topFive, pipelineRunId
