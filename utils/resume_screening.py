# Resume Screening with OpenAI Embeddings
import os
import io
import numpy as np
from typing import List, Dict, Tuple
from datetime import datetime
import json

# Import text extraction utilities
from utils.ai_utils import extract_text_from_pdf, extract_text_from_docx, extract_text_from_txt

# OpenAI Integration
try:
    import openai
    OPENAI_AVAILABLE = True
except ImportError:
    OPENAI_AVAILABLE = False
    print("⚠️ OpenAI not installed. Install with: pip install openai")

# Initialize OpenAI client
from dotenv import load_dotenv
load_dotenv()

OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
if OPENAI_API_KEY and OPENAI_AVAILABLE:
    openai_client = openai.OpenAI(api_key=OPENAI_API_KEY)
else:
    openai_client = None
    print("⚠️ OpenAI API key not configured for resume screening")


def extract_text_from_file(file_content: bytes, filename: str) -> str:
    """
    Extract text from uploaded file based on extension
    
    Args:
        file_content: File bytes
        filename: Original filename with extension
    
    Returns:
        Extracted text content
    """
    file_obj = io.BytesIO(file_content)
    filename_lower = filename.lower()
    
    if filename_lower.endswith('.pdf'):
        return extract_text_from_pdf(file_obj)
    elif filename_lower.endswith('.docx') or filename_lower.endswith('.doc'):
        return extract_text_from_docx(file_obj)
    elif filename_lower.endswith('.txt'):
        return extract_text_from_txt(file_obj)
    else:
        raise ValueError(f"Unsupported file format: {filename}")


def get_embedding(text: str) -> List[float]:
    """
    Generate embedding for text using OpenAI text-embedding-3-small
    
    Args:
        text: Text to embed
    
    Returns:
        Embedding vector (1536 dimensions)
    """
    if not openai_client:
        raise Exception("OpenAI client not configured")
    
    # Truncate text if too long (max 8191 tokens for text-embedding-3-small)
    if len(text) > 30000:  # Rough estimate: 4 chars per token
        text = text[:30000]
    
    response = openai_client.embeddings.create(
        model="text-embedding-3-small",
        input=text
    )
    
    return response.data[0].embedding


def cosine_similarity(vec1: List[float], vec2: List[float]) -> float:
    """Calculate cosine similarity between two vectors"""
    vec1_np = np.array(vec1)
    vec2_np = np.array(vec2)
    
    dot_product = np.dot(vec1_np, vec2_np)
    norm1 = np.linalg.norm(vec1_np)
    norm2 = np.linalg.norm(vec2_np)
    
    if norm1 == 0 or norm2 == 0:
        return 0.0
    
    return float(dot_product / (norm1 * norm2))


async def analyze_resume_with_ai(resume_text: str, jd_text: str, similarity_score: float) -> Dict:
    """
    Use OpenAI to analyze resume against JD and provide detailed insights
    
    Args:
        resume_text: Resume content
        jd_text: Job description content
        similarity_score: Embedding similarity score
    
    Returns:
        Analysis with strengths, weaknesses, skills match, etc.
    """
    if not openai_client:
        raise Exception("OpenAI client not configured")
    
    prompt = f"""You are an expert HR recruiter. Analyze this resume against the job description and provide a detailed assessment.

JOB DESCRIPTION:
{jd_text[:3000]}

RESUME:
{resume_text[:4000]}

EMBEDDING SIMILARITY SCORE: {similarity_score:.2%}

Provide a JSON response with:
1. "match_score": Overall match score 0-100
2. "strengths": List of 3-5 key strengths/positive points
3. "weaknesses": List of 3-5 gaps or concerns
4. "skills_match": {{
   "matched": [list of matched skills],
   "missing": [list of missing critical skills]
}}
5. "experience_match": Brief assessment of experience relevance
6. "education_match": Brief assessment of education fit
7. "recommendation": "STRONG_FIT" | "GOOD_FIT" | "MODERATE_FIT" | "WEAK_FIT"
8. "summary": 2-3 sentence overall assessment

Return ONLY valid JSON, no markdown or extra text."""

    try:
        response = openai_client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": "You are an expert HR recruiter providing structured resume analysis. Always respond with valid JSON only."},
                {"role": "user", "content": prompt}
            ],
            temperature=0.3,
            max_tokens=1000
        )
        
        analysis_text = response.choices[0].message.content.strip()
        
        # Remove markdown code blocks if present
        if analysis_text.startswith("```json"):
            analysis_text = analysis_text[7:]
        if analysis_text.startswith("```"):
            analysis_text = analysis_text[3:]
        if analysis_text.endswith("```"):
            analysis_text = analysis_text[:-3]
        
        analysis = json.loads(analysis_text.strip())
        return analysis
        
    except json.JSONDecodeError as e:
        print(f"⚠️ JSON decode error: {e}")
        # Return fallback analysis
        return {
            "match_score": int(similarity_score * 100),
            "strengths": ["Resume content extracted successfully"],
            "weaknesses": ["Detailed analysis unavailable"],
            "skills_match": {"matched": [], "missing": []},
            "experience_match": "Unable to analyze",
            "education_match": "Unable to analyze",
            "recommendation": "MODERATE_FIT" if similarity_score > 0.7 else "WEAK_FIT",
            "summary": f"Embedding similarity: {similarity_score:.2%}. Manual review recommended."
        }
    except Exception as e:
        print(f"❌ AI analysis error: {e}")
        raise


async def screen_resumes(
    resume_files: List[Tuple[bytes, str]],  # List of (file_content, filename)
    jd_file: Tuple[bytes, str],  # (jd_content, jd_filename)
    top_n: int = 5
) -> Dict:
    """
    Screen multiple resumes against a job description using embeddings
    
    Args:
        resume_files: List of tuples (file_content_bytes, filename)
        jd_file: Tuple of (jd_content_bytes, jd_filename)
        top_n: Number of top resumes to return
    
    Returns:
        Dictionary with top resumes and their analysis
    """
    if not openai_client:
        raise Exception("OpenAI client not configured. Please set OPENAI_API_KEY in .env")
    
    # Extract JD text
    jd_content, jd_filename = jd_file
    print(f"📄 Extracting JD from: {jd_filename}")
    jd_text = extract_text_from_file(jd_content, jd_filename)
    
    if not jd_text or len(jd_text.strip()) < 50:
        raise ValueError("Job description is too short or extraction failed")
    
    print(f"✅ JD extracted: {len(jd_text)} characters")
    
    # Generate JD embedding
    print("🔄 Generating JD embedding...")
    jd_embedding = get_embedding(jd_text)
    print(f"✅ JD embedding generated: {len(jd_embedding)} dimensions")
    
    # Process all resumes
    resume_results = []
    
    for idx, (resume_content, resume_filename) in enumerate(resume_files, 1):
        try:
            print(f"\n📄 Processing resume {idx}/{len(resume_files)}: {resume_filename}")
            
            # Extract text
            resume_text = extract_text_from_file(resume_content, resume_filename)
            
            if not resume_text or len(resume_text.strip()) < 50:
                print(f"⚠️ Skipping {resume_filename}: Text too short")
                continue
            
            print(f"✅ Text extracted: {len(resume_text)} characters")
            
            # Generate embedding
            resume_embedding = get_embedding(resume_text)
            print(f"✅ Embedding generated")
            
            # Calculate similarity
            similarity = cosine_similarity(jd_embedding, resume_embedding)
            print(f"📊 Similarity score: {similarity:.4f}")
            
            resume_results.append({
                "filename": resume_filename,
                "text": resume_text,
                "embedding": resume_embedding,
                "similarity_score": similarity
            })
            
        except Exception as e:
            print(f"❌ Error processing {resume_filename}: {e}")
            continue
    
    if not resume_results:
        raise ValueError("No resumes could be processed successfully")
    
    # Sort by similarity score (descending)
    resume_results.sort(key=lambda x: x["similarity_score"], reverse=True)
    
    # Get top N resumes
    top_resumes = resume_results[:top_n]
    
    print(f"\n🎯 Analyzing top {len(top_resumes)} resumes with AI...")
    
    # Analyze top resumes with AI
    final_results = []
    for idx, resume in enumerate(top_resumes, 1):
        print(f"\n🤖 AI Analysis {idx}/{len(top_resumes)}: {resume['filename']}")
        
        try:
            analysis = await analyze_resume_with_ai(
                resume["text"],
                jd_text,
                resume["similarity_score"]
            )
            
            final_results.append({
                "rank": idx,
                "filename": resume["filename"],
                "similarity_score": round(resume["similarity_score"], 4),
                "match_score": analysis.get("match_score", 0),
                "recommendation": analysis.get("recommendation", "MODERATE_FIT"),
                "summary": analysis.get("summary", ""),
                "strengths": analysis.get("strengths", []),
                "weaknesses": analysis.get("weaknesses", []),
                "skills_match": analysis.get("skills_match", {"matched": [], "missing": []}),
                "experience_match": analysis.get("experience_match", ""),
                "education_match": analysis.get("education_match", "")
            })
            
            print(f"✅ Analysis complete: {analysis.get('recommendation', 'N/A')}")
            
        except Exception as e:
            print(f"⚠️ AI analysis failed for {resume['filename']}: {e}")
            # Add basic result without AI analysis
            final_results.append({
                "rank": idx,
                "filename": resume["filename"],
                "similarity_score": round(resume["similarity_score"], 4),
                "match_score": int(resume["similarity_score"] * 100),
                "recommendation": "MODERATE_FIT",
                "summary": f"Embedding similarity: {resume['similarity_score']:.2%}",
                "strengths": ["Resume processed successfully"],
                "weaknesses": ["Detailed AI analysis unavailable"],
                "skills_match": {"matched": [], "missing": []},
                "experience_match": "Manual review required",
                "education_match": "Manual review required"
            })
    
    return {
        "total_resumes_processed": len(resume_results),
        "total_resumes_uploaded": len(resume_files),
        "top_n_requested": top_n,
        "top_resumes": final_results,
        "jd_filename": jd_filename,
        "processed_at": datetime.utcnow().isoformat()
    }
