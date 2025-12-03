# Enhanced Resume Screening with Weighted Scoring
import os
import io
import numpy as np
from typing import List, Dict, Tuple, Optional
from datetime import datetime
import json
import re

# Import base utilities
from utils.resume_screening import (
    extract_text_from_file,
    get_embedding,
    cosine_similarity,
    openai_client
)


async def analyze_resume_with_requirements(
    resume_text: str,
    jd_text: str,
    similarity_score: float,
    must_have_requirements: Optional[List[str]] = None,
    nice_to_have: Optional[List[str]] = None
) -> Dict:
    """
    Enhanced resume analysis with explicit requirement checking
    
    Args:
        resume_text: Resume content
        jd_text: Job description content
        similarity_score: Embedding similarity score
        must_have_requirements: List of critical requirements
        nice_to_have: List of preferred but not critical requirements
    
    Returns:
        Enhanced analysis with requirement compliance
    """
    if not openai_client:
        raise Exception("OpenAI client not configured")
    
    # Build requirements section
    requirements_section = ""
    if must_have_requirements:
        requirements_section += "\nCRITICAL REQUIREMENTS (MUST HAVE):\n"
        for req in must_have_requirements:
            requirements_section += f"- {req}\n"
    
    if nice_to_have:
        requirements_section += "\nPREFERRED REQUIREMENTS (NICE TO HAVE):\n"
        for req in nice_to_have:
            requirements_section += f"- {req}\n"
    
    prompt = f"""You are an expert HR recruiter. Analyze this resume against the job description with STRICT requirement checking.

JOB DESCRIPTION:
{jd_text[:3000]}

{requirements_section}

RESUME:
{resume_text[:4000]}

EMBEDDING SIMILARITY SCORE: {similarity_score:.2%}

IMPORTANT: Check if candidate meets ALL critical requirements. If any critical requirement is missing, the match_score should be LOW (below 60) regardless of other factors.

Provide a JSON response with:
1. "meets_critical_requirements": true/false (ALL must-haves satisfied?)
2. "critical_requirements_status": {{
   "requirement": "met/not_met/unclear",
   ...
}}
3. "match_score": Overall match score 0-100 (penalize heavily if critical requirements not met)
4. "strengths": List of 3-5 key strengths
5. "weaknesses": List of 3-5 gaps or concerns
6. "skills_match": {{
   "matched": [list of matched skills],
   "missing_critical": [list of missing critical skills],
   "missing_nice_to_have": [list of missing nice-to-have skills]
}}
7. "experience_match": {{
   "years": number of years experience,
   "relevance": "high/medium/low",
   "assessment": "brief text"
}}
8. "education_match": Brief assessment
9. "red_flags": List of any concerns (job hopping, gaps, etc.)
10. "recommendation": "STRONG_FIT" | "GOOD_FIT" | "MODERATE_FIT" | "WEAK_FIT" | "REJECT"
11. "summary": 2-3 sentence overall assessment

Return ONLY valid JSON, no markdown."""

    try:
        response = openai_client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": "You are an expert HR recruiter providing structured resume analysis with strict requirement checking. Always respond with valid JSON only."},
                {"role": "user", "content": prompt}
            ],
            temperature=0.2,  # Lower temperature for more consistent evaluation
            max_tokens=1200
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
        
        # Add embedding score to analysis
        analysis["embedding_similarity"] = similarity_score
        
        return analysis
        
    except json.JSONDecodeError as e:
        print(f"⚠️ JSON decode error: {e}")
        # Return fallback analysis
        return {
            "meets_critical_requirements": False,
            "critical_requirements_status": {},
            "match_score": int(similarity_score * 100),
            "strengths": ["Resume content extracted successfully"],
            "weaknesses": ["Detailed analysis unavailable"],
            "skills_match": {"matched": [], "missing_critical": [], "missing_nice_to_have": []},
            "experience_match": {"years": 0, "relevance": "unclear", "assessment": "Unable to analyze"},
            "education_match": "Unable to analyze",
            "red_flags": ["AI analysis failed - manual review required"],
            "recommendation": "MODERATE_FIT" if similarity_score > 0.7 else "WEAK_FIT",
            "summary": f"Embedding similarity: {similarity_score:.2%}. Manual review required.",
            "embedding_similarity": similarity_score
        }
    except Exception as e:
        print(f"❌ AI analysis error: {e}")
        raise


def calculate_weighted_score(
    embedding_score: float,
    llm_match_score: int,
    meets_critical_requirements: bool,
    embedding_weight: float = 0.3,
    llm_weight: float = 0.7
) -> float:
    """
    Calculate weighted final score combining embedding and LLM scores
    
    Args:
        embedding_score: Similarity score from embeddings (0-1)
        llm_match_score: Match score from LLM (0-100)
        meets_critical_requirements: Whether critical requirements are met
        embedding_weight: Weight for embedding score (default 0.3)
        llm_weight: Weight for LLM score (default 0.7)
    
    Returns:
        Weighted score (0-100)
    """
    # If critical requirements not met, cap score at 50
    if not meets_critical_requirements:
        return min(50, (embedding_score * 100 * embedding_weight) + (llm_match_score * llm_weight))
    
    # Normal weighted calculation
    weighted_score = (embedding_score * 100 * embedding_weight) + (llm_match_score * llm_weight)
    return round(weighted_score, 2)


async def screen_resumes_enhanced(
    resume_files: List[Tuple[bytes, str]],
    jd_file: Tuple[bytes, str],
    top_n: int = 5,
    must_have_requirements: Optional[List[str]] = None,
    nice_to_have: Optional[List[str]] = None,
    min_embedding_score: float = 0.5,
    embedding_weight: float = 0.3,
    llm_weight: float = 0.7
) -> Dict:
    """
    Enhanced resume screening with requirement checking and weighted scoring
    
    Args:
        resume_files: List of tuples (file_content_bytes, filename)
        jd_file: Tuple of (jd_content_bytes, jd_filename)
        top_n: Number of top resumes to return
        must_have_requirements: List of critical requirements
        nice_to_have: List of preferred requirements
        min_embedding_score: Minimum embedding score to consider (default 0.5)
        embedding_weight: Weight for embedding score (default 0.3)
        llm_weight: Weight for LLM score (default 0.7)
    
    Returns:
        Dictionary with top resumes and enhanced analysis
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
            
            # Filter out low-scoring resumes early
            if similarity < min_embedding_score:
                print(f"⚠️ Skipping {resume_filename}: Below minimum threshold ({similarity:.4f} < {min_embedding_score})")
                continue
            
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
        raise ValueError("No resumes met the minimum criteria")
    
    # Sort by similarity score (descending)
    resume_results.sort(key=lambda x: x["similarity_score"], reverse=True)
    
    # Get top N*2 for LLM analysis (analyze more, then re-rank)
    candidates_for_analysis = min(top_n * 2, len(resume_results))
    top_candidates = resume_results[:candidates_for_analysis]
    
    print(f"\n🎯 Analyzing top {len(top_candidates)} resumes with enhanced AI...")
    
    # Analyze candidates with enhanced LLM
    analyzed_results = []
    for idx, resume in enumerate(top_candidates, 1):
        print(f"\n🤖 Enhanced AI Analysis {idx}/{len(top_candidates)}: {resume['filename']}")
        
        try:
            analysis = await analyze_resume_with_requirements(
                resume["text"],
                jd_text,
                resume["similarity_score"],
                must_have_requirements,
                nice_to_have
            )
            
            # Calculate weighted final score
            final_score = calculate_weighted_score(
                resume["similarity_score"],
                analysis.get("match_score", 0),
                analysis.get("meets_critical_requirements", False),
                embedding_weight,
                llm_weight
            )
            
            analyzed_results.append({
                "filename": resume["filename"],
                "embedding_similarity": round(resume["similarity_score"], 4),
                "llm_match_score": analysis.get("match_score", 0),
                "final_weighted_score": final_score,
                "meets_critical_requirements": analysis.get("meets_critical_requirements", False),
                "critical_requirements_status": analysis.get("critical_requirements_status", {}),
                "recommendation": analysis.get("recommendation", "MODERATE_FIT"),
                "summary": analysis.get("summary", ""),
                "strengths": analysis.get("strengths", []),
                "weaknesses": analysis.get("weaknesses", []),
                "skills_match": analysis.get("skills_match", {}),
                "experience_match": analysis.get("experience_match", {}),
                "education_match": analysis.get("education_match", ""),
                "red_flags": analysis.get("red_flags", [])
            })
            
            print(f"✅ Analysis complete: {analysis.get('recommendation', 'N/A')} (Final Score: {final_score})")
            
        except Exception as e:
            print(f"⚠️ AI analysis failed for {resume['filename']}: {e}")
            continue
    
    # Re-rank by final weighted score
    analyzed_results.sort(key=lambda x: x["final_weighted_score"], reverse=True)
    
    # Return top N after re-ranking
    final_top_n = analyzed_results[:top_n]
    
    # Add ranks
    for idx, result in enumerate(final_top_n, 1):
        result["rank"] = idx
    
    return {
        "total_resumes_processed": len(resume_results),
        "total_resumes_uploaded": len(resume_files),
        "resumes_analyzed_with_llm": len(analyzed_results),
        "top_n_requested": top_n,
        "jd_filename": jd_filename,
        "must_have_requirements": must_have_requirements or [],
        "nice_to_have": nice_to_have or [],
        "scoring_weights": {
            "embedding_weight": embedding_weight,
            "llm_weight": llm_weight
        },
        "top_resumes": final_top_n,
        "processed_at": datetime.utcnow().isoformat()
    }
