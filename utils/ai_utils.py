# AI Utilities - CV Validation with OpenAI
import PyPDF2
import docx
import uuid
from datetime import datetime
from pymongo import MongoClient
import re
import json
import os
from typing import Dict, List, Optional

# OpenAI Integration
try:
    import openai
    OPENAI_AVAILABLE = True
except ImportError:
    OPENAI_AVAILABLE = False
    print("⚠️ OpenAI not installed. Install with: pip install openai")

# Initialize OpenAI client
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
if OPENAI_API_KEY and OPENAI_AVAILABLE:
    openai_client = openai.OpenAI(api_key=OPENAI_API_KEY)
else:
    openai_client = None
    print("⚠️ OpenAI API key not configured")

# ------------------------------------------------
# TEXT EXTRACTION UTILITIES
# ------------------------------------------------

def extract_text_from_pdf(file_obj):
    """Extract text from PDF file"""
    try:
        reader = PyPDF2.PdfReader(file_obj)
        text = ""
        for page in reader.pages:
            text += page.extract_text() + "\n"
        return text.strip()
    except Exception as e:
        print(f"❌ PDF extraction error: {e}")
        return ""

def extract_text_from_docx(file_obj):
    """Extract text from DOCX file"""
    try:
        doc = docx.Document(file_obj)
        text = ""
        for paragraph in doc.paragraphs:
            text += paragraph.text + "\n"
        return text.strip()
    except Exception as e:
        print(f"❌ DOCX extraction error: {e}")
        return ""

def extract_text_from_txt(file_obj):
    """Extract text from TXT file"""
    try:
        content = file_obj.read()
        if isinstance(content, bytes):
            content = content.decode('utf-8')
        return content.strip()
    except Exception as e:
        print(f"❌ TXT extraction error: {e}")
        return ""

# ------------------------------------------------
# AI CV VALIDATION WITH OPENAI
# ------------------------------------------------

async def extract_structured_cv_data(cv_text: str) -> Dict:
    """Extract structured data from CV using OpenAI GPT-4o mini"""
    if not openai_client:
        raise Exception("OpenAI client not configured")
    
    try:
        response = openai_client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {
                    "role": "system",
                    "content": "You are an expert HR analyst. Extract structured information from CVs/resumes in a comprehensive format."
                },
                {
                    "role": "user",
                    "content": f"""Extract comprehensive information from this CV/Resume:

{cv_text}

Focus on:
1. Personal Information (name, contact details)
2. Technical Skills (programming languages, frameworks, tools, databases)
3. Professional Experience (companies, roles, duration, responsibilities)
4. Education (degrees, institutions, years)
5. Projects and achievements
6. Certifications
7. Years of total experience"""
                }
            ],
            functions=[{
                "name": "extract_cv_data",
                "description": "Extract structured data from CV/Resume",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "personal_info": {
                            "type": "object",
                            "properties": {
                                "name": {"type": "string"},
                                "email": {"type": "string"},
                                "phone": {"type": "string"},
                                "location": {"type": "string"}
                            }
                        },
                        "technical_skills": {
                            "type": "object",
                            "properties": {
                                "programming_languages": {"type": "array", "items": {"type": "string"}},
                                "frameworks": {"type": "array", "items": {"type": "string"}},
                                "databases": {"type": "array", "items": {"type": "string"}},
                                "tools": {"type": "array", "items": {"type": "string"}},
                                "cloud_platforms": {"type": "array", "items": {"type": "string"}},
                                "other_skills": {"type": "array", "items": {"type": "string"}}
                            }
                        },
                        "experience": {
                            "type": "object",
                            "properties": {
                                "total_years": {"type": "number"},
                                "positions": {
                                    "type": "array",
                                    "items": {
                                        "type": "object",
                                        "properties": {
                                            "company": {"type": "string"},
                                            "role": {"type": "string"},
                                            "duration": {"type": "string"},
                                            "responsibilities": {"type": "array", "items": {"type": "string"}},
                                            "technologies": {"type": "array", "items": {"type": "string"}}
                                        }
                                    }
                                }
                            }
                        },
                        "education": {
                            "type": "array",
                            "items": {
                                "type": "object",
                                "properties": {
                                    "degree": {"type": "string"},
                                    "institution": {"type": "string"},
                                    "year": {"type": "string"},
                                    "field": {"type": "string"}
                                }
                            }
                        },
                        "projects": {
                            "type": "array",
                            "items": {
                                "type": "object",
                                "properties": {
                                    "name": {"type": "string"},
                                    "description": {"type": "string"},
                                    "technologies": {"type": "array", "items": {"type": "string"}}
                                }
                            }
                        },
                        "certifications": {"type": "array", "items": {"type": "string"}}
                    },
                    "required": ["technical_skills", "experience", "education"]
                }
            }],
            function_call={"name": "extract_cv_data"},
            temperature=0.1
        )
        
        function_call = response.choices[0].message.function_call
        if function_call:
            return json.loads(function_call.arguments)
        else:
            raise Exception("No structured data extracted")
            
    except Exception as e:
        print(f"❌ CV extraction error: {e}")
        raise Exception(f"Failed to extract CV data: {str(e)}")

async def extract_structured_jd_data(jd_text: str) -> Dict:
    """Extract structured data from Job Description using OpenAI GPT-4o mini"""
    if not openai_client:
        raise Exception("OpenAI client not configured")
    
    try:
        response = openai_client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {
                    "role": "system",
                    "content": "You are an expert HR analyst. Extract structured requirements from job descriptions."
                },
                {
                    "role": "user",
                    "content": f"""Extract comprehensive requirements from this Job Description:

{jd_text}

Focus on:
1. Required technical skills (must-have vs nice-to-have)
2. Experience requirements (years, specific technologies)
3. Educational qualifications
4. Role responsibilities
5. Required tools and technologies"""
                }
            ],
            functions=[{
                "name": "extract_jd_requirements",
                "description": "Extract structured requirements from Job Description",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "job_title": {"type": "string"},
                        "required_skills": {
                            "type": "object",
                            "properties": {
                                "programming_languages": {"type": "array", "items": {"type": "string"}},
                                "frameworks": {"type": "array", "items": {"type": "string"}},
                                "databases": {"type": "array", "items": {"type": "string"}},
                                "tools": {"type": "array", "items": {"type": "string"}},
                                "cloud_platforms": {"type": "array", "items": {"type": "string"}},
                                "other_skills": {"type": "array", "items": {"type": "string"}}
                            }
                        },
                        "nice_to_have_skills": {
                            "type": "object",
                            "properties": {
                                "programming_languages": {"type": "array", "items": {"type": "string"}},
                                "frameworks": {"type": "array", "items": {"type": "string"}},
                                "databases": {"type": "array", "items": {"type": "string"}},
                                "tools": {"type": "array", "items": {"type": "string"}},
                                "cloud_platforms": {"type": "array", "items": {"type": "string"}},
                                "other_skills": {"type": "array", "items": {"type": "string"}}
                            }
                        },
                        "experience_requirements": {
                            "type": "object",
                            "properties": {
                                "minimum_years": {"type": "number"},
                                "preferred_years": {"type": "number"},
                                "specific_experience": {"type": "array", "items": {"type": "string"}}
                            }
                        },
                        "education_requirements": {
                            "type": "array",
                            "items": {"type": "string"}
                        },
                        "responsibilities": {"type": "array", "items": {"type": "string"}}
                    },
                    "required": ["required_skills", "experience_requirements"]
                }
            }],
            function_call={"name": "extract_jd_requirements"},
            temperature=0.1
        )
        
        function_call = response.choices[0].message.function_call
        if function_call:
            return json.loads(function_call.arguments)
        else:
            raise Exception("No structured data extracted")
            
    except Exception as e:
        print(f"❌ JD extraction error: {e}")
        raise Exception(f"Failed to extract JD data: {str(e)}")

async def analyze_cv_vs_jd(cv_data: Dict, jd_data: Dict) -> Dict:
    """Analyze CV against JD requirements and provide scoring"""
    if not openai_client:
        raise Exception("OpenAI client not configured")
    
    try:
        response = openai_client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {
                    "role": "system",
                    "content": "You are an expert HR analyst. Analyze how well a candidate's CV matches job requirements and provide detailed scoring and recommendations."
                },
                {
                    "role": "user",
                    "content": f"""Analyze this candidate's CV against the job requirements:

CANDIDATE CV DATA:
{json.dumps(cv_data, indent=2)}

JOB REQUIREMENTS:
{json.dumps(jd_data, indent=2)}

Provide comprehensive analysis with:
1. Overall match score (0-100)
2. Skills analysis (matching vs missing)
3. Experience analysis
4. Strengths and weaknesses
5. Recommendations"""
                }
            ],
            functions=[{
                "name": "analyze_candidate_match",
                "description": "Analyze candidate CV against job requirements",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "overall_score": {
                            "type": "number",
                            "minimum": 0,
                            "maximum": 100,
                            "description": "Overall match score (0-100)"
                        },
                        "skills_analysis": {
                            "type": "object",
                            "properties": {
                                "matching_skills": {"type": "array", "items": {"type": "string"}},
                                "missing_critical_skills": {"type": "array", "items": {"type": "string"}},
                                "missing_nice_to_have": {"type": "array", "items": {"type": "string"}},
                                "additional_skills": {"type": "array", "items": {"type": "string"}},
                                "skills_score": {"type": "number", "minimum": 0, "maximum": 100}
                            }
                        },
                        "experience_analysis": {
                            "type": "object",
                            "properties": {
                                "meets_minimum_experience": {"type": "boolean"},
                                "total_experience_years": {"type": "number"},
                                "relevant_experience": {"type": "array", "items": {"type": "string"}},
                                "experience_score": {"type": "number", "minimum": 0, "maximum": 100}
                            }
                        },
                        "education_analysis": {
                            "type": "object",
                            "properties": {
                                "meets_requirements": {"type": "boolean"},
                                "education_details": {"type": "array", "items": {"type": "string"}},
                                "education_score": {"type": "number", "minimum": 0, "maximum": 100}
                            }
                        },
                        "strengths": {"type": "array", "items": {"type": "string"}},
                        "weaknesses": {"type": "array", "items": {"type": "string"}},
                        "recommendations": {"type": "array", "items": {"type": "string"}},
                        "hiring_recommendation": {
                            "type": "string",
                            "enum": ["STRONG_HIRE", "HIRE", "MAYBE", "NO_HIRE"]
                        }
                    },
                    "required": ["overall_score", "skills_analysis", "experience_analysis", "hiring_recommendation"]
                }
            }],
            function_call={"name": "analyze_candidate_match"},
            temperature=0.2
        )
        
        function_call = response.choices[0].message.function_call
        if function_call:
            return json.loads(function_call.arguments)
        else:
            raise Exception("No analysis generated")
            
    except Exception as e:
        print(f"❌ Analysis error: {e}")
        raise Exception(f"Failed to analyze CV vs JD: {str(e)}")

# ------------------------------------------------
# MAIN CV VALIDATION FUNCTION
# ------------------------------------------------

async def validate_cv_against_jd(cv_file, jd_file) -> Dict:
    """
    Main function to validate CV against JD
    Returns comprehensive analysis and scoring
    """
    try:
        # Extract text from files
        cv_text = ""
        jd_text = ""
        
        # Handle CV file
        if hasattr(cv_file, 'filename'):
            filename = cv_file.filename.lower()
            if filename.endswith('.pdf'):
                cv_text = extract_text_from_pdf(cv_file.file)
            elif filename.endswith('.docx'):
                cv_text = extract_text_from_docx(cv_file.file)
            elif filename.endswith('.txt'):
                cv_text = extract_text_from_txt(cv_file.file)
        else:
            cv_text = str(cv_file)  # Text input
        
        # Handle JD file
        if hasattr(jd_file, 'filename'):
            filename = jd_file.filename.lower()
            if filename.endswith('.pdf'):
                jd_text = extract_text_from_pdf(jd_file.file)
            elif filename.endswith('.docx'):
                jd_text = extract_text_from_docx(jd_file.file)
            elif filename.endswith('.txt'):
                jd_text = extract_text_from_txt(jd_file.file)
        else:
            jd_text = str(jd_file)  # Text input
        
        if not cv_text or len(cv_text.strip()) < 50:
            raise Exception("Could not extract meaningful text from CV")
        
        if not jd_text or len(jd_text.strip()) < 50:
            raise Exception("Could not extract meaningful text from JD")
        
        # Extract structured data
        print("🔍 Extracting structured CV data...")
        cv_data = await extract_structured_cv_data(cv_text)
        
        print("🔍 Extracting structured JD data...")
        jd_data = await extract_structured_jd_data(jd_text)
        
        # Analyze match
        print("🔍 Analyzing CV vs JD match...")
        analysis = await analyze_cv_vs_jd(cv_data, jd_data)
        
        # Compile final result
        result = {
            "validation_id": str(uuid.uuid4()),
            "timestamp": datetime.utcnow().isoformat(),
            "cv_data": cv_data,
            "jd_data": jd_data,
            "analysis": analysis,
            "status": "COMPLETED",
            "method": "OpenAI-GPT4o-mini"
        }
        
        return result
        
    except Exception as e:
        return {
            "validation_id": str(uuid.uuid4()),
            "timestamp": datetime.utcnow().isoformat(),
            "status": "FAILED",
            "error": str(e),
            "method": "OpenAI-GPT4o-mini"
        }