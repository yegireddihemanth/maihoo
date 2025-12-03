# AI Utilities - CV Authenticity Validation with OpenAI
import PyPDF2
import docx
import uuid
from datetime import datetime
import re
import json
import os
from typing import Dict, List, Optional

# Load environment variables
from dotenv import load_dotenv
load_dotenv()

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
# AI CV AUTHENTICITY VALIDATION (NO JD REQUIRED)
# ------------------------------------------------

async def validate_cv_authenticity(cv_text: str, has_uan: bool = False, candidate_type: str = "UNKNOWN", uan_note: str = "") -> Dict:
    """
    Validate CV authenticity - check for abnormalities, education overlaps, inconsistencies
    NO JD comparison - pure authenticity check
    
    Parameters:
    - cv_text: Extracted text from CV
    - has_uan: Boolean - whether candidate has verified UAN (formal employment)
    - candidate_type: "FRESHER", "EXPERIENCED_WITH_UAN", "EXPERIENCED_NO_UAN", "UNKNOWN"
    - uan_note: Note about UAN verification status
    
    Returns:
    - Positive findings (strengths, valid points)
    - Negative findings (red flags, inconsistencies, overlaps)
    - Authenticity score (0-100)
    """
    if not openai_client:
        raise Exception("OpenAI client not configured")
    
    try:
        # Build context with UAN verification status
        context_info = f"Candidate Type: {candidate_type}\n"
        context_info += f"UAN Verification: {uan_note}\n\n"
        
        if has_uan:
            context_info += "✅ IMPORTANT: Candidate has verified UAN number (Universal Account Number from EPFO).\n"
            context_info += "This means they have formal employment history with provident fund contributions.\n"
            context_info += "This significantly increases credibility and authenticity of employment claims.\n\n"
        else:
            context_info += "⚠️ NOTE: Candidate has NO UAN number.\n"
            context_info += "This could mean: fresher, freelancer, worked in unorganized sector, or foreign employment.\n"
            context_info += "Employment claims cannot be verified through official EPFO records.\n\n"
        
        # Build the full prompt
        system_prompt = """You are an expert Background Verification analyst specializing in CV authenticity checks.
Your job is to identify:
1. Education overlaps (studying while working full-time)
2. Employment gaps or inconsistencies
3. Timeline abnormalities
4. Suspicious patterns or red flags
5. Exaggerated claims or unrealistic achievements
6. Formatting or content inconsistencies

Also identify positive aspects:
1. Clear and consistent timeline
2. Realistic progression
3. Verifiable information
4. Professional presentation"""

        user_prompt = f"""{context_info}

CANDIDATE CV/RESUME:
{cv_text}

Analyze this CV for AUTHENTICITY ONLY (not job matching). Check for:
1. Education-Employment overlaps (full-time study during full-time work)
2. Timeline gaps or inconsistencies
3. Unrealistic claims or exaggerations
4. Red flags or suspicious patterns
5. **IMPORTANT**: Consider UAN verification status in your assessment:
   - If UAN verified: Higher credibility, employment claims are backed by official records
   - If NO UAN: Lower credibility, employment claims cannot be verified officially

Provide detailed positive and negative findings with an authenticity score.
**Adjust the score based on UAN status** - candidates with UAN should score higher (more credible)."""

        # Print the prompts for debugging
        print("\n" + "="*80)
        print("🤖 SENDING TO OPENAI GPT-4o-mini")
        print("="*80)
        print("\n📋 SYSTEM PROMPT:")
        print("-"*80)
        print(system_prompt)
        print("\n📋 USER PROMPT:")
        print("-"*80)
        print(user_prompt)
        print("\n" + "="*80)
        
        response = openai_client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {
                    "role": "system",
                    "content": system_prompt
                },
                {
                    "role": "user",
                    "content": user_prompt
                }
            ],
            functions=[{
                "name": "validate_cv_authenticity",
                "description": "Validate CV authenticity and identify red flags",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "authenticity_score": {
                            "type": "number",
                            "minimum": 0,
                            "maximum": 100,
                            "description": "Overall authenticity score (0-100)"
                        },
                        "candidate_profile": {
                            "type": "object",
                            "properties": {
                                "total_experience_years": {"type": "number"},
                                "education_level": {"type": "string"},
                                "career_progression": {"type": "string", "enum": ["CONSISTENT", "INCONSISTENT", "UNCLEAR"]},
                                "timeline_clarity": {"type": "string", "enum": ["CLEAR", "VAGUE", "MISSING"]}
                            }
                        },
                        "positive_findings": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "Strengths and valid points found in CV"
                        },
                        "negative_findings": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "Red flags, inconsistencies, and concerns"
                        },
                        "education_analysis": {
                            "type": "object",
                            "properties": {
                                "education_entries": {"type": "array", "items": {"type": "string"}},
                                "overlaps_detected": {"type": "boolean"},
                                "overlap_details": {"type": "array", "items": {"type": "string"}},
                                "education_score": {"type": "number", "minimum": 0, "maximum": 100}
                            }
                        },
                        "employment_analysis": {
                            "type": "object",
                            "properties": {
                                "employment_entries": {"type": "array", "items": {"type": "string"}},
                                "gaps_detected": {"type": "boolean"},
                                "gap_details": {"type": "array", "items": {"type": "string"}},
                                "uan_verification_status": {"type": "string", "enum": ["MATCHED", "MISMATCHED", "NOT_AVAILABLE"]},
                                "uan_discrepancies": {"type": "array", "items": {"type": "string"}},
                                "employment_score": {"type": "number", "minimum": 0, "maximum": 100}
                            }
                        },
                        "timeline_analysis": {
                            "type": "object",
                            "properties": {
                                "timeline_consistent": {"type": "boolean"},
                                "timeline_issues": {"type": "array", "items": {"type": "string"}},
                                "timeline_score": {"type": "number", "minimum": 0, "maximum": 100}
                            }
                        },
                        "red_flags": {
                            "type": "array",
                            "items": {
                                "type": "object",
                                "properties": {
                                    "severity": {"type": "string", "enum": ["HIGH", "MEDIUM", "LOW"]},
                                    "category": {"type": "string"},
                                    "description": {"type": "string"}
                                }
                            }
                        },
                        "recommendation": {
                            "type": "string",
                            "enum": ["APPROVE", "REVIEW_REQUIRED", "REJECT"],
                            "description": "Final recommendation based on authenticity"
                        },
                        "summary": {"type": "string", "description": "Brief summary of findings"}
                    },
                    "required": ["authenticity_score", "positive_findings", "negative_findings", "recommendation"]
                }
            }],
            function_call={"name": "validate_cv_authenticity"},
            temperature=0.1
        )
        
        function_call = response.choices[0].message.function_call
        if function_call:
            result = json.loads(function_call.arguments)
            
            # Print the response for debugging
            print("\n" + "="*80)
            print("✅ RECEIVED FROM OPENAI")
            print("="*80)
            print(json.dumps(result, indent=2))
            print("="*80 + "\n")
            
            return result
        else:
            raise Exception("No authenticity analysis generated")
            
    except Exception as e:
        print(f"❌ CV authenticity validation error: {e}")
        raise Exception(f"Failed to validate CV authenticity: {str(e)}")

# ----
# --------------------------------------------
# OCR TEXT EXTRACTION (for education documents)
# ------------------------------------------------

def extract_text_with_ocr(file_path: str) -> str:
    """
    Extract text from image or PDF using OCR (Tesseract)
    Works with: JPG, PNG, PDF
    
    Args:
        file_path: Path to image or PDF file
    
    Returns:
        Extracted text
    """
    try:
        import pytesseract
        from PIL import Image
        
        ext = file_path.split(".")[-1].lower()
        
        if ext == "pdf":
            # Try PDF text extraction first (faster, no OCR needed)
            try:
                print(f"📄 Attempting direct PDF text extraction...")
                with open(file_path, 'rb') as f:
                    text = extract_text_from_pdf(f)
                    if text and len(text.strip()) > 50:  # If we got meaningful text
                        print(f"✅ Extracted text directly from PDF (no OCR needed)")
                        return text
            except Exception as pdf_err:
                print(f"⚠️ Direct PDF extraction failed: {pdf_err}")
            
            # Fallback to OCR if direct extraction failed or returned little text
            try:
                from pdf2image import convert_from_path
                print(f"📄 Converting PDF to images for OCR...")
                images = convert_from_path(file_path)
                text = ""
                for i, image in enumerate(images):
                    print(f"🔍 OCR processing page {i+1}/{len(images)}")
                    page_text = pytesseract.image_to_string(image)
                    text += page_text + "\n\n"
                return text.strip()
            except ImportError:
                raise Exception("pdf2image not installed. Install with: pip install pdf2image")
            except Exception as ocr_err:
                if "poppler" in str(ocr_err).lower():
                    raise Exception(
                        "Poppler not installed. Install with: brew install poppler (macOS) or apt-get install poppler-utils (Linux). "
                        "Alternatively, upload a text-based PDF or image file instead."
                    )
                raise Exception(f"PDF OCR failed: {str(ocr_err)}")
        
        elif ext in ["jpg", "jpeg", "png", "tiff", "bmp"]:
            # Direct OCR on image
            print(f"🔍 OCR processing image...")
            image = Image.open(file_path)
            text = pytesseract.image_to_string(image)
            return text.strip()
        
        else:
            raise Exception(f"Unsupported file type for OCR: {ext}. Supported: PDF, JPG, PNG, TIFF, BMP")
            
    except Exception as e:
        print(f"❌ OCR extraction error: {e}")
        raise Exception(f"Failed to extract text with OCR: {str(e)}")


# ------------------------------------------------
# AI EDUCATION VALIDATION
# ------------------------------------------------

async def validate_education_document(document_text: str) -> Dict:
    """
    Validate education document using OpenAI GPT-4o-mini
    Extracts structured education information
    
    Args:
        document_text: Extracted text from education certificate/marksheet
    
    Returns:
        Structured education data with validation
    """
    if not openai_client:
        raise Exception("OpenAI client not configured")
    
    try:
        print(f"🎓 Starting AI education document validation...")
        
        response = openai_client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {
                    "role": "system",
                    "content": """You are an expert education document validator.
Extract structured information from education certificates, marksheets, and degree documents.

Validate:
1. Degree/qualification type
2. Field of study/specialization
3. Institution name
4. Duration (start and end dates)
5. Grades/marks/CGPA
6. Authenticity indicators
7. Red flags (tampering, inconsistencies)"""
                },
                {
                    "role": "user",
                    "content": f"""Analyze this education document and extract structured information:

DOCUMENT TEXT:
{document_text}

Extract all education details and validate authenticity."""
                }
            ],
            functions=[{
                "name": "validate_education",
                "description": "Extract and validate education document information",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "degree_type": {
                            "type": "string",
                            "description": "Type of degree (e.g., Bachelor of Technology, Master of Science, High School)"
                        },
                        "field_of_study": {
                            "type": "string",
                            "description": "Major/specialization (e.g., Computer Science, Mechanical Engineering)"
                        },
                        "institution_name": {
                            "type": "string",
                            "description": "Name of university/college/school"
                        },
                        "start_date": {
                            "type": "string",
                            "description": "Start year or date (e.g., 2014, Aug 2014)"
                        },
                        "end_date": {
                            "type": "string",
                            "description": "End year or date (e.g., 2018, May 2018)"
                        },
                        "duration_years": {
                            "type": "number",
                            "description": "Duration in years"
                        },
                        "grade": {
                            "type": "string",
                            "description": "Grade/marks/CGPA (e.g., First Class, 8.5 CGPA, 85%)"
                        },
                        "board_university": {
                            "type": "string",
                            "description": "Affiliated board/university"
                        },
                        "document_type": {
                            "type": "string",
                            "enum": ["DEGREE_CERTIFICATE", "MARKSHEET", "PROVISIONAL_CERTIFICATE", "TRANSCRIPT", "OTHER"],
                            "description": "Type of document"
                        },
                        "authenticity_score": {
                            "type": "number",
                            "minimum": 0,
                            "maximum": 100,
                            "description": "Authenticity score (0-100)"
                        },
                        "verification_status": {
                            "type": "string",
                            "enum": ["VERIFIED", "SUSPICIOUS", "INCOMPLETE", "UNCLEAR"],
                            "description": "Overall verification status"
                        },
                        "positive_findings": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "Valid/authentic elements found"
                        },
                        "red_flags": {
                            "type": "array",
                            "items": {
                                "type": "object",
                                "properties": {
                                    "severity": {"type": "string", "enum": ["HIGH", "MEDIUM", "LOW"]},
                                    "issue": {"type": "string"},
                                    "description": {"type": "string"}
                                }
                            },
                            "description": "Issues or suspicious elements"
                        },
                        "extracted_text_quality": {
                            "type": "string",
                            "enum": ["EXCELLENT", "GOOD", "FAIR", "POOR"],
                            "description": "Quality of OCR text extraction"
                        },
                        "recommendation": {
                            "type": "string",
                            "enum": ["APPROVE", "REVIEW_REQUIRED", "REJECT"],
                            "description": "Final recommendation"
                        },
                        "summary": {
                            "type": "string",
                            "description": "Brief summary of findings"
                        }
                    },
                    "required": ["degree_type", "institution_name", "authenticity_score", "verification_status", "recommendation"]
                }
            }],
            function_call={"name": "validate_education"},
            temperature=0.1
        )
        
        function_call = response.choices[0].message.function_call
        if function_call:
            result = json.loads(function_call.arguments)
            
            print(f"✅ Education validation completed")
            print(f"📊 Score: {result.get('authenticity_score', 0)}/100")
            print(f"🎓 Degree: {result.get('degree_type', 'N/A')}")
            print(f"🏫 Institution: {result.get('institution_name', 'N/A')}")
            
            return result
        else:
            raise Exception("No education validation generated")
            
    except Exception as e:
        print(f"❌ Education validation error: {e}")
        raise Exception(f"Failed to validate education document: {str(e)}")
