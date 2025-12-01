# Education AI Check - Current Implementation & Improvements

## 📊 Current Implementation Analysis

### How It Works Now

```
1. Candidate uploads education certificate (PDF/DOCX)
   ↓
2. System extracts text using PyPDF2 or python-docx
   ↓
3. Extracted text sent to LLaMA 3.2 model
   ↓
4. LLaMA analyzes certificate for:
   - Institution name validity
   - Degree/course information
   - Graduation year
   - Candidate name match
   - Suspicious patterns
   ↓
5. Returns JSON with validation result
```

### Current Code Flow

**File: `apis.py`**
```python
async def verify_education_ai(candidate: dict):
    # 1. Get certificate path from candidate
    educationCertPath = candidate.get("educationCertificatePath")
    
    # 2. Extract text based on file type
    if ext == "pdf":
        extractedText = extract_text_from_pdf(educationCertPath)
    elif ext == "docx":
        extractedText = extract_text_from_docx(educationCertPath)
    
    # 3. Validate using LLM
    validation = await llm_education_validator(extractedText, candidate)
    
    # 4. Return result
    if validation.get("status") == "VALID":
        return "COMPLETED", {...}
    else:
        return "FAILED", {...}
```

**File: `utils/ai_utils.py`**
```python
async def llm_education_validator(extractedText: str, candidate: dict):
    # 1. Build prompt with validation criteria
    prompt = f"""
    Analyze education certificate for: {candidateName}
    Check for:
    - Valid institution
    - Proper format
    - Consistent dates
    - Name match
    - Fake patterns
    """
    
    # 2. Call LLaMA 3.2
    res = client.chat(
        model="llama3.2",
        messages=[{"role": "user", "content": prompt}],
        format="json"
    )
    
    # 3. Parse and return JSON
    return json.loads(res["message"]["content"])
```

---

## 🔍 Current Strengths

✅ **Uses Local AI (Ollama/LLaMA)**
- No API costs
- Privacy-friendly (data stays local)
- Fast inference

✅ **Structured Output**
- Returns JSON format
- Consistent response structure
- Easy to parse

✅ **Multiple File Formats**
- Supports PDF
- Supports DOCX

✅ **Name Matching**
- Checks if certificate name matches candidate

---

## ⚠️ Current Limitations

### 1. **Poor OCR Quality**
```python
# Current: Basic text extraction
extractedText = extract_text_from_pdf(educationCertPath)
```

**Problems:**
- ❌ Doesn't handle scanned images
- ❌ No OCR for image-based PDFs
- ❌ Poor quality for handwritten text
- ❌ Loses formatting/structure

### 2. **Limited Validation Checks**
```python
# Current checks:
- Institution name
- Degree name
- Graduation year
- Name match
- Basic fake patterns
```

**Missing:**
- ❌ Institution verification against database
- ❌ Degree format validation
- ❌ Seal/signature detection
- ❌ Watermark verification
- ❌ Certificate number validation
- ❌ Date consistency checks

### 3. **No Image Analysis**
- ❌ Can't detect tampered images
- ❌ Can't verify logos/seals
- ❌ Can't check photo quality
- ❌ Can't detect copy-paste artifacts

### 4. **Single Model Dependency**
- ❌ Only uses LLaMA 3.2
- ❌ No fallback model
- ❌ No ensemble validation

### 5. **No Database Verification**
- ❌ Doesn't check against known universities
- ❌ Doesn't verify degree programs
- ❌ Doesn't validate certificate formats

---

## 🚀 Proposed Improvements

### Improvement 1: Enhanced OCR with Tesseract

**Add OCR for scanned documents:**

```python
# Install
pip install pytesseract pillow pdf2image

# Implementation
import pytesseract
from pdf2image import convert_from_path
from PIL import Image

def extract_text_with_ocr(file_path):
    """
    Extract text from scanned PDFs using OCR
    """
    if file_path.endswith('.pdf'):
        # Convert PDF to images
        images = convert_from_path(file_path)
        
        text = ""
        for i, image in enumerate(images):
            # Apply OCR to each page
            page_text = pytesseract.image_to_string(image)
            text += f"\n--- Page {i+1} ---\n{page_text}"
        
        return text
    else:
        # For image files
        image = Image.open(file_path)
        return pytesseract.image_to_string(image)
```

### Improvement 2: Multi-Stage Validation

**Stage 1: Text Extraction**
```python
async def extract_certificate_text(file_path):
    # Try basic extraction first
    basic_text = extract_text_from_pdf(file_path)
    
    # If text is too short, use OCR
    if len(basic_text.strip()) < 50:
        ocr_text = extract_text_with_ocr(file_path)
        return ocr_text
    
    return basic_text
```

**Stage 2: Structure Analysis**
```python
async def analyze_certificate_structure(text):
    """
    Extract structured data from certificate
    """
    prompt = f"""
    Extract structured information from this certificate:
    
    {text}
    
    Return JSON:
    {{
        "studentName": "",
        "fatherName": "",
        "institutionName": "",
        "degreeName": "",
        "specialization": "",
        "graduationYear": "",
        "rollNumber": "",
        "certificateNumber": "",
        "issueDate": "",
        "grade": ""
    }}
    """
    
    # Call LLM
    result = await call_llm(prompt)
    return result
```

**Stage 3: Validation**
```python
async def validate_certificate_data(extracted_data, candidate):
    """
    Validate extracted data against candidate info and databases
    """
    validations = []
    
    # 1. Name matching
    name_match = fuzzy_match(
        extracted_data['studentName'],
        f"{candidate['firstName']} {candidate['lastName']}"
    )
    validations.append({
        "check": "name_match",
        "passed": name_match > 0.8,
        "score": name_match
    })
    
    # 2. Institution verification
    institution_valid = await verify_institution(
        extracted_data['institutionName']
    )
    validations.append({
        "check": "institution_valid",
        "passed": institution_valid,
        "details": "Verified against UGC database"
    })
    
    # 3. Date consistency
    dates_valid = validate_dates(
        extracted_data['graduationYear'],
        extracted_data['issueDate']
    )
    validations.append({
        "check": "dates_consistent",
        "passed": dates_valid
    })
    
    return validations
```

**Stage 4: Fraud Detection**
```python
async def detect_fraud_patterns(text, image_path):
    """
    Detect common fraud patterns
    """
    fraud_checks = []
    
    # 1. Text-based fraud detection
    prompt = f"""
    Analyze this certificate for fraud indicators:
    
    {text}
    
    Check for:
    - Generic/template language
    - Spelling errors in official text
    - Inconsistent formatting
    - Suspicious patterns
    - Known fake institution names
    
    Return JSON with fraud score (0-100) and reasons.
    """
    
    text_fraud = await call_llm(prompt)
    fraud_checks.append(text_fraud)
    
    # 2. Image-based fraud detection (if available)
    if image_path:
        image_fraud = await analyze_certificate_image(image_path)
        fraud_checks.append(image_fraud)
    
    return fraud_checks
```

### Improvement 3: Institution Database

**Create university database:**

```python
# universities_db.py
VERIFIED_UNIVERSITIES = {
    "india": [
        {
            "name": "Indian Institute of Technology",
            "aliases": ["IIT", "IIT Delhi", "IIT Bombay", "IIT Madras"],
            "type": "Central University",
            "ugc_approved": True
        },
        {
            "name": "Jawaharlal Nehru Technological University",
            "aliases": ["JNTU", "JNTUH", "JNTUK", "JNTUA"],
            "type": "State University",
            "ugc_approved": True
        },
        # Add more universities
    ]
}

async def verify_institution(institution_name):
    """
    Verify if institution is legitimate
    """
    institution_lower = institution_name.lower()
    
    for uni in VERIFIED_UNIVERSITIES["india"]:
        # Check main name
        if uni["name"].lower() in institution_lower:
            return True
        
        # Check aliases
        for alias in uni["aliases"]:
            if alias.lower() in institution_lower:
                return True
    
    # If not found, use AI to check
    prompt = f"""
    Is "{institution_name}" a legitimate educational institution in India?
    Check if it's UGC approved or recognized.
    Return JSON: {{"legitimate": true/false, "reason": "..."}}
    """
    
    result = await call_llm(prompt)
    return result.get("legitimate", False)
```

### Improvement 4: Enhanced Prompt Engineering

**Better prompt with examples:**

```python
async def llm_education_validator_enhanced(extractedText: str, candidate: dict):
    """
    Enhanced education certificate validator with better prompts
    """
    from ollama import Client
    client = Client()

    candidateName = f"{candidate.get('firstName', '')} {candidate.get('lastName', '')}".strip()
    
    prompt = f"""
    You are an expert education certificate validator with 20 years of experience.
    
    TASK: Analyze this education certificate for authenticity and validity.
    
    CANDIDATE INFORMATION:
    - Name: {candidateName}
    - Expected Degree: {candidate.get('expectedDegree', 'Any')}
    - Expected Year: {candidate.get('expectedGraduationYear', 'Any')}
    
    CERTIFICATE TEXT:
    {extractedText}
    
    VALIDATION CRITERIA:
    
    1. INSTITUTION VERIFICATION:
       - Is the institution name clearly mentioned?
       - Is it a recognized/accredited institution?
       - Are there spelling errors in the institution name?
    
    2. STUDENT INFORMATION:
       - Does the student name match "{candidateName}"? (allow minor variations)
       - Is father's/mother's name mentioned?
       - Is roll number/registration number present?
    
    3. DEGREE INFORMATION:
       - Is the degree name clearly stated?
       - Is the specialization/branch mentioned?
       - Is the degree level appropriate (Bachelor's, Master's, etc.)?
    
    4. DATES AND TIMELINE:
       - Is graduation year mentioned?
       - Is certificate issue date present?
       - Are dates logically consistent?
       - Is the duration appropriate for the degree?
    
    5. OFFICIAL ELEMENTS:
       - Are there mentions of seals/stamps?
       - Are signatures mentioned?
       - Is there a certificate number/registration number?
       - Is the format professional?
    
    6. FRAUD INDICATORS:
       - Generic/template language
       - Spelling/grammar errors in official text
       - Inconsistent formatting
       - Missing critical information
       - Suspicious patterns
    
    EXAMPLES OF VALID CERTIFICATES:
    - Clear institution name (e.g., "Jawaharlal Nehru Technological University")
    - Student name with father's name
    - Specific degree (e.g., "Bachelor of Technology in Computer Science")
    - Graduation year and issue date
    - Certificate number
    - Mentions of seal and signatures
    
    EXAMPLES OF INVALID/SUSPICIOUS CERTIFICATES:
    - Generic text like "This is to certify that..."
    - Misspelled institution names
    - Missing dates or student information
    - No certificate number
    - Inconsistent information
    
    OUTPUT FORMAT (JSON only):
    {{
        "status": "VALID" or "INVALID" or "SUSPICIOUS",
        "confidence": 0-100,
        "institutionName": "extracted institution name",
        "institutionRecognized": true/false,
        "degreeName": "extracted degree/course name",
        "specialization": "extracted specialization",
        "graduationYear": "extracted year",
        "certificateNumber": "extracted cert number or null",
        "studentName": "extracted student name",
        "candidateNameMatch": true/false,
        "nameMatchScore": 0-100,
        "fatherName": "extracted father name or null",
        "rollNumber": "extracted roll number or null",
        "issueDate": "extracted issue date or null",
        "datesConsistent": true/false,
        "officialElements": {{
            "hasSeal": true/false,
            "hasSignature": true/false,
            "hasCertificateNumber": true/false
        }},
        "fraudIndicators": [
            "list of suspicious patterns found"
        ],
        "issues": [
            "list of validation issues"
        ],
        "strengths": [
            "list of positive indicators"
        ],
        "explanation": "detailed analysis in 2-3 sentences",
        "recommendation": "APPROVE" or "REJECT" or "MANUAL_REVIEW"
    }}
    """

    try:
        res = client.chat(
            model="llama3.2",
            messages=[{"role": "user", "content": prompt}],
            format="json",
            options={
                "temperature": 0.1,  # Lower temperature for more consistent output
                "top_p": 0.9
            }
        )

        raw = res["message"]["content"]
        import json
        result = json.loads(raw)
        
        # Post-process: Add additional validations
        result = await post_process_validation(result, candidate)
        
        return result

    except Exception as e:
        return {
            "status": "INVALID",
            "confidence": 0,
            "institutionName": "",
            "degreeName": "",
            "graduationYear": "",
            "candidateNameMatch": False,
            "issues": [f"Model error: {str(e)}"],
            "explanation": "Could not analyze education certificate",
            "recommendation": "MANUAL_REVIEW"
        }
```

### Improvement 5: Post-Processing Validation

```python
async def post_process_validation(llm_result, candidate):
    """
    Add additional validations after LLM analysis
    """
    # 1. Fuzzy name matching
    if llm_result.get('studentName'):
        from fuzzywuzzy import fuzz
        candidate_name = f"{candidate.get('firstName', '')} {candidate.get('lastName', '')}".strip()
        extracted_name = llm_result['studentName']
        
        match_score = fuzz.ratio(
            candidate_name.lower(),
            extracted_name.lower()
        )
        
        llm_result['nameMatchScore'] = match_score
        llm_result['candidateNameMatch'] = match_score > 80
    
    # 2. Institution verification
    if llm_result.get('institutionName'):
        is_recognized = await verify_institution(llm_result['institutionName'])
        llm_result['institutionRecognized'] = is_recognized
        
        if not is_recognized:
            llm_result['issues'].append("Institution not found in verified database")
            llm_result['confidence'] = max(0, llm_result.get('confidence', 50) - 20)
    
    # 3. Date validation
    if llm_result.get('graduationYear'):
        current_year = datetime.now().year
        grad_year = int(llm_result['graduationYear'])
        
        if grad_year > current_year:
            llm_result['issues'].append("Graduation year is in the future")
            llm_result['status'] = "INVALID"
        
        if grad_year < current_year - 50:
            llm_result['issues'].append("Graduation year is too old")
            llm_result['recommendation'] = "MANUAL_REVIEW"
    
    # 4. Final recommendation
    if llm_result['status'] == "VALID" and llm_result.get('confidence', 0) > 80:
        llm_result['recommendation'] = "APPROVE"
    elif llm_result['status'] == "INVALID" or llm_result.get('confidence', 0) < 40:
        llm_result['recommendation'] = "REJECT"
    else:
        llm_result['recommendation'] = "MANUAL_REVIEW"
    
    return llm_result
```

---

## 📊 Comparison: Current vs Improved

| Feature | Current | Improved |
|---------|---------|----------|
| **OCR Support** | ❌ No | ✅ Yes (Tesseract) |
| **Image Analysis** | ❌ No | ✅ Yes |
| **Institution DB** | ❌ No | ✅ Yes (UGC verified) |
| **Fraud Detection** | ⚠️ Basic | ✅ Advanced |
| **Name Matching** | ⚠️ Exact | ✅ Fuzzy (80%+ match) |
| **Confidence Score** | ❌ No | ✅ Yes (0-100) |
| **Structured Output** | ⚠️ Basic | ✅ Comprehensive |
| **Post-Processing** | ❌ No | ✅ Yes |
| **Recommendation** | ❌ No | ✅ APPROVE/REJECT/REVIEW |

---

## 🎯 Implementation Priority

### Phase 1: Quick Wins (1-2 days)
1. ✅ Enhanced prompt engineering
2. ✅ Fuzzy name matching
3. ✅ Confidence scoring
4. ✅ Better error handling

### Phase 2: Core Improvements (3-5 days)
1. ✅ OCR integration (Tesseract)
2. ✅ Institution database
3. ✅ Post-processing validation
4. ✅ Date consistency checks

### Phase 3: Advanced Features (1-2 weeks)
1. ✅ Image-based fraud detection
2. ✅ Multi-model ensemble
3. ✅ Certificate template matching
4. ✅ Watermark detection

---

## 📝 Next Steps

1. **Review current implementation** ✅ (Done)
2. **Choose improvements to implement**
3. **Update `utils/ai_utils.py`**
4. **Add OCR dependencies**
5. **Create institution database**
6. **Test with real certificates**
7. **Deploy and monitor**

---

Would you like me to implement any of these improvements? I can start with Phase 1 (quick wins) or jump to Phase 2 (OCR + database) based on your priority! 🚀
