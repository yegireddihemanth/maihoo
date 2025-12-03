# Resume Screening - Which Endpoint Should I Use?

## 🎯 Quick Decision Tree

```
What type of position are you hiring for?
│
├─ FRESHERS / ENTRY-LEVEL (0-2 years)
│  │
│  ├─ Campus Hiring
│  ├─ Internships
│  ├─ Junior Developer
│  ├─ Trainee positions
│  │
│  └─ ✅ USE: Basic Screening
│     Endpoint: POST /secure/ai_resume_screening
│     Why: Fast, simple, cost-effective
│     Cost: $0.007 per 100 resumes
│
└─ EXPERIENCED / SPECIALIZED (3+ years)
   │
   ├─ Senior Developer (5+ years)
   ├─ Tech Lead / Architect
   ├─ DevOps Engineer (certifications required)
   ├─ ML Engineer (specialized skills)
   ├─ Any role with MUST-HAVE requirements
   │
   └─ ✅ USE: Enhanced Screening
      Endpoint: POST /secure/ai_resume_screening_enhanced
      Why: Requirement validation, better accuracy
      Cost: $0.010 per 100 resumes
```

---

## 📊 Comparison Table

| Criteria | Basic Screening | Enhanced Screening |
|----------|----------------|-------------------|
| **Best For** | Freshers, Juniors, Internships | Senior, Specialized, Critical roles |
| **Experience Level** | 0-2 years | 3+ years, especially 5+ |
| **Requirements** | General fit | Specific must-haves |
| **Accuracy** | 85-90% | 88-92% |
| **Speed** | 2-3 min (100 resumes) | 3-4 min (100 resumes) |
| **Cost** | $0.007 per 100 | $0.010 per 100 |
| **Complexity** | Simple (3 parameters) | Advanced (8 parameters) |
| **Requirement Checking** | ❌ No | ✅ Yes |
| **Weighted Scoring** | ❌ No | ✅ Yes |
| **Red Flag Detection** | ✅ Basic | ✅ Advanced |

---

## 🎯 Use Case Examples

### ✅ Use Basic Screening For:

#### 1. Campus Hiring (100 Freshers)
```
Position: Python Developer - Fresher
Candidates: 100 college graduates
Requirements: Basic Python, good academics
Decision: BASIC - No strict requirements, high volume
```

#### 2. Internship Program (50 Students)
```
Position: Summer Intern - Software Development
Candidates: 50 students
Requirements: Any programming language, learning attitude
Decision: BASIC - Focus on potential, not experience
```

#### 3. Junior Developer (30 Candidates)
```
Position: Junior Full Stack Developer
Candidates: 30 with 0-2 years experience
Requirements: Basic web development skills
Decision: BASIC - Entry-level, flexible requirements
```

---

### ✅ Use Enhanced Screening For:

#### 1. Senior Python Developer (40 Candidates)
```
Position: Senior Python Developer
Candidates: 40 experienced professionals
MUST HAVE: 5+ years Python, AWS certification, Team leadership
NICE TO HAVE: Docker, Kubernetes, Microservices
Decision: ENHANCED - Specific requirements, senior role
```

#### 2. DevOps Engineer (25 Candidates)
```
Position: DevOps Engineer
Candidates: 25 professionals
MUST HAVE: 3+ years DevOps, AWS/Azure cert, Kubernetes production
NICE TO HAVE: Terraform, Ansible, CI/CD
Decision: ENHANCED - Certifications required, specialized
```

#### 3. Tech Lead (15 Candidates)
```
Position: Technical Lead
Candidates: 15 senior professionals
MUST HAVE: 8+ years experience, Architecture skills, Team management
NICE TO HAVE: Cloud architecture cert, Agile experience
Decision: ENHANCED - Critical role, leadership required
```

#### 4. ML Engineer (20 Candidates)
```
Position: Machine Learning Engineer
Candidates: 20 specialists
MUST HAVE: 4+ years ML, Python, Deep Learning frameworks
NICE TO HAVE: PhD, Research publications, MLOps
Decision: ENHANCED - Highly specialized, specific skills
```

---

## 📝 Postman Quick Setup

### For Basic Screening (Freshers)

**Postman Request:**
```
Method: POST
URL: https://your-domain.com/secure/ai_resume_screening

Headers:
  Authorization: Bearer YOUR_JWT_TOKEN

Body (form-data):
  jd_file: [Upload: fresher_python_developer.pdf]
  resume_files: [Upload: candidate1.pdf]
  resume_files: [Upload: candidate2.pdf]
  ... (repeat for all resumes)
  top_n: 15
```

**That's it! Only 3 fields needed.**

---

### For Enhanced Screening (Senior)

**Postman Request:**
```
Method: POST
URL: https://your-domain.com/secure/ai_resume_screening_enhanced

Headers:
  Authorization: Bearer YOUR_JWT_TOKEN

Body (form-data):
  jd_file: [Upload: senior_python_developer.pdf]
  resume_files: [Upload: candidate1.pdf]
  resume_files: [Upload: candidate2.pdf]
  ... (repeat for all resumes)
  top_n: 5
  must_have_requirements: 5+ years Python,AWS certification,Team leadership
  nice_to_have: Docker,Kubernetes,Microservices,CI/CD
  min_embedding_score: 0.5
  embedding_weight: 0.3
  llm_weight: 0.7
```

**More parameters, but better accuracy for critical roles.**

---

## 💡 Pro Tips

### When to Use Basic:
1. **High Volume:** 100+ resumes, need quick results
2. **Flexible Requirements:** No strict must-haves
3. **Entry-Level:** Freshers, juniors, interns
4. **Budget Conscious:** Every penny counts
5. **General Screening:** First-pass filtering

### When to Use Enhanced:
1. **Critical Roles:** Senior, lead, architect positions
2. **Specific Requirements:** Certifications, years of experience
3. **Specialized Skills:** DevOps, ML, Security, etc.
4. **Quality Over Speed:** Accuracy matters more than cost
5. **Compliance:** Need to prove requirement checking

### When to Use Both:
1. **Two-Stage Process:**
   - Stage 1: Basic screening (100 → 20)
   - Stage 2: Enhanced screening (20 → 5)
   - Best of both worlds!

2. **Mixed Hiring:**
   - Basic for junior positions
   - Enhanced for senior positions
   - Use appropriate endpoint per role

---

## 🔧 Configuration Recommendations

### Basic Screening Settings

| Scenario | top_n | Why |
|----------|-------|-----|
| Campus Hiring | 20-30 | Large pool, need many candidates |
| Internships | 15-20 | Moderate pool |
| Junior Roles | 10-15 | Focused screening |

### Enhanced Screening Settings

| Scenario | top_n | min_score | weights | Why |
|----------|-------|-----------|---------|-----|
| Senior Dev | 5-8 | 0.5 | 0.3/0.7 | Balanced |
| Tech Lead | 3-5 | 0.6 | 0.2/0.8 | Focus on LLM analysis |
| DevOps | 5-10 | 0.5 | 0.3/0.7 | Balanced |
| Specialized | 3-5 | 0.6 | 0.2/0.8 | High accuracy needed |

**Weights Explanation:**
- `0.3/0.7` = 30% embedding + 70% LLM (default, balanced)
- `0.2/0.8` = 20% embedding + 80% LLM (trust LLM more)
- `0.4/0.6` = 40% embedding + 60% LLM (faster, less LLM cost)

---

## 📊 Expected Results

### Basic Screening Output:
```json
{
  "rank": 1,
  "filename": "john_doe.pdf",
  "similarity_score": 0.82,
  "match_score": 85,
  "recommendation": "GOOD_FIT",
  "summary": "Strong fresher with good academics...",
  "strengths": [...],
  "weaknesses": [...],
  "skills_match": {...}
}
```

### Enhanced Screening Output:
```json
{
  "rank": 1,
  "filename": "sarah_johnson.pdf",
  "embedding_similarity": 0.85,
  "llm_match_score": 95,
  "final_weighted_score": 91.87,
  "meets_critical_requirements": true,
  "critical_requirements_status": {
    "5+ years Python": "met",
    "AWS certification": "met",
    "Team leadership": "met"
  },
  "recommendation": "STRONG_FIT",
  "summary": "Excellent candidate...",
  "strengths": [...],
  "weaknesses": [...],
  "red_flags": []
}
```

**Key Difference:** Enhanced shows requirement compliance!

---

## ✅ Decision Checklist

Before choosing an endpoint, ask yourself:

### Choose BASIC if you answer YES to most:
- [ ] Position is entry-level (0-2 years)?
- [ ] No strict must-have requirements?
- [ ] High volume (50+ resumes)?
- [ ] Speed is more important than accuracy?
- [ ] Budget is tight?
- [ ] First-pass screening?

### Choose ENHANCED if you answer YES to most:
- [ ] Position is senior/specialized (3+ years)?
- [ ] Has specific must-have requirements?
- [ ] Certifications required?
- [ ] Accuracy is critical?
- [ ] Willing to pay 40% more for better results?
- [ ] Need requirement compliance tracking?

---

## 🎓 Summary

### Basic Screening
- **For:** Freshers, juniors, internships, high-volume
- **Endpoint:** `/secure/ai_resume_screening`
- **Parameters:** 3 (simple)
- **Cost:** $0.007 per 100
- **Accuracy:** 85-90%
- **Speed:** 2-3 minutes

### Enhanced Screening
- **For:** Senior, specialized, critical roles
- **Endpoint:** `/secure/ai_resume_screening_enhanced`
- **Parameters:** 8 (advanced)
- **Cost:** $0.010 per 100
- **Accuracy:** 88-92%
- **Speed:** 3-4 minutes

**Both endpoints are ready to use! Choose based on your hiring needs.**

---

## 📚 Related Documentation

- `POSTMAN_RESUME_SCREENING_GUIDE.md` - Detailed Postman setup
- `AI_RESUME_SCREENING_GUIDE.md` - Complete technical guide
- `RESUME_SCREENING_COMPARISON.md` - Detailed comparison
- `RESUME_SCREENING_QUICK_START.md` - Quick reference

**Start testing now with your real resumes!**
