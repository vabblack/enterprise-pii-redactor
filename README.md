# Enterprise AI-Powered PII Redaction & Document Anonymization Platform

An enterprise-grade Python solution and Web Application designed to detect, redact, and anonymize Personally Identifiable Information (PII) within Microsoft Word (`.docx`) and text documents. The system preserves document formatting, table alignments, typography, and styling while replacing sensitive data with consistent synthetic alternatives generated via `Faker`.

---

## 🌟 Level 1, Level 2 & Level 3 Enterprise Features

```
┌───────────────────────────────────────────────────────────────────────────────────┐
│                              PII REDACTION PLATFORM                               │
├──────────────────────────────┬──────────────────────────────────┬─────────────────┤
│  LEVEL 1 — CORE ASSIGNMENT   │  LEVEL 2 — NLP & ML ENGINE       │ LEVEL 3 — WEB   │
├──────────────────────────────┼──────────────────────────────────┼─────────────────┤
│ • DOCX Text Redaction        │ • Presidio + spaCy + Regex Engine│ • Flask Web App │
│ • 9 PII Categories           │ • Pseudonymous Replacement Map   │ • Drag & Drop   │
│ • Faker Synthetic Alternatives│ • Confidence Score Scoring       │ • Live Stats UI │
│ • Ground Truth Benchmark     │ • False Positive Blocklist       │ • REST API      │
│ • Technical README           │ • Unit Test Suite (unittest)     │ • One-Click DL  │
└──────────────────────────────┴──────────────────────────────────┴─────────────────┘
```

---

## 📌 Architecture & Pipeline

```
┌────────────────────────┐      ┌─────────────────────────┐      ┌─────────────────────────┐
│ Input Docx Document    │ ───► │ Multi-Stage PII Engine  │ ───► │ Synthetic Faker Mapping │
│ (Paragraphs & Tables)  │      │ (Regex + Presidio/NER)  │      │ (Deterministic Replacer)│
└────────────────────────┘      └─────────────────────────┘      └─────────────────────────┘
                                                                              │
                                                                              ▼
                                                                 ┌─────────────────────────┐
                                                                 │ Redacted Docx Output    │
                                                                 │ (Redacted Prospectus)   │
                                                                 └─────────────────────────┘
```

### Supported PII Categories
1. **Full Names**: Recognized via Title/Role patterns (`Mr.`, `Ms.`, `Director`), Indian name gazetteers, and spaCy NER (`PERSON`).
2. **Email Addresses**: High-precision Regex (`[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`) + Presidio recognizers.
3. **Phone Numbers**: Multi-format regex catching Indian mobiles (`+91 9876543210`), landlines (`020-67314000`), and international formats.
4. **Company Names**: Legal suffix matching (`Limited`, `Private Limited`, `LLP`, `Bank`, `Securities`) + spaCy NER (`ORG`).
5. **Physical / Mailing Addresses**: Location keyword triggers (`Village`, `Taluka`, `Road`, `Street`, `Pincode`) + Presidio (`LOCATION`).
6. **SSNs & National IDs**: Regex patterns for US SSN (`XXX-XX-XXXX`), Indian PAN (`[A-Z]{5}\d{4}[A-Z]`), and Aadhaar (`XXXX XXXX XXXX`).
7. **Credit Card Numbers**: Pattern extraction validated using the **Luhn Algorithm**.
8. **Dates of Birth**: Contextual date parser targeting personal birth dates (e.g. `August 6, 1982`) while preserving financial period dates (e.g., `June 30, 2025`).
9. **IP Addresses**: IPv4 and IPv6 regex filters excluding version numbers.

---

## 🔒 Pseudonymous & Consistent Replacement Mapping

When an entity appears multiple times across paragraphs or tables, the engine maintains a deterministic mapping:
- `Pushpa Kushal Hegde` $\rightarrow$ `John Smith` (consistently everywhere)
- `cs.connect@kshinternational.com` $\rightarrow$ `john.smith@domain.com` (consistently everywhere)
- `+91 9876543210` $\rightarrow$ `+91 1234567645` (consistently everywhere)

---

## 🛠️ Code Layout & Testing

- `pii_redactor.py`: Core PII detection, anonymization, and docx redactor engine.
- `app.py`: Web dashboard application and REST API (`http://127.0.0.1:5000`).
- `evaluate_redaction.py`: Ground-truth benchmark evaluation script.
- `test_pii_redactor.py`: Automated unit test suite.

### Running Unit Tests
```bash
python -m unittest test_pii_redactor.py
```

### Running Web Application
```bash
python app.py
```
Open **http://127.0.0.1:5000** in your browser.

### Running CLI Redactor & Benchmark
```bash
python pii_redactor.py
python evaluate_redaction.py
```
