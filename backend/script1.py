import os
import re
import json
import spacy
import pdfplumber
from vt import Client
import urllib.parse
from typing import Dict, List, Optional
import time
import logging
from fastapi import FastAPI, UploadFile
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
import requests
from pathlib import Path
import uvicorn

from pathlib import Path
from dotenv import load_dotenv

load_dotenv()
VT_API_KEY = os.getenv("VT_API_KEY")

# Setup logging
logging.basicConfig(filename="error.log", level=logging.ERROR)

# Initialize FastAPI app
app = FastAPI()

# Enable CORS (Important for React Frontend)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allows requests from any frontend
    allow_credentials=True,
    allow_methods=["*"],  # Allow all HTTP methods (POST, GET, etc.)
    allow_headers=["*"],  # Allow all headers
)

# Directory to store uploaded files & generated JSONs
UPLOAD_DIR = "uploaded_files"
os.makedirs(UPLOAD_DIR, exist_ok=True)

VT_API_URL = "https://www.virustotal.com/api/v3"

MITRE_DATA = "mitre_data.json"
try:
    with open(MITRE_DATA, "r", encoding="utf-8") as f:
        mitre_json = json.load(f)
        MITRE_TACTICS = mitre_json.get("tactics", {})
        MITRE_TECHNIQUES = mitre_json.get("techniques", {})
except Exception as e:
    logging.error(f"Error loading MITRE file: {e}")
    MITRE_TACTICS = {}
    MITRE_TECHNIQUES = {}

# IoC Extraction Patterns
IOC_PATTERNS = {
    'IPv4 addresses': r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
    'IPv6 addresses': r'\b(?:(?:[a-fA-F0-9]{1,4}:){7,7}[a-fA-F0-9]{1,4}|'  # Full 8-block IPv6
                  r'(?:[a-fA-F0-9]{1,4}:){1,7}:|'  # Abbreviated IPv6 (:: shorthand)
                  r'(?:[a-fA-F0-9]{1,4}:){1,6}:[a-fA-F0-9]{1,4}|'  
                  r'(?:[a-fA-F0-9]{1,4}:){1,5}(?::[a-fA-F0-9]{1,4}){1,2}|'  
                  r'(?:[a-fA-F0-9]{1,4}:){1,4}(?::[a-fA-F0-9]{1,4}){1,3}|'  
                  r'(?:[a-fA-F0-9]{1,4}:){1,3}(?::[a-fA-F0-9]{1,4}){1,4}|'  
                  r'(?:[a-fA-F0-9]{1,4}:){1,2}(?::[a-fA-F0-9]{1,4}){1,5}|'  
                  r'[a-fA-F0-9]{1,4}:(?:(?::[a-fA-F0-9]{1,4}){1,6})|'  
                  r':(?:(?::[a-fA-F0-9]{1,4}){1,7}|:)|'  
                  r'fe80:(?::[a-fA-F0-9]{0,4}){0,4}%[0-9a-zA-Z]{1,}|'  # Link-local
                  r'::(ffff(:0{1,4}){0,1}:){0,1}'  # IPv4-mapped IPv6
                  r'([a-fA-F0-9]{1,4}:){1,4}[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\b', 
    'URLs': r'\b(?:https?|ftp)://[^\s/$.?#].[^\s]*\b',
    'Domains': r"\b(?!(?:[a-fA-F0-9]{32,64}))(?:(?:[a-zA-Z0-9-]+\.)+(?:com|net|org|info|biz|ru|cn|io|me|tv|xyz|top|club|online|site|tech|store|pro|vip|best|blog|host|click|review|press|live|space|fun|today|cloud|agency|services|email|solutions|trade|market|network|systems|expert|guru|company|digital|world|center|group|design|media|news|social|support|video|download|software|photo|tips|game|plus|zone|chat|team|tools|website|cool|global|fashion|company|directory|management|engineering|finance|domains|ventures|enterprises|academy|training|institute|school|university|community|foundation|partners|church|charity|gives|credit|loans|insure|health|band|theater|watch|dance|cafe|bar|restaurant|wedding|gallery|photo|events|house|garden|vacations|holiday|boutique|shoes|diamonds|gold|jewelry|jewelers|builders|construction|contractors))\b",
    'MD5 Hashes': r'\b[a-fA-F0-9]{32}\b',
    'SHA1 Hashes': r'\b[a-fA-F0-9]{40}\b',
    'SHA256 Hashes': r'\b[a-fA-F0-9]{64}\b',
    'Emails': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
    'Files': r"\b(?!www\.|http[s]?://)[a-zA-Z0-9_\-]+\.(?:exe|dll|txt|pdf|docx|xls|xlsx|zip|rar|7z|tar|gz|py|sh|js|php|html|json|bin|apk|msi|scr|sys|log|db|cfg|bak|cmd|rpm|iso|img|vmdk|jar|war)\b"
}

MITRE_PATTERN = r"\bT\d{4}(?:\.\d{3})?\b"

def extract_text_from_pdf(pdf_path: Path) -> str:
    """Extract text from a PDF file."""
    text = ""
    try:
        with pdfplumber.open(pdf_path) as pdf:
            for page in pdf.pages:
                page_text = page.extract_text()
                if page_text:
                    text += page_text + "\n"
    except Exception as e:
        logging.error(f"Error extracting text from {pdf_path}: {e}")
        return ""
    return text.strip()

def extract_iocs(text: str) -> dict:
    """Extract IoCs using regex patterns."""
    return {category: list(set(re.findall(pattern, text))) for category, pattern in IOC_PATTERNS.items()}


def query_virustotal(ioc: str, ioc_type: str) -> dict:
    """Query VirusTotal API for IoC analysis, including MD5 and SHA256 hashes."""
    if not VT_API_KEY:
        return {"error": "VirusTotal API key not set"}

    headers = {"x-apikey": VT_API_KEY}

    # Add support for MD5, SHA1, and SHA256
    endpoint_map = {
        "SHA256 Hashes": f"/files/{ioc}",
        "MD5 Hashes": f"/files/{ioc}",
        "SHA1 Hashes": f"/files/{ioc}",
        "Domains": f"/domains/{ioc}",
        "IPv4 addresses": f"/ip_addresses/{ioc}",
        "URLs": f"/urls/{urllib.parse.quote_plus(ioc)}"
    }

    endpoint = endpoint_map.get(ioc_type)
    if not endpoint:
        return {"error": f"Unsupported IoC type: {ioc_type}"}

    url = f"{VT_API_URL}{endpoint}"

    try:
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code == 200:
            data = response.json().get("data", {}).get("attributes", {})
            return {
                "detections": data.get("last_analysis_stats", {}),
                "reputation_score": data.get("reputation", 0),
                "malware_family": data.get("popular_threat_name", "Unknown"),
                "tags": data.get("tags", []),
                "last_analysis_results": data.get("last_analysis_results", {})
            }
        elif response.status_code == 429:
            return {"error": "Rate limit exceeded, please wait"}
        else:
            return {"error": f"VirusTotal API error: {response.status_code}"}
    except requests.exceptions.RequestException as e:
        return {"error": f"Request failed: {e}"}


def enrich_malware_data(hashes: List[str]) -> List[dict]:
    """Query VirusTotal API for malware details including MD5 hashes."""
    if not VT_API_KEY:
        return [{"error": "VirusTotal API key is missing"}]

    malware_data = []
    for file_hash in hashes:
        # Query VT for all hash types
        vt_result = query_virustotal(file_hash, "MD5 Hashes")  # Added MD5 support
        if vt_result:
            malware_data.append(vt_result)

    return malware_data


def extract_mitre_ttps(text: str) -> list:
    """Extract MITRE ATT&CK technique IDs from text."""
    return sorted(set(re.findall(MITRE_PATTERN, text)))

def extract_ttps(text: str) -> dict:
    """Extract MITRE ATT&CK TTPs using keyword matching"""
    tactics = []
    techniques = []
    
    # Match tactics
    for tactic_name, tactic_id in MITRE_TACTICS.items():
        if re.search(r'\b' + re.escape(tactic_name) + r'\b', text, re.IGNORECASE):
            tactics.append({tactic_id: tactic_name.title()})
    
    # Match techniques
    for tech_name, tech_id in MITRE_TECHNIQUES.items():
        if re.search(r'\b' + re.escape(tech_name) + r'\b', text, re.IGNORECASE):
            techniques.append({tech_id: tech_name.title()})
    
    return {'Tactics': tactics, 'Techniques': techniques}

nlp = spacy.load("en_core_web_sm")

def extract_entities(text: str) -> dict:
    """Extract threat actors and targeted entities from text using SpaCy NER"""
    doc = nlp(text)
    entities = {
        'Threat Actors': [],
        'Targeted Entities': []
    }
    
    for ent in doc.ents:
        if ent.label_ in ['ORG', 'PERSON']:
            entities['Threat Actors'].append(ent.text)
        elif ent.label_ in ['ORG', 'GPE', 'NORP']:
            entities['Targeted Entities'].append(ent.text)
    
    # Deduplicate and clean
    entities['Threat Actors'] = list(set(entities['Threat Actors']))
    entities['Targeted Entities'] = list(set(entities['Targeted Entities']))
    
    return entities

def enrich_malware_data(hashes: List[str]) -> List[dict]:
    """Query VirusTotal API for malware details."""
    if not VT_API_KEY:
        logging.error("VirusTotal API key is missing. Skipping enrichment.")
        return []

    malware_data = []
    with Client(VT_API_KEY) as client:
        for file_hash in hashes:
            try:
                file_obj = client.get_object(f"/files/{file_hash}")
                malware_data.append({
                    'Name': getattr(file_obj, 'meaningful_name', 'Unknown'),
                    'md5': str(file_obj.md5),
                    'sha1': str(file_obj.sha1),
                    'sha256': str(file_obj.sha256),
                    'tags': list(getattr(file_obj, 'tags', [])),
                    'last_analysis_stats': dict(file_obj.last_analysis_stats)
                })
            except Exception as e:
                logging.error(f"Error processing hash {file_hash}: {str(e)}")
    
    return malware_data

@app.post("/upload_pdf/")
async def upload_pdf(file: UploadFile):
    """Process PDF, extract IoCs, and generate JSON."""
    file_path = Path(f"{UPLOAD_DIR}/{file.filename}")
    with file_path.open("wb") as buffer:
        buffer.write(await file.read())

    text = extract_text_from_pdf(file_path)
    iocs = extract_iocs(text)
    mitre = extract_ttps(text)
    target = extract_entities(text)

    output_data = {
        "IoCs": iocs,
        "TTPS": mitre,
        "Entities": target,
    }
    json_filename = file_path.with_suffix(".json")

    with open(json_filename, "w", encoding="utf-8") as f:
        json.dump(output_data, f, indent=2)

    return {"message": "Processing complete", "report_path": str(json_filename.name)}

@app.get("/get_json/{filename}")
async def get_json(filename: str):
    """Return JSON data for the uploaded PDF."""
    json_path = Path(UPLOAD_DIR) / filename

    if not json_path.exists():
        return JSONResponse(content={"error": "File not found"}, status_code=404)

    with open(json_path, "r", encoding="utf-8") as f:
        json_data = json.load(f)

    return JSONResponse(content=json_data)

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000, reload=True)
