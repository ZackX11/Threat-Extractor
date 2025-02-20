import os
import re
import json
import spacy
import pdfplumber
import logging
import requests
from fastapi import FastAPI, UploadFile, Form
from typing import Dict, List, Optional
from pathlib import Path
import uvicorn
from dotenv import load_dotenv  # Load API key from .env

# Load API keys from .env file
load_dotenv()
VT_API_KEY = os.getenv("VT_API_KEY")

# Configure logging
logging.basicConfig(filename="error.log", level=logging.ERROR)

# Initialize FastAPI app
app = FastAPI()

# Ensure upload directory exists
UPLOAD_DIR = "uploaded_files"
os.makedirs(UPLOAD_DIR, exist_ok=True)

# Load spaCy model
nlp = spacy.load("en_core_web_lg")

# VirusTotal API Base URL
VT_API_URL = "https://www.virustotal.com/api/v3"

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
    return text.strip() if text else ""

def extract_iocs(text: str) -> Dict[str, List[str]]:
    """Extract IoCs using regex patterns."""
    return {category: list(set(re.findall(pattern, text))) for category, pattern in IOC_PATTERNS.items()}

def query_virustotal(ioc: str, ioc_type: str) -> Dict:
    """Query VirusTotal API for IoC analysis, malware data, and score with rate limit handling."""
    
    if not VT_API_KEY:
        return {"error": "VirusTotal API key not set"}

    headers = {"x-apikey": VT_API_KEY}
    
    # Determine API endpoint based on IoC type
    endpoint_map = {
        "SHA256 Hashes": f"/files/{ioc}",
        "MD5 Hashes": f"/files/{ioc}",
        "SHA1 Hashes": f"/files/{ioc}",
        "Domains": f"/domains/{ioc}",
        "URLs": f"/urls/{ioc}",
        "IPv4 addresses": f"/ip_addresses/{ioc}"
    }

    endpoint = endpoint_map.get(ioc_type, None)
    if not endpoint:
        return {"error": f"Unsupported IoC type: {ioc_type}"}

    url = f"{VT_API_URL}{endpoint}"

    max_retries = 3  # ✅ Retry up to 3 times if rate-limited
    for attempt in range(max_retries):
        try:
            response = requests.get(url, headers=headers, timeout=10)
            status_code = response.status_code
            print(f"DEBUG: VirusTotal Response - {status_code}")  # ✅ Debug response

            if status_code == 200:
                data = response.json()

                # ✅ Ensure response is a dictionary before parsing
                if not isinstance(data, dict):
                    return {"error": f"Unexpected API response format: {data}"}

                # Extract relevant fields
                attributes = data.get("data", {}).get("attributes", {})
                return {
                    "detections": attributes.get("last_analysis_stats", {}),
                    "reputation_score": attributes.get("reputation", 0),
                    "sandbox_verdicts": attributes.get("sandbox_verdicts", {}),
                    "malware_family": attributes.get("popular_threat_name", "Unknown")
                }

            elif status_code == 429:  # ❌ Rate limit exceeded
                wait_time = 15  # ✅ Adjust wait time as needed
                print(f"Rate limit exceeded! Waiting {wait_time} seconds before retrying...")
                time.sleep(wait_time)
                continue  # Retry the request

            else:
                return {"error": f"VirusTotal API error: {status_code}", "response": response.text}

        except requests.exceptions.RequestException as e:
            logging.error(f"VirusTotal API request failed: {e}")
            return {"error": "VirusTotal request failed"}

    return {"error": "VirusTotal API failed after retries"}

import time

def enrich_iocs(iocs: Dict[str, List[str]]) -> Dict:
    """Query VirusTotal for each IoC, following rate limits."""
    enriched_data = {"VirusTotal": {}}
    count = 0  # ✅ Track API calls

    for ioc_type, ioc_list in iocs.items():
        enriched_data["VirusTotal"][ioc_type] = {}

        for ioc in ioc_list:
            if count >= 4:  # ✅ If 4 requests sent, wait before continuing
                print("Reached API rate limit (4/min). Waiting 60 seconds...")
                time.sleep(60)
                count = 0  # ✅ Reset count after waiting

            enriched_data["VirusTotal"][ioc_type][ioc] = query_virustotal(ioc, ioc_type)
            count += 1  # ✅ Increment request count

    return enriched_data


@app.post("/upload_pdf/")
async def upload_pdf(file: UploadFile):
    """Process PDF, extract IoCs, and query VirusTotal."""
    file_path = Path(f"{UPLOAD_DIR}/{file.filename}")
    with file_path.open("wb") as buffer:
        buffer.write(await file.read())

    text = extract_text_from_pdf(file_path)
    iocs = extract_iocs(text)
    enriched_data = enrich_iocs(iocs)

    output_data = {"IoCs": iocs, "Threat Intelligence": enriched_data}

    output_path = file_path.with_suffix(".json")
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(output_data, f, indent=2)

    return {"message": "Processing complete", "report_path": str(output_path)}

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000, reload=True)
