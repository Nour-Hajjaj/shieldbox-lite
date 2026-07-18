import os
import logging
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from scanner_logic import calculate_score, is_valid_url_structure

load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=[os.getenv("CORS_ORIGIN")],
    allow_methods=["*"],
    allow_headers=["*"],
)

class URLRequest(BaseModel):
    url: str

@app.post("/scan-url")
def scan_url(request: URLRequest):
    logger.info(f"Received scan request for URL: {request.url}")

    if not request.url.strip():
        logger.warning("Rejected empty URL request.")
        raise HTTPException(status_code=400, detail="URL cannot be empty.")

    if not is_valid_url_structure(request.url):
        logger.warning(f"Rejected invalid URL structure: {request.url}")
        raise HTTPException(status_code=400, detail="This does not appear to be a valid URL. Make sure it starts with http:// or https:// and includes a valid domain.")

    result = calculate_score(request.url)
    logger.info(f"Scan complete. Score: {result['score']}, Risk: {result['risk_level']}")
    return result