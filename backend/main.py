from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from scanner_logic import calculate_score, is_valid_url_structure

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_methods=["*"],
    allow_headers=["*"],
)

class URLRequest(BaseModel):
    url: str

@app.post("/scan-url")
def scan_url(request: URLRequest):
    if not request.url.strip():
        raise HTTPException(status_code=400, detail="URL cannot be empty.")

    if not is_valid_url_structure(request.url):
        raise HTTPException(status_code=400, detail="This does not appear to be a valid URL. Make sure it starts with http:// or https:// and includes a valid domain.")

    result = calculate_score(request.url)
    return result