import os

class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", "vulnx-secret-2024")
    DB_PATH = os.path.join(os.path.dirname(__file__), "database", "vulnx.db")
    GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY", "")
    VIRUSTOTAL_API_KEY = os.environ.get("VIRUSTOTAL_API_KEY", "")
    MAX_CRAWL_DEPTH = 2
    MAX_URLS = 50
    SCAN_TIMEOUT = 10
