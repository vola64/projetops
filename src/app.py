"""
Application FastAPI sécurisée - Pipeline DevSecOps
"""
from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import logging
import os
from src.utils import verify_token, sanitize_input, get_app_version

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s - %(message)s"
)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="DevSecOps Demo API",
    description="API sécurisée - supply chain logicielle",
    version=get_app_version(),
    docs_url="/docs" if os.getenv("ENV") != "production" else None,
    redoc_url=None,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=os.getenv("ALLOWED_ORIGINS", "http://localhost").split(","),
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["Authorization", "Content-Type"],
)

security = HTTPBearer()


@app.get("/health", tags=["Monitoring"])
async def health_check():
    """Endpoint de santé pour le monitoring."""
    return {
        "status": "healthy",
        "version": get_app_version(),
        "environment": os.getenv("ENV", "development"),
    }


@app.get("/", tags=["General"])
async def root():
    """Point d'entrée principal."""
    return {"message": "DevSecOps API opérationnelle", "version": get_app_version()}


@app.get("/secure/data", tags=["Sécurisé"])
async def get_secure_data(
    credentials: HTTPAuthorizationCredentials = Depends(security),
):
    """Endpoint protégé par token Bearer."""
    token = credentials.credentials
    if not verify_token(token):
        logger.warning("Tentative d'accès non autorisée")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token invalide ou expiré",
            headers={"WWW-Authenticate": "Bearer"},
        )
    logger.info("Accès autorisé aux données sécurisées")
    return {
        "data": "Données confidentielles",
        "classification": "INTERNAL",
    }


@app.post("/echo", tags=["General"])
async def echo(payload: dict):
    """Echo sécurisé avec sanitisation des inputs."""
    sanitized = {k: sanitize_input(str(v)) for k, v in payload.items()}
    return {"echo": sanitized}


@app.exception_handler(Exception)
async def global_exception_handler(request, exc):
    """Handler global - évite la fuite d'informations sensibles."""
    logger.error(f"Erreur non gérée: {type(exc).__name__}")
    return JSONResponse(
        status_code=500,
        content={"detail": "Erreur interne du serveur"},
    )
