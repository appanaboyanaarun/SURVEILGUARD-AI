import uvicorn
import os
import sys

# Ensure project root is on PYTHONPATH
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app.config import settings

if __name__ == "__main__":
    print("==================================================================")
    print("  SURVEILLANCE FOOTAGE METADATA ANOMALY DETECTION SYSTEM (AGY)   ")
    print(f"  Open your browser and navigate to {settings.BASE_URL}")
    print("==================================================================")
    uvicorn.run(
        "app.main:app",
        host=settings.APP_HOST,
        port=settings.APP_PORT,
        reload=True,
    )
