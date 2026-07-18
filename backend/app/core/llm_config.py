import os
from dotenv import load_dotenv

load_dotenv()

def get_llm():
    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key:
        raise ValueError("CRITICAL: GEMINI_API_KEY not found in environment variables!")

    try:
        from langchain_google_genai import ChatGoogleGenerativeAI
    except ModuleNotFoundError as error:
        raise ValueError(
            "CRITICAL: langchain-google-genai is not installed. "
            "Install project dependencies with: pip install -r requirements.txt"
        ) from error

    llm = ChatGoogleGenerativeAI(
        model="gemini-2.5-flash",
        temperature=0.0,
        max_retries=3
    )
    
    return llm
