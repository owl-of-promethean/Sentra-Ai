"""
Application configuration and environment variables.
"""

import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()


class Config:
    """Application configuration settings."""

    # Groq configuration (single LLM provider)
    GROQ_API_KEY = os.getenv("GROQ_API_KEY")
    GROQ_BASE_URL = os.getenv(
        "GROQ_BASE_URL", "https://api.groq.com/openai/v1"
    )
    GROQ_MODEL = os.getenv("GROQ_MODEL", "openai/gpt-oss-20b")

    # Validate required configuration
    @classmethod
    def validate(cls):
        """Validate that required configuration is present."""
        if not cls.GROQ_API_KEY:
            raise ValueError(
                "GROQ_API_KEY is required. Please set it in your .env file."
            )
