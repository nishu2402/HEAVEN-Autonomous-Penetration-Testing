"""
HEAVEN — AI Remediation Generator
Uses Google Gemini API to automatically generate patch code for vulnerabilities.
"""

from __future__ import annotations

import os
from typing import Any, Optional

from heaven.utils.logger import get_logger

logger = get_logger("devsecops.ai_remediation")

class AIRemediationEngine:
    """Generates remediation code using Google Gemini."""
    
    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or os.getenv("GEMINI_API_KEY")
        self.available = False
        
        if self.api_key:
            try:
                import google.generativeai as genai
                genai.configure(api_key=self.api_key)
                self.model = genai.GenerativeModel('gemini-pro')
                self.available = True
            except ImportError:
                logger.warning("google-generativeai not installed. AI Remediation unavailable.")
            except Exception as e:
                logger.error(f"Failed to initialize Gemini AI: {e}")
                
    def generate_patch(self, vuln: dict[str, Any]) -> str:
        """Generate a patch for a specific vulnerability."""
        if not self.available:
            return vuln.get("patch", "Apply standard security patches for this vulnerability.")
            
        title = vuln.get("title", vuln.get("type", "Unknown"))
        desc = vuln.get("description", "")
        target = vuln.get("target", "")
        
        prompt = (
            f"You are an expert DevSecOps engineer. I have discovered a vulnerability "
            f"during an automated penetration test. \n\n"
            f"Target: {target}\n"
            f"Vulnerability: {title}\n"
            f"Description: {desc}\n\n"
            f"Please provide specific, actionable remediation steps, including code snippets "
            f"(like Terraform config, Python code, or Nginx config) to fix this issue immediately."
        )
        
        try:
            logger.info(f"Requesting AI remediation for {title}...")
            response = self.model.generate_content(prompt)
            return response.text
        except Exception as e:
            logger.error(f"AI Remediation failed: {e}")
            return vuln.get("patch", "Apply standard security patches for this vulnerability.")
