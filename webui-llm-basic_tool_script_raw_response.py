import os
import requests
from pydantic import BaseModel, Field

class Tools:
    def __init__(self):
        self.whois_api_base = os.getenv("WHOIS_API_BASE", "http://localhost:3000")

    def whois(
        self,
        domain: str = Field(..., description="Domain name to lookup")
    ) -> str:
        """
        Get raw WHOIS information for a domain for the LLM to analyze.
        """
        try:
            response = requests.get(f"{self.whois_api_base}/whois/{domain}", timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                raw_data = data.get('raw_data', '')
                
                if raw_data:
                    return f"Raw WHOIS data for {domain}:\n\n{raw_data}"
                else:
                    return f"No WHOIS data available for {domain}. This may be due to privacy protection or server restrictions."
            else:
                return f"Error: Failed to get WHOIS data for {domain}"
                
        except Exception as e:
            return f"Error: {str(e)}" 