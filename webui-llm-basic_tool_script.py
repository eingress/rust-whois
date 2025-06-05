import os
import requests
import json
from pydantic import BaseModel, Field

class Tools:
    def __init__(self):
        self.whois_api_base = os.getenv("WHOIS_API_BASE", "http://localhost:3001")
        
    def whois(
        self,
        domain: str = Field(..., description="Domain name to lookup")
    ) -> str:
        """
        Get WHOIS information for a domain.
        """
        try:
            domain = domain.strip().lower()
            response = requests.get(f"{self.whois_api_base}/whois/{domain}", timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                
                # Extract key information
                result = f"WHOIS Information for {domain}:\n\n"
                result += f"Domain: {data.get('domain', 'Unknown')}\n"
                result += f"WHOIS Server: {data.get('whois_server', 'Unknown')}\n"
                result += f"Cached: {data.get('cached', False)}\n"
                result += f"Query Time: {data.get('query_time_ms', 0)}ms\n\n"
                
                # Check if we have parsed data
                parsed_data = data.get('parsed_data')
                if parsed_data:
                    result += "Parsed WHOIS Data:\n"
                    result += f"  Registrar: {parsed_data.get('registrar', 'Not available')}\n"
                    result += f"  Created: {parsed_data.get('creation_date', 'Not available')}\n"
                    result += f"  Updated: {parsed_data.get('updated_date', 'Not available')}\n"
                    result += f"  Expires: {parsed_data.get('expiration_date', 'Not available')}\n"
                    result += f"  Created Days Ago: {parsed_data.get('created_ago', 'Not available')}\n"
                    result += f"  Updated Days Ago: {parsed_data.get('updated_ago', 'Not available')}\n"
                    result += f"  Expires In Days: {parsed_data.get('expires_in', 'Not available')}\n"
                    
                    name_servers = parsed_data.get('name_servers', [])
                    if name_servers:
                        result += f"  Name Servers: {', '.join(name_servers)}\n"
                    else:
                        result += "  Name Servers: Not available\n"
                    
                    status = parsed_data.get('status', [])
                    if status:
                        result += f"  Status: {', '.join(status)}\n"
                    else:
                        result += "  Status: Not available\n"
                        
                    result += f"  Registrant Name: {parsed_data.get('registrant_name', 'Not available')}\n"
                    result += f"  Registrant Email: {parsed_data.get('registrant_email', 'Not available')}\n"
                    result += f"  Admin Email: {parsed_data.get('admin_email', 'Not available')}\n"
                    result += f"  Tech Email: {parsed_data.get('tech_email', 'Not available')}\n"
                else:
                    result += "Parsed Data: Not available or could not be parsed\n"
                
                # Show raw data availability
                raw_data = data.get('raw_data', '')
                if raw_data:
                    result += f"\nRaw WHOIS Data Available: Yes ({len(raw_data)} characters)\n"
                    # Show first few lines
                    lines = raw_data.split('\n')[:5]
                    result += "First few lines of raw data:\n"
                    for line in lines:
                        result += f"  {line}\n"
                else:
                    result += "\nRaw WHOIS Data Available: No\n"
                
                # For debugging, also show the full JSON
                result += f"\n--- Full API Response ---\n{json.dumps(data, indent=2)}"
                
                return result
            else:
                return f"Error: Failed to get WHOIS data for {domain} (Status: {response.status_code})"
                
        except Exception as e:
            return f"Error: {str(e)}" 