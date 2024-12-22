import requests
from dotenv import load_dotenv
import os

load_dotenv()

url = "https://50e136fe78584084803617ef7744e007.us-central1.gcp.cloud.es.io/api/detection_engine/rules"
api_key = os.getenv("elatic_api_key")
headers = {
    "Content-Type": "application/json;charset=UTF-8",
    "kbn-xsrf": "true",
    "Authorization": f"ApiKey {api_key}"
}

data = """
{
  "rule_id": "process_started_by_ms_office_program",
  "risk_score": 50,
  "description": "Process started by MS Office program - possible payload",
  "interval": "1h", 
  "name": "MS Office child process",
  "severity": "low",
  "tags": [
   "child process",
   "ms office"
   ],
  "type": "query",
  "from": "now-70m", 
  "query": "process.parent.name:EXCEL.EXE or process.parent.name:MSPUB.EXE or process.parent.name:OUTLOOK.EXE or process.parent.name:POWERPNT.EXE or process.parent.name:VISIO.EXE or process.parent.name:WINWORD.EXE",
  "language": "kuery",
  "filters": [
     {
      "query": {
         "match": {
            "event.action": {
               "query": "Process Create (rule: ProcessCreate)",
               "type": "phrase"
            }
         }
      }
     }
  ],
  "required_fields": [
    { name: "process.parent.name", "type": "keyword" }
  ],
  "related_integrations": [
    { "package": "o365", "version": "^2.3.2"}
  ],
  "enabled": true
}
"""

elastic_data = requests.post(url, headers=headers, data=data).json()
print(elastic_data)