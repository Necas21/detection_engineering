import requests
from dotenv import load_dotenv
import os

load_dotenv()

url = "https://50e136fe78584084803617ef7744e007.us-central1.gcp.cloud.es.io/api/detection_engine/rules?rule_id="
id = "00000000-0000-0000-0000-000000000001"
api_key = os.getenv("elatic_api_key")
headers = {
    "Content-Type": "application/json;charset=UTF-8",
    "kbn-xsrf": "true",
    "Authorization": f"ApiKey {api_key}"
}

elastic_data = requests.get(f"{url}{id}", headers=headers).json()
print(elastic_data)