import requests
from dotenv import load_dotenv
import os
import tomllib

load_dotenv()

url = "https://50e136fe78584084803617ef7744e007.us-central1.gcp.cloud.es.io/api/detection_engine/rules"
api_key = os.getenv("ELASTIC_API_KEY")
headers = {
    "Content-Type": "application/json;charset=UTF-8",
    "kbn-xsrf": "true",
    "Authorization": f"ApiKey {api_key}"
}

changed_files = os.getenv("CHANGED_FILES")

data = ""

for root, dirs, files in os.walk("detections/"):
    for file in files:
        if file in changed_files:
            data = "{\n"
            if file.endswith(".toml"):
                full_path = os.path.join(root, file)
                with open(full_path, "rb") as toml:
                    alert = tomllib.load(toml)

                    if alert["rule"]["type"] == "query":
                        required_fields = ["author", "description", "name", "risk_score", "severity", "type", "query", "threat", "rule_id"]
                    elif alert["rule"]["type"] == "eql":
                        required_fields = ["author", "description", "name", "risk_score", "severity", "type", "query", "language", "threat", "rule_id"]
                    elif alert["rule"]["type"] == "threshold":
                        required_fields = ["author", "description", "name", "risk_score", "severity", "type", "query", "threshold", "threat", "rule_id"]
                    else:
                        print(f"[!] ERROR: Unsupported rule type [{alert['rule']['type']}] found in <{file}>")
                        break

                    for field in alert["rule"]:
                        if field in required_fields:
                            if type(alert["rule"][field]) == list:
                                data += "  " + "\"" + field + "\": " + str(alert["rule"][field]).replace("'", "\"") + ",\n"
                            elif type(alert["rule"][field]) == str:
                                if field == "description":
                                    data += "  " + "\"" + field + "\": " + "\"" + str(alert["rule"][field]).replace("\n", " ").replace("\"", "\\\"").replace("\\", "\\\\") + "\"" + ",\n"
                                elif field == "query":
                                    data += "  " + "\"" + field + "\": " + "\"" + str(alert["rule"][field]).replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", " ") + "\"" + ",\n"
                                else:
                                    data += "  " + "\"" + field + "\": " + "\"" + str(alert["rule"][field]).replace("\n", " ").replace("\"", "\\\"") + "\"" + ",\n"
                            elif type(alert["rule"][field]) == int:
                                data += "  " + "\"" + field + "\": " + str(alert["rule"][field]) + ",\n"
                            elif type(alert["rule"][field]) == dict:
                                data += "  " + "\"" + field + "\": " + str(alert["rule"][field]).replace("'", "\"") + ",\n"
                    data += "  \"enabled\": true\n}"
                rule_id = alert["rule"]["rule_id"]

                rule_id = alert['rule']['rule_id']
                update_url = url + "?rule_id=" + rule_id
            
                elastic_data = requests.put(update_url, headers=headers, data=data).json()
            
                for key in elastic_data:
                    if key == "status_code":
                        if 404 == elastic_data["status_code"]:
                            elastic_data = requests.post(url, headers=headers, data=data).json()
                            print(f"[*] SUCCESS: Successfully created rule <{file}>")
                    else:
                        print(f"[*] SUCCESS: Successfully updated rule <{file}>")