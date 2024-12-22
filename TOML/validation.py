import tomllib
import sys
import os

# file = "alert_example.toml"

# with open(file, "rb") as toml:
#     alert = tomllib.load(toml)

for root, dirs, files in os.walk("C:/Users/Mounir/Documents/Security Studies/Detection Engineering/converted_detections"):
    for file in files:
        if file.endswith(".toml"):
            full_path = os.path.join(root, file)
            with open(full_path, "rb") as toml:
                alert = tomllib.load(toml)

                present_fields = []
                missing_fields = []

                if alert["rule"]["type"] == "query":
                    required_fields = ["description", "name", "risk_score", "severity", "type", "query", "rule_id"]
                elif alert["rule"]["type"] == "eql":
                    required_fields = ["description", "name", "risk_score", "severity", "type", "query", "language", "rule_id"]
                elif alert["rule"]["type"] == "threshold":
                    required_fields = ["description", "name", "risk_score", "severity", "type", "query", "threshold", "rule_id"]
                else:
                    print(f"[!] ERROR: Unsupported rule type [{alert['rule']['type']}] found in <{file}>")
                    break

                for table in alert:
                    for field in alert[table]:
                        present_fields.append(field)

                for field in required_fields:
                    if field not in present_fields:
                        missing_fields.append(field)

                if missing_fields:
                    print(f"[!] ERROR: The following required fields are missing in <{file}> : {str(missing_fields)}")
                else:
                    print(f"[*] SUCCESS: Validation passed for <{file}>")