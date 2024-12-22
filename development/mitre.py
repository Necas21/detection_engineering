import requests
import tomllib
import os
import sys

url = "https://raw.githubusercontent.com/mitre/cti/refs/heads/master/enterprise-attack/enterprise-attack.json"
headers = {
    "Accept": "application/json"
}

mitre_data = requests.get(url, headers=headers).json()
mitre_mapping = {}

# def get_mapping(mitre_data):

for object in mitre_data["objects"]:
    tactics = []
    if object["type"] == "attack-pattern":
        if "external_references" in object:
            for reference in object["external_references"]:
                if "external_id" in reference:
                    if reference["external_id"].startswith("T"):
                        if "kill_chain_phases" in object:
                            for tactic in object["kill_chain_phases"]:
                                tactics.append(tactic["phase_name"])
                        technique = reference["external_id"]
                        name = object["name"]
                        url = reference["url"]
                        if "x_mitre_deprecated" in object:
                            deprecated = object["x_mitre_deprecated"]
                            filtered_object = {"tactics" : str(tactics), "technique": technique, "name": name, "url": url, "deprecated": deprecated}
                            mitre_mapping[technique] = filtered_object
                        else:
                            filtered_object = {"tactics" : str(tactics), "technique": technique, "name": name, "url": url, "deprecated": "False"}
                            mitre_mapping[technique] = filtered_object

alert_data = {}

for root, dirs, files in os.walk("detections/"):
    for file in files:
        if file.endswith(".toml"):
            full_path = os.path.join(root, file)
            with open(full_path, "rb") as toml:
                alert = tomllib.load(toml)
                filtered_object_array = []
                if alert["rule"]["threat"][0]["framework"] == "MITRE ATT&CK":
                    for threat in alert["rule"]["threat"]:
                        technique_id = threat["technique"][0]["id"]
                        technique_name = threat["technique"][0]["name"]
                        if "tactic" in threat:
                            tactic = threat["tactic"]["name"]
                        else:
                            tactic = "none"

                        if "subtechnique" in threat["technique"][0]:
                            subtechnique_id = threat["technique"][0]["subtechnique"][0]["id"]
                            subtechnique_name = threat["technique"][0]["subtechnique"][0]["name"]
                        else:
                            subtechnique_id = "none"
                            subtechnique_name = "none"

                        filtered_object = {"tactic": tactic, "technique_id": technique_id, "technique_name": technique_name, "subtechnique_id": subtechnique_id, "subtechnique_name": subtechnique_name}
                        filtered_object_array.append(filtered_object)
                        alert_data[file] = filtered_object_array

mitre_tactic_list = ['none','reconnaissance','resource development','initial access','execution','persistence','privilege escalation','defense evasion','credential access','discovery','lateral movement','collection','command and control','exfiltration','impact']

for file in alert_data:
   for line in alert_data[file]:
       tactic = line["tactic"].lower()
       technique_id = line["technique_id"]
       subtechnique_id = line["subtechnique_id"]

       # Check MITRE tactic exists
       if tactic not in mitre_tactic_list:
           print(f"[!] ERROR: Invalid MITRE tactic supplied [{tactic}] in file <{file}>")
           sys.exit(1)

       # Check MITRE technique ID is valid
       try:
           if mitre_mapping[technique_id]:
               pass
       except KeyError:
           print(f"[!] ERROR: Invalid MITRE technique ID [{technique_id}] in file <{file}>")
           sys.exit(1)

       # Check MITRE TID and name combination is valid
       try:
           mitre_name = mitre_mapping[technique_id]["name"]
           alert_name = line["technique_name"]
           if alert_name != mitre_name:
               print(f"[!] ERROR: Invalid MITRE technique ID and technique name combination in file <{file}>:")
               print(f"EXPECTED: {mitre_name}")
               print(f"GIVEN: {alert_name}")
               sys.exit(1)
       except KeyError:
           pass
       
       # Check if sub TID and name combination is valid
       try:
           if subtechnique_id != "none":
               mitre_name = mitre_mapping[subtechnique_id]["name"]
               alert_name = line["subtechnique_name"]
               if alert_name != mitre_name:
                    print(f"[!] ERROR: Invalid MITRE subtechnique ID and subtechnique name combination in file <{file}>:")
                    print(f"EXPECTED: {mitre_name}")
                    print(f"GIVEN: {alert_name}")
                    sys.exit(1)
       except KeyError:
           pass          

       # Check technique is not deprecated
       try:
           if mitre_mapping[technique_id]["deprecated"]:
               print(f"[!] ERROR: Deprecated MITRE technique ID [{technique_id}] in file <{file}>")
               sys.exit(1)
       except KeyError:
           pass