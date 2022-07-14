import os
from dotenv import load_dotenv
import requests
from requests.adapters import HTTPAdapter
from urllib3 import Retry
from os.path import join, dirname
import json
import time
# import mitreattack.navlayers as navlayers


dotenv_path = join(dirname(__file__), '.env')
load_dotenv(dotenv_path)

retry_strategy = Retry(
    total=3,
    status_forcelist=[429, 500, 502, 503, 504],
    allowed_methods=["GET"],
    backoff_factor=os.getenv('BACKOFF', 15)
)
Retry.BACKOFF_MAX = os.getenv('BACKOFF_MAX', 60)
adapter = HTTPAdapter(max_retries=retry_strategy)
http = requests.Session()
http.mount("https://", adapter)

elk_base_route = os.getenv('BASE_ROUTE')
elk_rule_route = os.getenv('ELK_ROUTE')
elk_rule_filter = os.getenv('ELK_FILTER')
elk_per_page = os.getenv('ELK_PER_PAGE')
elk_headers = {
    "Content-Type": "application/json;charset=UTF-8",
    "Authorization": f"ApiKey {os.getenv('ELK_KEY')}",
    "kbn-xsrf": "true"
    }

def add_rule(techniqueID, tactic, comment, score):
    rule = {
        "techniqueID": techniqueID,
        "tactic": tactic,
        "enabled": True,
        "comment": comment,
        "score": score
    }
    new_techniques.append(rule)
    return

elk_response = http.get(elk_base_route + elk_rule_route + elk_rule_filter + elk_per_page, headers=elk_headers).json()
total_pages = (int(elk_response["total"]/elk_response["perPage"]) + (elk_response["total"] % elk_response["perPage"]>0))
all_elk_responses = elk_response["data"]
for page in range(2, total_pages+1):
    elk_response = http.get(elk_base_route + elk_rule_route + elk_rule_filter + elk_per_page + f"&page={page}", headers=elk_headers).json()
    all_elk_responses.extend(elk_response["data"])

print(f"Found {len(all_elk_responses)} Detection Rules")
print("Forging Att&ck Heatmap")

with open("mitre_format.json", "r") as jsonFile:
    mitre_json = json.load(jsonFile)

count_1 = 0
count_2 = 0
count_3 = 0
count_4 = 0
count_5 = 0

score_max = 5
new_techniques = []
for rule in all_elk_responses:
    for threat in rule['threat']:
        if threat['tactic'] and threat['tactic']['name']:
            for technique in threat['technique']:
                score_relative = 0
                if rule['tags']:
                    for tag in rule['tags']:
                        if tag[:18] == "huntress-priority-":
                            score_value = int(tag[-1])
                            score_relative = int((score_value/score_max)*100)
                            if score_value == 1:
                                count_1 = count_1 + 1
                            if score_value == 2:
                                count_2 = count_2 + 1
                            if score_value == 3:
                                count_3 = count_3 + 1
                            if score_value == 4:
                                count_4 = count_4 + 1
                            if score_value == 5:
                                count_5 = count_5 + 1

                comment_extracted = ""
                if rule['references']:
                    comment_extracted = "\n\n".join([str(reference) for reference in rule['references']])
                add_rule(techniqueID=technique['id'], tactic=str(threat['tactic']['name']).lower().replace(" ","-"), comment=comment_extracted, score=score_relative)
                if "subtechnique" in technique.keys():
                    for subtechnique in technique['subtechnique']:
                        add_rule(techniqueID=subtechnique['id'], tactic=str(threat['tactic']['name']).lower().replace(" ","-"), comment=comment_extracted, score=score_relative)

mitre_json['techniques'] = new_techniques

print(f"Priority 1 Count = {count_1}")
print(f"Priority 2 Count = {count_2}")
print(f"Priority 3 Count = {count_3}")
print(f"Priority 4 Count = {count_4}")
print(f"Priority 5 Count = {count_5}")

with open(f"{time.strftime('%Y%m%d')}-heatmap.json", "w") as outfile:
    json.dump(mitre_json, outfile, indent=4)