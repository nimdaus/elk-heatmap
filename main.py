import mitreattack.navlayers as navlayers
import requests
import tempfile
import time
import json
import os
from requests.adapters import HTTPAdapter
from os.path import join, dirname
from collections import Counter
from dotenv import load_dotenv
from urllib3 import Retry

dotenv_path = join(dirname(__file__), '.env')
load_dotenv(dotenv_path)

retry_strategy = Retry(
    total=3,
    status_forcelist=[429, 500, 502, 503, 504],
    allowed_methods=["GET"],
    backoff_factor=os.getenv('BACKOFF', 15)
)
Retry.BACKOFF_MAX = int(os.getenv('BACKOFF_MAX', 60))
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

def rev_score(score, max):
    return (max + 1) - score

try:
    elk_request = http.get(elk_base_route + elk_rule_route + elk_rule_filter + elk_per_page, headers=elk_headers)
    elk_request.raise_for_status()
    elk_response = elk_request.json()
    total_pages = (int(elk_response["total"]/elk_response["perPage"]) + (elk_response["total"] % elk_response["perPage"]>0))
    all_elk_responses = elk_response["data"]
    for page in range(2, total_pages+1):
        elk_request = http.get(elk_base_route + elk_rule_route + elk_rule_filter + elk_per_page + f"&page={page}", headers=elk_headers)
        elk_request.raise_for_status()
        elk_response = elk_request.json()
        all_elk_responses.extend(elk_response["data"])
except requests.exceptions.HTTPError as e:
    print (e.response.text)
    exit()

all_elk_responses_number = len(all_elk_responses)
print(f"{all_elk_responses_number} Detection Rules")

rule_tag_dict = {}
for rule in all_elk_responses:
    if rule['tags']:
        for tag in rule['tags']:
            if tag[:(len(os.getenv('TAG_PREFIX')))].lower() == f"{os.getenv('TAG_PREFIX').lower()}":
                priority_value = int(tag[len(os.getenv('TAG_PREFIX'))].rstrip())
                rule_tag_dict[f"{rule['id']}"] = priority_value
maximum = max(rule_tag_dict.values())
count = Counter(rule_tag_dict.values())

for key, value in sorted(count.items()):
    print(f"Priority {key} = {value} [{(value/all_elk_responses_number):.1%}]")

new_techniques = []
for rule in all_elk_responses:
    if rule_tag_dict[f"{rule['id']}"]:
        score_relative = int(round((rev_score(score=rule_tag_dict.get(f"{rule['id']}"), max=maximum)/maximum)*100))
    for threat in rule['threat']:
        if threat['tactic'] and threat['tactic']['name']:
            for technique in threat['technique']:
                comment_extracted = ""
                if rule['references']:
                    comment_extracted = "\n\n".join([str(reference) for reference in rule['references']])
                add_rule(techniqueID=technique['id'], tactic=str(threat['tactic']['name']).lower().replace(" ","-"), comment=comment_extracted, score=score_relative)
                if "subtechnique" in technique.keys():
                    for subtechnique in technique['subtechnique']:
                        add_rule(techniqueID=subtechnique['id'], tactic=str(threat['tactic']['name']).lower().replace(" ","-"), comment=comment_extracted, score=score_relative)

navigator_layer = navlayers.Layer()
navigator_layer.from_dict(
    dict(
        name=f"{os.getenv('HEATMAP_NAME')}",
        domain="enterprise-attack",
        showTacticRowBackground=True,
        tacticRowBackground=f"{os.getenv('TACTIC_ROW_BACKGROUND')}",
        selectTechniquesAcrossTactics=True,
        selectSubtechniquesWithParent=False,
    )
)
navigator_layer.layer.versions = dict(layer=f"{os.getenv('LAYER_VERSION')}", navigator=f"{os.getenv('NAVIGATOR_VERSION')}")
navigator_layer.layer.description = f"Heatmap based on rules enabled on ELK Cluster at {elk_base_route}"
navigator_layer.layer.filters = dict(platforms=['Windows', 'macOS', 'Office 365'])
navigator_layer.layer.sorting = 0
navigator_layer.layer.layout = dict(
    layout="side",
    showID=True,
    showName=True,
    showAggregateScores=True,
    countUnscored=True,
    aggregateFunction="average"
)
navigator_layer.layer.hideDisabled = True
navigator_layer.layer.gradient = dict(
    minValue=0,
    maxValue=100,
    colors=json.loads(os.environ['DESC_GRADIENT'])
)
legend_items = []
for iteration_no, hex_color in enumerate(json.loads(os.environ['DESC_GRADIENT'])):
    legend_items.append(dict(label=f"{int(round((rev_score(score=iteration_no + 1, max=len(json.loads(os.environ['DESC_GRADIENT']))))/len(json.loads(os.environ['DESC_GRADIENT']))*100))}%", color=f'{hex_color}'))
navigator_layer.layer.legendItems = legend_items

navigator_layer.layer.metadata = [
    dict(name='Generated', value=f"{time.strftime('%Y%m%d')}"),
    dict(name='Usage', value=f"INTERNAL ONLY")
]
navigator_layer.layer.techniques = new_techniques

if os.getenv("DEBUG", 'False').lower() in ('true', '1', 't'):
    f = f"{dirname(__file__)}/heatmap-{time.strftime('%Y%m%d')}.json"
    navigator_layer.to_file(f)
else:
    with tempfile.TemporaryDirectory() as dir:
        f = f"{dir}/heatmap-{time.strftime('%Y%m%d')}.json"
        navigator_layer.to_file(f)
        time.sleep(1)