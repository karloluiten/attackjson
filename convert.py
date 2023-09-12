#!/usr/bin/env python3
import json

# The file we want to read
# Get first via
#  wget -O source.json https://github.com/mitre/cti/blob/master/enterprise-attack/enterprise-attack.json
json_file = "source.json"

# Parse the file, get data
with open(json_file) as json_data:
    data = json.load(json_data)

# Empty lists for results
tactics = []
attacks = []

# I can't get the ordering from the json (PR welcome)
tactic_order = [
    'Reconnaissance',
    'Resource Development',
    'Initial Access',
    'Execution',
    'Persistence',
    'Privilege Escalation',
    'Defense Evasion',
    'Credential Access',
    'Discovery',
    'Lateral Movement',
    'Collection',
    'Command and Control',
    'Exfiltration',
    'Impact',
    ]

# Go through all objects
for data_object in data['objects']:

    # Handle tactics
    if data_object['type'] == 'x-mitre-tactic':
        tactics.append(dict(
            type="tactic",
            index=tactic_order.index(data_object['name']),
            name=data_object['name'],
            shortname=data_object['x_mitre_shortname'],
            external_id=data_object['external_references'][0]['external_id'],
            url=data_object['external_references'][0]['url'],
        ))

    # Handle attacks
    if data_object['type'] == 'attack-pattern':
        for kill_chain_phase in data_object['kill_chain_phases']:
            if kill_chain_phase['kill_chain_name'] != 'mitre-attack':
                continue
            
            if data_object['x_mitre_is_subtechnique']:
                parent = data_object['external_references'][0]['external_id'].split('.')[0]
            else:
                parent = 'False'

            attacks.append(dict(
                type="attack",
                phase_name=kill_chain_phase['phase_name'],
                name=data_object['name'],
                parent=parent,
                external_id=data_object['external_references'][0]['external_id'],
                url=data_object['external_references'][0]['url'],
            ))

# Write files
with open('out_tactics.json', 'w') as fp:
    json.dump(tactics, fp, indent=4, sort_keys=True)

with open('out_attacks.json', 'w') as fp:
    json.dump(attacks, fp, indent=4, sort_keys=True)
