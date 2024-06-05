import os
import glob
import sys
import yaml

# Add the Sigma library path
sys.path.insert(0, os.path.abspath('sigma'))

from sigma.rule import SigmaRule
from sigma.backends.microsoft365defender import Microsoft365DefenderBackend
from sigma.pipelines.microsoft365defender import microsoft_365_defender_pipeline

# Path to Sigma rules
# Verify the current directory
home_dir = os.path.expanduser('~')
path = os.path.join(home_dir, 'sigma', 'rules', '*', '*')
file_pattern = os.path.join(path, '*.yml')
file_list_a = glob.glob(file_pattern)
# print(file_list_a)

# Function to convert YAML dict to string with custom string style
def convert_to_string(yaml_dict):
    yaml.SafeDumper.org_represent_str = yaml.SafeDumper.represent_str

    def repr_str(dumper, data):
        if '\n' in data:
            return dumper.represent_scalar('tag:yaml.org,2002:str', data, style='|')
        return dumper.org_represent_str(data)

    yaml.add_representer(str, repr_str, Dumper=yaml.SafeDumper)
    yaml_str = yaml.dump(yaml_dict, default_flow_style=False, Dumper=yaml.SafeDumper)
    return yaml_str

# Ensure the output directory exists
os.makedirs('KQL', exist_ok=True)
# Process each YAML file
for yml in file_list_a:
    with open(yml) as yaml_file:
        try:
            yaml_contents = yaml.safe_load(yaml_file)
            sigma_rule = SigmaRule.from_yaml(convert_to_string(yaml_contents))
            print(yaml_contents)
            m365def_backend = Microsoft365DefenderBackend()

            pipeline = microsoft_365_defender_pipeline()
            pipeline.apply(sigma_rule)

            # print(sigma_rule.title + " KQL Query: \n")
            kql_query = m365def_backend.convert_rule(sigma_rule)[0]
            # print(kql_query)
            print("\n \n ")

            with open('KQL/' + sigma_rule.title.replace(' ', '_') + '.kql', 'w') as kql_file:
                kql_file.write(f'// Title: {yaml_contents.get("title", "")}\n')
                kql_file.write(f'// ID: {yaml_contents.get("id", "")}\n')
                kql_file.write(f'// Author: {yaml_contents.get("author", "")}\n')
                kql_file.write(f'// Date: {yaml_contents.get("date", "")}\n')
                kql_file.write(f'// Level: {yaml_contents.get("level", "")}\n')
                kql_file.write(f'// Description: {yaml_contents.get("description", "")}\n')
                kql_file.write(f'// Status: {yaml_contents.get("status", "")}\n')
                kql_file.write(f'// Date: {yaml_contents.get("date", "")}\n')
                kql_file.write(f'// Modified: {yaml_contents.get("modified", "")}\n')
                kql_file.write(f'// Logsource Category: {yaml_contents.get("logsource", {}).get("category", "")}\n')
                kql_file.write(f'// Logsource Product: {yaml_contents.get("logsource", {}).get("product", "")}\n')
                tags = yaml_contents.get("tags", [])
                kql_file.write(f'// Tags: {", ".join(tags) if tags else ""}\n')
                kql_file.write(kql_query)
            print(f'{sigma_rule.title} rule Converted successfully')
        except Exception as e:
            print(sigma_rule.title + " KQL Query: \n")
            print(f'SigmaTransformationError: Rule category not yet supported by the Microsoft 365 Defender Sigma backend. {str(e)}')

