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
path = os.path.join(home_dir, "Desktop", 'sigma', 'rules', '*', '*')
file_pattern = os.path.join(path, '*.yml')
file_list_a = glob.glob(file_pattern)

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

            kql_query = m365def_backend.convert_rule(sigma_rule)[0]
            print("\n \n ")

            # Initialize sets to hold unique tactics and techniques
            tactics = set()
            techniques = set()

            # Separate tags into tactics and techniques
            tags = yaml_contents.get('tags', [])
            for tag in tags:
                if tag.startswith('attack.'):
                    parts = tag.split('.')
                    if len(parts) == 2 and not parts[1].startswith('t'):
                        tactics.add(parts[1])
                    elif len(parts) == 3 and parts[1].startswith('t'):
                        techniques.add(f'{parts[1]}.{parts[2]}')
                    elif len(parts) == 2 and parts[1].startswith('t'):
                        techniques.add(parts[1])

            # Convert sets to sorted lists
            sorted_tactics = sorted(tactics)
            sorted_techniques = sorted(techniques)

            # Create a dictionary for the YAML content
            yaml_content = {
                'name': yaml_contents.get("title", ""),
                'id': yaml_contents.get("id", ""),
                'author': yaml_contents.get("author", ""),
                'date': yaml_contents.get("date", ""),
                'level': yaml_contents.get("level", ""),
                'description': yaml_contents.get("description", ""),
                'status': yaml_contents.get("status", ""),
                'modified': yaml_contents.get("modified", ""),
                'logsource': {
                    'category': yaml_contents.get("logsource", {}).get("category", ""),
                    'product': yaml_contents.get("logsource", {}).get("product", "")
                },
                'tactics': sorted_tactics,
                'relevantTechniques': sorted_techniques,
                'query': kql_query
            }

            # Write the dictionary to a YAML file
            output_file = f'KQL/{sigma_rule.title.replace(" ", "_")}.yaml'
            with open(output_file, 'w') as yaml_file:
                yaml.dump(yaml_content, yaml_file, sort_keys=False, default_flow_style=False)
            
            print(f'{sigma_rule.title} rule converted successfully')
        except Exception as e:
            print(f'SigmaTransformationError: Rule category not yet supported by the Microsoft 365 Defender Sigma backend. {str(e)}')