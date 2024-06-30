import os
import time
import requests
import yaml
#from github import Github, GithubException
from sigma.rule import SigmaRule
from sigma.backends.microsoft365defender import Microsoft365DefenderBackend
from sigma.pipelines.microsoft365defender import microsoft_365_defender_pipeline
from dotenv import load_dotenv

load_dotenv()
SUPER_SECRET_TOKEN = os.getenv('SUPER_SECRET_TOKEN')

#github_token = os.getenv('SUPER_SECRET_TOKEN')  # This will fetch the token from the .env file
#github_token = Github.SUPER_SECRET_TOKEN  # This will fetch the token from the .env file

# Initialize GitHub API with your token
# github_token = os.getenv('SUPER_SECRET_TOKEN')  # Add your GitHub token as a secret in GitHub repository settings

# def get_github_repo_with_retries(repo_name, max_retries=5, retry_delay=10):
#    retries = 0
#    while retries < max_retries:
#        try:
#            g = Github(github_token)
#            return g.get_repo(repo_name)
#        except (requests.exceptions.ConnectionError, GithubException) as e:
#            print(f"Error accessing GitHub API: {e}")
#            print(f"Retrying in {retry_delay} seconds...")
#            retries += 1
#            time.sleep(retry_delay)
#    raise Exception(f"Failed to access GitHub API after {max_retries} retries")

# repo = get_github_repo_with_retries('SigmaHQ/sigma')

# Load the last known commit SHA
commit_sha_file = 'last_commit_sha.txt'

def get_last_commit_sha():
    if os.path.exists(commit_sha_file):
        with open(commit_sha_file, 'r') as file:
            return file.read().strip()
    return None

def save_last_commit_sha(sha):
    with open(commit_sha_file, 'w') as file:
        file.write(sha)

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

# Function to download and process Sigma rules
def download_sigma_rules(repo='SigmaHQ/sigma', path='rules/windows'):
    headers = {
        'Accept': 'application/vnd.github.v3+json',
        'Authorization': f'token {SUPER_SECRET_TOKEN}'

    }
    url = f'https://api.github.com/repos/{repo}/contents/{path}'
    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        contents = response.json()
        for file in contents:
            if file['type'] == 'dir':
                download_sigma_rules(repo, file['path'])  # Recursively process directories
            elif file['name'].endswith('.yml'):
                download_url = file['download_url']
                print(file['name'])

                process_yaml_file(download_url)
    else:
        print(f"Failed to fetch contents from GitHub API. Status code: {response.status_code}")

def process_techniques(techniques_list):
    processed_techniques = set()
    for technique in techniques_list:
        main_technique = technique.split('.')[0].replace('t', 'T', 1)
        processed_techniques.add(main_technique)
    return sorted(processed_techniques)

# Function to process each YAML file
def process_yaml_file(download_url):
    response = requests.get(download_url)
    if response.status_code == 200:
        try:
            yaml_contents = yaml.safe_load(response.text)
            sigma_rule = SigmaRule.from_yaml(convert_to_string(yaml_contents))
            print(yaml_contents)
            m365def_backend = Microsoft365DefenderBackend()

            pipeline = microsoft_365_defender_pipeline()
            pipeline.apply(sigma_rule)
            print("HEEEEEEEEEEEEY")
            kql_query = m365def_backend.convert_rule(sigma_rule)[0]
            print("\n \n ")

            # Initialize sets to hold unique tactics and techniques
            tactics = set()
            techniques = set()

            # Separate tags into tactics and techniques
            tags = yaml_contents.get('tags', [])
            for tag in tags:
                if (parts := tag.split('.')) and tag.startswith('attack.'):
                    if len(parts) == 2 and not parts[1].startswith('t'):
                        # Transform the tactic to capitalize and replace underscores with spaces
                        transformed_tactic = ' '.join(word.capitalize() for word in parts[1].split('_'))
                        tactics.add(transformed_tactic)
                    elif len(parts) >= 2 and parts[1].startswith('t'):
                        techniques.add(parts[1])

            # Convert sets to sorted lists and process techniques
            sorted_tactics = sorted(tactics)
            sorted_techniques = process_techniques(techniques)
            print(sorted_techniques)
            yaml_content = {
                'name': yaml_contents.get("title", ""),
                'id': yaml_contents.get("id", ""),
                'author': yaml_contents.get("author", ""),
                'date': yaml_contents.get("date", ""),
                'severity': yaml_contents.get("level", ""),
                'description': yaml_contents.get("description", ""),
                'status': yaml_contents.get("status", ""),
                'modified': yaml_contents.get("modified", ""),
                'logsource': {
                    'category': yaml_contents.get("logsource", {}).get("category", ""),
                    'product': yaml_contents.get("logsource", {}).get("product", "")
                },
                'tactics': sorted_tactics,
                'relevantTechniques': sorted_techniques,
                'query': kql_query,
                'eventGroupingSettings': {
                    'aggregationKind': 'SingleAlert'
                },
                'queryFrequency': 'P1D',
                'queryPeriod': 'P1D',
                'enabled': True,
                'entityMappings': None,
                'sentinelEntitiesMappings': None,
                'triggerThreshold': 0,
                'suppressionDuration': 'PT5H',
                'suppressionEnabled': False,
                'triggerOperator': 'GreaterThan',
                'kind': 'Scheduled'
            }
            print(f'fdfdf {yaml_content}')


            # Write the dictionary to a YAML file
            output_file = f'KQL/{sigma_rule.title.replace(" ", "_")}.yaml'
            with open(output_file, 'w') as yaml_file:
                yaml.dump(yaml_content, yaml_file, sort_keys=False, default_flow_style=False)

            print(f'{sigma_rule.title} rule converted successfully')
        except Exception as e:
            print(f'SigmaTransformationError: Rule category not yet supported by the Microsoft 365 Defender Sigma backend. {str(e)}')
    else:
        print(f"Failed to download YAML file. Status code: {response.status_code}")

def fetch_commits_with_retries(max_retries=5, retry_delay=10):
    retries = 0
    while retries < max_retries:
        try:
            headers = {
                'Accept': 'application/vnd.github.v3+json',
                'Authorization': f'token {SUPER_SECRET_TOKEN}'

            }
            response = requests.get(f'https://api.github.com/repos/SigmaHQ/sigma/commits', headers=headers)
            response.raise_for_status()  # Raise HTTPError for bad responses
            return response.json()
        except requests.exceptions.RequestException as e:
            print(f"Error accessing GitHub API: {e}")
            print(f"Retrying in {retry_delay} seconds...")
            retries += 1
            time.sleep(retry_delay)
    raise Exception(f"Failed to access GitHub API after {max_retries} retries")

def main():
    try:
        commits_data = fetch_commits_with_retries()

        if not commits_data:
            print("No commits found for the specified path.")
            return

        latest_commit = commits_data[0]
        last_commit_sha = get_last_commit_sha()

        if latest_commit['sha'] != last_commit_sha:
            print(f"New commit detected: {latest_commit['sha']}")
            download_sigma_rules()
            save_last_commit_sha(latest_commit['sha'])
        else:
            print("No new commits detected.")
    except IndexError:
        print("IndexError: List index out of range. Likely no commits found.")
    except Exception as e:
        print(f"Error accessing commits: {e}")

if __name__ == "__main__":
    main()
