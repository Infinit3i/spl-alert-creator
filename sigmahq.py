import yaml
import os
import requests
from bs4 import BeautifulSoup
from datetime import datetime

def fetch_sigma_repo(github_url, local_dir):
    """Clone or download the entire Sigma repository."""
    command = f"git clone {github_url} {local_dir}" if not os.path.exists(local_dir) else f"git -C {local_dir} pull"
    exit_code = os.system(command)
    if exit_code == 0:
        print(f"Sigma repository fetched and saved to {local_dir}")
    else:
        print(f"Failed to fetch Sigma repository. Command: {command}")

def search_sigma_files(local_dir, mitre_code):
    """Search all Sigma YAML files for a specific MITRE T-code."""
    matching_files = []
    t_code = f"T{mitre_code}"  # Ensure the input is formatted as T####

    print(f"Starting to search for T-code {t_code} in all files under {local_dir}...")
    for root, dirs, files in os.walk(local_dir):
        print(f"Searching directory: {root}")
        for file in files:
            if file.endswith('.yml'):
                file_path = os.path.join(root, file)
                print(f"Examining file: {file_path}")
                try:
                    with open(file_path, 'r') as f:
                        # Load all YAML documents in the file
                        documents = yaml.safe_load_all(f)
                        for doc in documents:
                            if doc:  # Ensure document is not None
                                tags = doc.get('tags', [])
                                if any(tag.lower() == f"attack.{t_code.lower()}" for tag in tags):
                                    print(f"Match found in file: {file_path}")
                                    matching_files.append(file_path)
                                    break
                except yaml.YAMLError as e:
                    print(f"Error parsing YAML file {file_path}: {e}")
    print(f"Finished searching. Total matching files: {len(matching_files)}")
    return list(set(matching_files))  # Remove duplicates

def fetch_mitre_technique_name(technique_id):
    """Fetch the MITRE technique name from the MITRE ATT&CK website."""
    technique_id = technique_id.upper()
    url = f"https://attack.mitre.org/techniques/{technique_id}/"
    try:
        response = requests.get(url)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, 'html.parser')
        h1_element = soup.find('h1')
        if h1_element:
            technique_name = h1_element.text.strip()
            print(f"Fetched technique name: {technique_name} for ID: {technique_id}")
            return technique_name
        else:
            print(f"Technique name not found in the page for ID: {technique_id}")
    except requests.exceptions.RequestException as e:
        print(f"Error fetching MITRE technique name for ID {technique_id}: {e}")
    return f"Technique {technique_id}"

def sigma_to_splunk_search(sigma_data):
    """Convert Sigma detection to a Splunk search query."""
    detection = sigma_data.get('detection', {})
    selection = detection.get('selection', {})
    filters = [key for key in detection.keys() if key.startswith('filter_')]

    # Process selection conditions
    conditions = []
    for key, value in selection.items():
        if isinstance(value, str):
            conditions.append(f"{key}='{value}'")
        elif isinstance(value, list):
            or_conditions = " OR ".join([f"{key}='{v}'" for v in value])
            conditions.append(f"({or_conditions})")

    # Process filters for NOT conditions
    not_conditions = []
    for filter_key in filters:
        filter_values = detection[filter_key]
        if isinstance(filter_values, dict):
            for sub_key, sub_values in filter_values.items():
                if isinstance(sub_values, str):
                    not_conditions.append(f"{sub_key}='{sub_values}'")
                elif isinstance(sub_values, list):
                    or_conditions = " OR ".join([f"{sub_key}='{v}'" for v in sub_values])
                    not_conditions.append(f"({or_conditions})")

    selection_condition = " AND ".join(conditions)
    not_condition = " OR ".join(not_conditions)

    # Combine conditions into a Splunk search query
    splunk_search = (
        f"`sysmon` AND (" + selection_condition + ")"
    )
    if not_condition:
        splunk_search += f" AND NOT ({not_condition})"

    return splunk_search

def parse_sigma_to_splunk(sigma_file, output_directory, mitre_code):
    """Convert a Sigma rule to a Splunk query and save it as a .txt alert."""
    # Ensure the output directory exists
    if not os.path.exists(output_directory):
        os.makedirs(output_directory)

    try:
        # Load the Sigma file
        with open(sigma_file, 'r') as f:
            documents = yaml.safe_load_all(f)  # Handle multiple YAML documents
            for sigma_data in documents:
                if sigma_data:  # Process only valid documents
                    description = sigma_data.get('description', 'No description available')
                    first_sentence = description.split('.')[0] if description else ''
                    tags = sigma_data.get('tags', [])
                    priority = sigma_data.get('level', 'medium').capitalize()

                    # Extract MITRE ATT&CK details
                    mitre_categories = []
                    mitre_technique_id = f"T{mitre_code}"  # Use user-specified T-code
                    mitre_technique = fetch_mitre_technique_name(mitre_technique_id)
                    mitre_subtechnique_id = ""
                    mitre_subtechnique = ""

                    mitre_category = "_".join(mitre_categories)

                    # Convert Sigma detection to Splunk search
                    splunk_search = sigma_to_splunk_search(sigma_data)

                    # Set metadata
                    creator = "Cpl Iverson"
                    last_modify_date = datetime.now().strftime("%Y-%m-%d")
                    mitre_version = "v16"
                    alert_link = sigma_file.replace(local_sigma_repo, "https://github.com/SigmaHQ/sigma/tree/master").replace(os.sep, "/")

                    # Construct Splunk query
                    splunk_query = f"""`indextime`  {splunk_search}
| eval hash_sha256=lower(hash_sha256),
hunting_trigger="{first_sentence}",
mitre_category="{mitre_category}",
mitre_technique="{mitre_technique}",
mitre_technique_id="{mitre_technique_id}",
mitre_subtechnique="{mitre_subtechnique}",
mitre_subtechnique_id="{mitre_subtechnique_id}",
apt="",
alert_link="{alert_link}",
creator="{creator}",
upload_date="{last_modify_date}",
last_modify_date="{last_modify_date}",
mitre_version="{mitre_version}",
priority="{priority}"
| `process_create_whitelist`
| eval indextime = _indextime
| convert ctime(indextime)
| table _time indextime event_description hash_sha256 host_fqdn user_name original_file_name process_path process_guid process_parent_path process_id process_parent_id process_command_line process_parent_command_line process_parent_guid mitre_category mitre_technique mitre_technique_id hunting_trigger mitre_subtechnique mitre_subtechnique_id apt alert_link creator upload_date last_modify_date mitre_version priority
| collect `jarvis_index`
"""

                    # Create the alert file
                    sigma_filename = os.path.basename(sigma_file).replace('.yml', '')
                    output_filename = f"[{mitre_technique_id}] {sigma_filename}.txt"
                    output_path = os.path.join(output_directory, output_filename)

                    with open(output_path, 'w') as f:
                        f.write(splunk_query)

                    print(f"Alert file created: {output_path}")
    except Exception as e:
        print(f"Error processing file {sigma_file}: {e}")

# Main logic
if __name__ == "__main__":
    github_url = "https://github.com/SigmaHQ/sigma.git"
    local_sigma_repo = "./SigmaHQ"
    output_directory = "./Sigma-T-Code-Alerts"

    fetch_sigma_repo(github_url, local_sigma_repo)

    mitre_code = input("Enter the MITRE T-code (e.g., 1102, 1059): ").strip()

    matching_files = search_sigma_files(local_sigma_repo, mitre_code)

    if matching_files:
        print(f"Found {len(matching_files)} matching Sigma files:")
        for file in matching_files:
            parse_sigma_to_splunk(file, output_directory, mitre_code)
    else:
        print(f"No Sigma files found matching T-code {mitre_code}.")