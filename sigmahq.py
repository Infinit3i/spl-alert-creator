import yaml
import os
import sys
import requests
from bs4 import BeautifulSoup
from datetime import datetime

def fetch_mitre_details(technique_id, subtechnique_id=None):
    """Fetch the MITRE details (technique name, category, sub-technique, etc.) from the MITRE ATT&CK website."""
    # Determine the URL based on whether a sub-technique is provided
    if subtechnique_id:
        url = f"https://attack.mitre.org/techniques/{technique_id}/{subtechnique_id.split('.')[1]}/"
    else:
        url = f"https://attack.mitre.org/techniques/{technique_id}/"

    try:
        response = requests.get(url)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, "html.parser")

        # Extract technique name
        try:
            raw_name = soup.find("h1", {"id": ""}).text.strip()
            if ":" in raw_name:
                technique_name, subtechnique_name = map(str.strip, raw_name.split(":", 1))
            else:
                technique_name = raw_name
                subtechnique_name = ""
        except AttributeError:
            technique_name = "Unknown"
            subtechnique_name = ""

        # Extract category (tactic)
        try:
            tactic_section = soup.find("div", {"id": "card-tactics"})
            if tactic_section:
                tactic_link = tactic_section.find("a")
                mitre_category = tactic_link.text.strip().replace(" ", "_") if tactic_link else "Unknown"
            else:
                mitre_category = "Unknown"
        except AttributeError:
            mitre_category = "Unknown"

        return {
            "technique_name": technique_name,
            "mitre_category": mitre_category,
            "subtechnique_name": subtechnique_name,
        }

    except requests.exceptions.RequestException as e:
        print(f"Error fetching MITRE details for ID {technique_id}: {e}")
        return {
            "technique_name": f"Technique {technique_id}",
            "mitre_category": "Unknown",
            "subtechnique_name": "",
        }

def sigma_to_splunk_search(detection):
    """Convert Sigma detection rules into a Splunk search query."""
    conditions = []
    not_conditions = []

    for key, value in detection.items():
        if isinstance(value, dict):
            for sub_key, sub_value in value.items():
                if isinstance(sub_value, str):
                    conditions.append(f'{sub_key}="{sub_value}"')
                elif isinstance(sub_value, list):
                    or_conditions = " OR ".join([f'{sub_key}="{v}"' for v in sub_value])
                    conditions.append(f"({or_conditions})")
        elif isinstance(value, str):
            conditions.append(f'{key}="{value}"')
        elif isinstance(value, list):
            or_conditions = " OR ".join([f'{key}="{v}"' for v in value])
            conditions.append(f"({or_conditions})")

    condition_str = " AND ".join(conditions)
    not_condition_str = " OR ".join(not_conditions)
    
    if not_condition_str:
        return f"({condition_str}) AND NOT ({not_condition_str})"
    return condition_str

def format_field(field_values):
    """
    Format field values based on whether they are single or multiple.

    :param field_values: A list of field values.
    :return: Formatted string for single or mvappend for multiple.
    """
    if len(field_values) > 1:
        return f'mvappend("{'","'.join(field_values)}")'
    elif field_values:
        return f'"{field_values[0]}"'
    return '""'  # Return empty string if no values

def extract_fields_from_sigma(sigma_file):
    """Extract fields from a Sigma YAML file."""
    try:
        with open(sigma_file, 'r') as f:
            sigma_data = yaml.safe_load(f)

            # Extract description and tags
            description = sigma_data.get('description', 'No description available')
            tags = sigma_data.get('tags', [])
            detection = sigma_data.get('detection', {})
            priority = sigma_data.get('level', 'medium').lower()

            # Detect MITRE Technique ID from tags
            mitre_code = None
            mitre_subcode = None
            for tag in tags:
                if tag.startswith("attack.t"):
                    parts = tag.split('attack.t')[1].split('.')
                    mitre_code = parts[0].upper()  # Extract main technique ID
                    if len(parts) > 1:
                        mitre_subcode = '.'.join(parts).upper()  # Extract sub-technique ID
                    break

            if not mitre_code:
                print(f"Warning: No MITRE Technique ID found in tags for {sigma_file}. Using default placeholder.")
                mitre_code = "0000"

            mitre_technique_id = f"T{mitre_code}"
            mitre_subtechnique_id = f"T{mitre_subcode}" if mitre_subcode else ""  # Ensure proper format

            # Fetch technique and sub-technique details
            mitre_details = fetch_mitre_details(mitre_technique_id, mitre_subtechnique_id)
            mitre_technique = mitre_details["technique_name"]
            mitre_category = mitre_details["mitre_category"]
            mitre_subtechnique = mitre_details["subtechnique_name"]

            splunk_search = sigma_to_splunk_search(detection)

            return {
                "description": description,
                "tags": tags,
                "priority": priority,
                "splunk_search": splunk_search,
                "mitre_technique_id": mitre_technique_id,
                "mitre_technique": mitre_technique,
                "mitre_category": mitre_category,
                "mitre_subtechnique_id": mitre_subtechnique_id,
                "mitre_subtechnique": mitre_subtechnique,
                "alert_link": f"https://github.com/SigmaHQ/sigma/blob/master/{os.path.basename(sigma_file)}",
                "upload_date": datetime.now().strftime("%Y-%m-%d"),
                "last_modify_date": datetime.now().strftime("%Y-%m-%d"),
                "mitre_version": "v16",
                "creator": "Cpl Iverson",
            }
    except Exception as e:
        print(f"Error reading file {sigma_file}: {e}")
        return None

def create_alert_file(sigma_file, output_directory, fields):
    """Create an alert file based on extracted fields."""
    if not os.path.exists(output_directory):
        os.makedirs(output_directory)

    try:
        # Construct Splunk alert query
        first_sentence = fields["description"].split('.')[0]
        alert_content = f"""`indextime`  {fields['splunk_search']}
| eval hash_sha256=lower(hash_sha256),
hunting_trigger="{first_sentence}",
mitre_category={format_field([fields['mitre_category']])},
mitre_technique={format_field([fields['mitre_technique']])},
mitre_technique_id={format_field([fields['mitre_technique_id']])},
mitre_subtechnique={format_field([fields['mitre_subtechnique']])},
mitre_subtechnique_id={format_field([fields['mitre_subtechnique_id']])},
apt={format_field([])},
alert_link="{fields['alert_link']}",
creator="{fields['creator']}",
upload_date="{fields['upload_date']}",
last_modify_date="{fields['last_modify_date']}",
mitre_version="{fields['mitre_version']}",
priority="{fields['priority']}"
| `process_create_whitelist`
| eval indextime = _indextime
| convert ctime(indextime)
| table _time indextime event_description hash_sha256 host_fqdn user_name original_file_name process_path process_guid process_parent_path process_id process_parent_id process_command_line process_parent_command_line process_parent_guid mitre_category mitre_technique mitre_technique_id hunting_trigger mitre_subtechnique mitre_subtechnique_id apt alert_link creator upload_date last_modify_date mitre_version priority
| collect `jarvis_index`
"""

        # Write to alert file
        sigma_filename = os.path.basename(sigma_file).replace('.yml', '')
        output_filename = f"[{fields['mitre_technique_id']}] {sigma_filename}.txt"
        output_path = os.path.join(output_directory, output_filename)

        with open(output_path, 'w') as alert_file:
            alert_file.write(alert_content)
        print(f"Alert file created: {output_path}")
    except Exception as e:
        print(f"Error creating alert file for {sigma_file}: {e}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 sigmahq.py <sigma_file_path>")
        sys.exit(1)

    sigma_file_path = sys.argv[1]
    output_dir = "./SIGMAHQ_Alerts"

    fields = extract_fields_from_sigma(sigma_file_path)
    if fields:
        create_alert_file(sigma_file_path, output_dir, fields)
