import os
import requests
from bs4 import BeautifulSoup
from datetime import datetime

def get_mitre_technique_details(technique_id):
    """
    Fetches details of a MITRE ATT&CK technique.
    """
    if "." in technique_id:
        base_id, sub_id = technique_id.split(".")
        url = f"https://attack.mitre.org/techniques/T{base_id}/{sub_id.zfill(3)}/"
    else:
        url = f"https://attack.mitre.org/techniques/T{technique_id}/"
    
    response = requests.get(url)
    if response.status_code != 200:
        return {"error": f"Failed to fetch details for Technique ID {technique_id}"}

    soup = BeautifulSoup(response.text, "html.parser")
    try:
        raw_name = soup.find("h1", {"id": ""}).text.strip()
        if ":" in raw_name:
            name, subtechnique = map(str.strip, raw_name.split(":", 1))
        else:
            name = raw_name
            subtechnique = ""
    except AttributeError:
        name = "Unknown"
        subtechnique = ""

    try:
        tactic_section = soup.find("div", {"class": "card-tactics"})
        tactics = [tactic.text.strip() for tactic in tactic_section.find_all("a")]
    except AttributeError:
        tactics = []

    try:
        hunting_trigger_section = soup.find("div", {"class": "description-body"})
        full_text = hunting_trigger_section.get_text(separator=" ").strip()
        hunting_trigger = full_text.split(".")[0].strip() + "."
    except AttributeError:
        hunting_trigger = "Description not found."

    try:
        tactic_section = soup.find("div", {"id": "card-tactics"})
        if tactic_section:
            tactic_link = tactic_section.find("a")
            mitre_category = tactic_link.text.strip() if tactic_link else "Unknown"
        else:
            mitre_category = "Unknown"
    except AttributeError:
        mitre_category = "Unknown"

    analytics_queries = []
    try:
        for analytic in soup.find_all("p"):
            if "Analytic" in analytic.text:
                query_text = analytic.find_next("code")
                if query_text:
                    query_text_transformed = query_text.text.strip()

                    # Replace sourcetypes with more readable macros
                    if "sourcetype=WinEventLog:Microsoft-Windows-Sysmon/Operational" in query_text_transformed:
                        query_text_transformed = query_text_transformed.replace("sourcetype=WinEventLog:Microsoft-Windows-Sysmon/Operational", "`sysmon`")
                    if "sourcetype=WinEventLog:Security" in query_text_transformed:
                        query_text_transformed = query_text_transformed.replace("sourcetype=WinEventLog:Security", "`windows-security`")

                    # Remove "Analytic # -" prefix from description
                    description = analytic.text.strip()
                    if description.startswith("Analytic"):
                        description = description.split("-", 1)[-1].strip()

                    # Append transformed query
                    analytics_queries.append({
                        "description": description,
                        "query": query_text_transformed
                    })
    except AttributeError:
        analytics_queries = []


    apts = extract_unique_apts(response.text)
    return {
        "ID": f"T{technique_id}",
        "Name": name,
        "Subtechnique": subtechnique,
        "Tactic": tactics,
        "Hunting Trigger": hunting_trigger,
        "MITRE Category": mitre_category,
        "Analytics": analytics_queries,
        "APTs": apts,
        "URL": url,
        "Technique ID": f"T{technique_id.split('.')[0]}",
        "Subtechnique ID": f"T{technique_id}" if "." in technique_id else ""
    }
    
def extract_unique_apts(html):
    soup = BeautifulSoup(html, "html.parser")
    apts = set()
    try:
        table = soup.find("div", {"class": "tables-mobile"}).find("table")
        rows = table.find("tbody").find_all("tr")
        for row in rows:
            columns = row.find_all("td")
            if len(columns) > 2:
                apt_id = columns[0].text.strip()
                apt_name = columns[1].text.strip()
                if apt_id.startswith("G") and len(apt_id) == 5 and apt_id[1:].isdigit():
                    apts.add(apt_name)
    except AttributeError:
        return []
    return sorted(apts)

def save_analytics_to_files(technique_id, details, today_date):
    """Save analytics queries to files under MITRE_Alerts folder."""
    base_folder = "MITRE_Alerts"
    os.makedirs(base_folder, exist_ok=True)

    mitre_category = details["MITRE Category"]
    if mitre_category == "Unknown":
        print(f"Skipping analytics save for Technique ID {technique_id} due to unknown category.")
        return  # Skip saving if category is unknown

    category_folder = os.path.join(base_folder, mitre_category.replace(", ", "_"))
    os.makedirs(category_folder, exist_ok=True)

    
    apts = '","'.join(details["APTs"])

    for index, analytic in enumerate(details["Analytics"], start=1):
        file_title = f"[T{technique_id}] {details['Name']}_Analytic_{index}.txt"
        file_path = os.path.join(category_folder, file_title)

        with open(file_path, "w") as file:
            file.write(f"`indextime` {analytic['query']}\n")
            file.write(f"| eval hash_sha256=lower(hash_sha256),\n")
            file.write(f'hunting_trigger="{analytic["description"]}",\n')
            file.write(f'mitre_category="{details["MITRE Category"]}",\n')
            file.write(f'mitre_technique="{details["Name"]}",\n')
            file.write(f'mitre_technique_id="{details.get("Technique ID", "")}",\n')
            file.write(f'mitre_subtechnique="{details.get("Subtechnique", "")}",\n')
            file.write(f'mitre_subtechnique_id="{details.get("Subtechnique ID", "")}",\n')
            file.write(f'apt=mvappend("{apts}"),\n')
            file.write(f'mitre_link="{details["URL"]}",\n')
            file.write(f'creator="Cpl Iverson",\n')
            file.write(f'upload_date="{today_date}",\n')
            file.write(f'last_modify_date="{today_date}",\n')
            file.write(f'mitre_version="v16",\n')
            file.write(f'priority="medium"\n')
            file.write(f"| `process_create_whitelist`\n")
            file.write(f"| eval indextime = _indextime\n")
            file.write(f"| convert ctime(indextime)\n")
            file.write(f"| table _time indextime event_description hash_sha256 host_fqdn user_name original_file_name process_path process_guid process_parent_path process_id process_parent_id process_command_line process_parent_command_line process_parent_guid mitre_category mitre_technique mitre_technique_id hunting_trigger mitre_subtechnique mitre_subtechnique_id apt mitre_link creator upload_date last_modify_date mitre_version priority\n")
            file.write(f"| collect `jarvis_index`\n")

    print(f"Analytics saved in folder: {category_folder}")

if __name__ == "__main__":
    today_date = datetime.now().strftime("%Y-%m-%d")
    technique_ids = input("Enter the technique IDs separated by spaces (e.g., 1059 1059.001 1059.002): ").strip().split()
    for technique_id in technique_ids:
        details = get_mitre_technique_details(technique_id)
        if "error" in details:
            print(f"Error for {technique_id}: {details['error']}")
        else:
            if details["Analytics"]:
                save_analytics_to_files(technique_id, details, today_date)
            else:
                print(f"No Analytics Queries Found for {technique_id}")
