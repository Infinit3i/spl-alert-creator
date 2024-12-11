import os
import requests
from bs4 import BeautifulSoup
from datetime import datetime

def get_mitre_technique_details(technique_id):
    """
    Fetches details of a MITRE ATT&CK technique.

    :param technique_id: A string representing the technique ID (e.g., T#### or T####.0##).
    :return: A dictionary with the technique's name, description, ID, category, and analytics.
    """
    # Ensure technique_id starts with "T" and matches the expected format
    if "." in technique_id:
        base_id, sub_id = technique_id.split(".")
        url = f"https://attack.mitre.org/techniques/T{base_id}/{sub_id.zfill(3)}/"
    else:
        url = f"https://attack.mitre.org/techniques/T{technique_id}/"
    
    response = requests.get(url)

    if response.status_code != 200:
        return {"error": f"Failed to fetch details for Technique ID {technique_id}"}

    soup = BeautifulSoup(response.text, "html.parser")
    
    # Extract technique name
    try:
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
    except AttributeError:
        name = "Unknown"
    
    # Extract tactics
    try:
        tactic_section = soup.find("div", {"class": "card-tactics"})
        tactics = [tactic.text.strip() for tactic in tactic_section.find_all("a")]
    except AttributeError:
        tactics = []
    
    # Extract the first sentence of the hunting trigger (description)
    try:
        hunting_trigger_section = soup.find("div", {"class": "description-body"})
        full_text = hunting_trigger_section.get_text(separator=" ").strip()
        hunting_trigger = full_text.split(".")[0].strip() + "."  # Get text up to the first period
        # Remove leading "Analytic # -" if present
        if hunting_trigger.startswith("Analytic"):
            hunting_trigger = hunting_trigger.split("-", 1)[-1].strip()
    except AttributeError:
        hunting_trigger = "Description not found."


    # Extract mitre category
    try:
        mitre_category_section = soup.find("div", {"class": "card-tactics"})
        mitre_categories = [category.text.strip() for category in mitre_category_section.find_all("a")]
        mitre_category = ", ".join(mitre_categories)  # Join multiple categories with a comma
    except AttributeError:
        mitre_category = "Unknown"
    
    # Extract analytics queries
    # Extract analytics queries
    analytics_queries = []
    try:
        for analytic in soup.find_all("p"):
            if "Analytic" in analytic.text:
                query_text = analytic.find_next("code")
                if query_text:
                    # Transform sourcetype strings
                    query_text_transformed = query_text.text.strip()
                    if "sourcetype=WinEventLog:Security" in query_text_transformed:
                        query_text_transformed = query_text_transformed.replace("sourcetype=WinEventLog:Security", "`windows-security`")
                    if "sourcetype=sysmon" in query_text_transformed:
                        query_text_transformed = query_text_transformed.replace("sourcetype=sysmon", "`sysmon`")
                    
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


    # Extract unique APTs
    apts = extract_unique_apts(response.text)
    

    # Return the details as a dictionary
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
        "Technique ID": f"T{technique_id.split('.')[0]}",  # Base technique ID (T####)
        "Subtechnique ID": f"T{technique_id}" if "." in technique_id else ""  # Subtechnique ID or blank
    }
    
def extract_unique_apts(html):
    """
    Extracts unique APT group names from the given HTML content, including only those where the first column starts with 'G####'.

    :param html: The HTML content of the page.
    :return: A sorted list of unique APT group names matching the criteria.
    """
    soup = BeautifulSoup(html, "html.parser")
    apts = set()  # Use a set to store unique names
    
    # Locate the table containing APT details
    try:
        table = soup.find("div", {"class": "tables-mobile"}).find("table")
        rows = table.find("tbody").find_all("tr")

        # Debugging: Check if rows are being detected
        print(f"Found {len(rows)} rows in the APT table.")

        # Extract the first column (ID) and second column (Name) for APT group names
        for row in rows:
            columns = row.find_all("td")
            if len(columns) > 2:  # Ensure the row has at least 3 columns (ID, Name, Description)
                apt_id = columns[0].text.strip()  # First column (ID)
                apt_name = columns[1].text.strip()  # Second column (Name)
                # Include only if the ID starts with 'G' and is followed by 4 digits
                if apt_id.startswith("G") and len(apt_id) == 5 and apt_id[1:].isdigit():
                    apts.add(apt_name)
                else:
                    print(f"Excluded APT: ID={apt_id}, Name={apt_name}")  # Debugging: Log excluded APTs

    except AttributeError:
        print("APT table not found or malformed HTML structure.")
        return []

    # Return sorted list of unique APT names
    return sorted(apts)




def save_analytics_to_files(technique_id, details, today_date):
    """
    Saves each analytic segment to a file in the appropriate MITRE category folder.

    :param technique_id: The MITRE technique ID.
    :param details: A dictionary with details about the technique.
    :param today_date: The current date to include in file content.
    """
    # Prepare the folder based on the MITRE category
    folder_name = details["MITRE Category"].replace(", ", "_")
    os.makedirs(folder_name, exist_ok=True)
    
    # Convert APT list to a comma-separated string
    apts = '","'.join(details["APTs"])

    # Save each analytic segment to a separate file
    for index, analytic in enumerate(details["Analytics"], start=1):
        file_title = f"[T{technique_id}] {details['Name']}"
        file_name = os.path.join(folder_name, f"{file_title}_Analytic_{index}.txt")


        with open(file_name, "w") as file:
            file.write(f"`indextime` {analytic['query']}\n")
            file.write(f"| eval hash_sha256= lower(hash_sha256),\n")
            file.write(f'hunting_trigger="{analytic['description']}",\n')
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
            file.write(f'priority=""\n')
            file.write(f"| `process_create_whitelist`\n")
            file.write(f"| eval indextime = _indextime\n")
            file.write(f"| convert ctime(indextime)\n")
            file.write(f"| table _time indextime event_description hash_sha256 host_fqdn user_name original_file_name process_path process_guid process_parent_path process_id process_parent_id process_command_line process_parent_command_line process_parent_guid mitre_category mitre_technique mitre_technique_id hunting_trigger mitre_subtechnique mitre_subtechnique_id apt mitre_link creator upload_date last_modify_date mitre_version priority\n")
            file.write(f"| collect `jarvis_index`\n")

    print(f"Saved analytics to {folder_name}/")


if __name__ == "__main__":
    # Get today's date
    today_date = datetime.now().strftime("%Y-%m-%d")
    
    # Ask user for multiple technique IDs separated by spaces
    technique_ids = input("Enter the technique IDs separated by spaces (e.g., 1059 1059.001 1059.002): ").strip().split()
    
    # Process each technique ID
    for technique_id in technique_ids:
        details = get_mitre_technique_details(technique_id)
        if "error" in details:
            print(f"Error for {technique_id}: {details['error']}")
        else:
            if details["Analytics"]:
                save_analytics_to_files(technique_id, details, today_date)
            else:
                print(f"No Analytics Queries Found for {technique_id}")

