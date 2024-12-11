import os
import subprocess

def main_menu():
    """Display the main menu and handle user selection."""
    print("Select an option:")
    print("1. SigmaHQ")
    print("2. MITRE ATT&CK")
    print("3. Both SigmaHQ and MITRE ATT&CK")
    print("Type the name or number of your choice.")

    choice = input("Enter your choice: ").strip().lower()
    
    if choice not in ["1", "2", "3", "sigmahq", "mitre", "both"]:
        print("Invalid choice. Please try again.")
        main_menu()
        return

    # Loop to validate the technique ID input
    while True:
        technique_id = input("Enter the technique ID (e.g., 1059): ").strip()
        if technique_id.isdigit() or (technique_id.startswith("T") and technique_id[1:].replace(".", "").isdigit()):
            break
        print("Invalid technique ID. Please enter a valid ID (e.g., 1059 or T1059).")

    if choice in ["1", "sigmahq"]:
        run_sigmahq(technique_id)
    elif choice in ["2", "mitre"]:
        run_mitre(technique_id)
    elif choice in ["3", "both"]:
        run_sigmahq(technique_id)
        run_mitre(technique_id)
        print(f"Search completed for SigmaHQ and MITRE ATT&CK with Technique ID {technique_id}.")

def run_sigmahq(technique_id):
    """Run the SigmaHQ script."""
    try:
        print(f"Running SigmaHQ script for Technique ID {technique_id}...")
        subprocess.run(["python3", "sigmahq.py", technique_id], check=True)
    except FileNotFoundError:
        print("SigmaHQ script not found. Ensure 'sigmahq.py' is in the same directory.")
    except subprocess.CalledProcessError as e:
        print(f"Error while running SigmaHQ script: {e}")

def run_mitre(technique_id):
    """Run the MITRE script."""
    try:
        print(f"Running MITRE script for Technique ID {technique_id}...")
        subprocess.run(["python3", "mitre.py", technique_id], check=True)
    except FileNotFoundError:
        print("MITRE script not found. Ensure 'mitre.py' is in the same directory.")
    except subprocess.CalledProcessError as e:
        print(f"Error while running MITRE script: {e}")

if __name__ == "__main__":
    main_menu()
