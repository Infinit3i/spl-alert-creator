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

    if choice in ["1", "sigmahq"]:
        run_sigmahq()
    elif choice in ["2", "mitre"]:
        run_mitre()
    elif choice in ["3", "both"]:
        run_sigmahq()
        run_mitre()
    else:
        print("Invalid choice. Please try again.")
        main_menu()

def run_sigmahq():
    """Run the SigmaHQ script."""
    try:
        print("Running SigmaHQ script...")
        subprocess.run(["python3", "sigmahq.py"], check=True)
    except FileNotFoundError:
        print("SigmaHQ script not found. Ensure 'parse_sigma_splunk.py' is in the same directory.")
    except subprocess.CalledProcessError as e:
        print(f"Error while running SigmaHQ script: {e}")

def run_mitre():
    """Run the MITRE script."""
    try:
        print("Running MITRE script...")
        subprocess.run(["python3", "mitre.py"], check=True)
    except FileNotFoundError:
        print("MITRE script not found. Ensure 'mitre.py' is in the same directory.")
    except subprocess.CalledProcessError as e:
        print(f"Error while running MITRE script: {e}")

if __name__ == "__main__":
    main_menu()

