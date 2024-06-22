import csv
import json
import os
import sys

from censys.search import CensysHosts


def load_env_file(filepath):
    """
    Loads environment variables from a file into the system environment.

    Parameters:
    filepath (str): Path to the file containing environment variables.

    The function reads the specified file and sets environment variables based on the file's contents.
    Each line in the file should have the format KEY=VALUE. Lines that are empty or start with '#' are ignored.
    """

    # Check if the file exists, raise an error if it does not
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"Env file {filepath} not found")

    # Open the file and read its contents
    with open(filepath) as f:
        for line in f:
            # Ignore empty lines and comments
            if line.strip() and not line.startswith('#'):
                # Split the line into key and value
                key, value = line.strip().split('=', 1)
                # Set the environment variable
                os.environ[key] = value


def query_censys_and_save(query_input, output_filename):
    """
    This function initializes a CensysHosts object, performs a search query,
    and saves the results into a JSON file.

    Parameters:
    query_input (str): The query to be executed on Censys.
    output_filename (str): The name of the file where the results will be saved.
    """
    load_env_file('.env')
    api_id = os.getenv('CENSYS_API_ID')
    api_secret = os.getenv('CENSYS_API_SECRET')
    if not api_id or not api_secret:
        raise ValueError("Censys API ID and Secret must be set")

    h = CensysHosts(api_id=api_id, api_secret=api_secret)

    # Perform the search query
    query = h.search(query_input, pages=1)

    # Retrieve the query results
    query_result = query()

    # Output results into json file
    with open(output_filename, "w") as file:
        json.dump(query_result, file, indent=4)

    print(f"Query results have been saved to {output_filename}")


def extract_domain_names_csv(input_filename, output_filename):
    """
    This function reads domain names from a CSV file and writes those ending with ".fr"
    to another CSV file, avoiding duplicates and limiting to 1000 entries.

    Parameters:
    input_filename (str): The path to the input CSV file containing domain names.
    output_filename (str): The path to the output CSV file where filtered domains will be saved.
    """
    with open(input_filename, "r") as infile, open(output_filename, "a", newline="") as outfile:
        reader = csv.reader(infile)
        if os.path.getsize(output_filename) == 0:
            old_fr_domains = []
        else:
            # Read the existing domains from the output file
            with open(output_filename, "r") as f:
                old_fr_domains = f.read().split('\n')

        counter = 0
        for row in reader:
            if counter < 10:
                # Check if the domain name ends with ".fr"
                domain = row[1]
                if domain.endswith(".fr") and domain not in old_fr_domains:
                    outfile.write(domain + '\n')
                    counter += 1


def extract_domain_names_txt(input_filename, output_filename):
    """
    This function reads domain names from a text file and writes those ending with ".fr"
    to another text file, avoiding duplicates and limiting to 1000 entries.

    Parameters:
    input_filename (str): The path to the input text file containing domain names.
    output_filename (str): The path to the output text file where filtered domains will be saved.
    """
    with open(input_filename, "r") as infile, open(output_filename, "a", newline="") as outfile:
        reader = csv.reader(infile)
        if os.path.getsize(output_filename) == 0:
            old_fr_domains = []
        else:
            # Read the existing domains from the output file
            with open(output_filename, "r") as f:
                old_fr_domains = f.read().split('\n')

        print(len(old_fr_domains))
        counter = 0
        for row in reader:
            if counter < 10:
                # Check if the domain name ends with ".fr"
                domain = row[0].split()[1]
                if domain.endswith(".fr") and domain not in old_fr_domains:
                    outfile.write(domain + '\n')
                    counter += 1


if __name__ == "__main__":
    print("Starting the collection of potential amplifiers...")
    if len(sys.argv) < 2:
        print("Usage: python server_collection.py <method_name> <args>")
        sys.exit(1)

    method_name = sys.argv[1]
    args = sys.argv[2:]

    try:
        method = getattr(sys.modules[__name__], method_name)
    except AttributeError:
        print(f"Unknown method: {method_name}")
        sys.exit(1)

    method(*args)