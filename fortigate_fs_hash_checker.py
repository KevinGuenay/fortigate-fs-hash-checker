'''
Compare FortiGate filesystem hashes. Take input files in raw format or JSON format, convert raw to JSON, and compare the old and new hash files. Optionally retrieve the new hash file via SSH from a FortiGate. Can use CSV input for multiple FortiGate.

Usage: fortigate_fs_hash_checker.py [-h] [-f FORTIGATE] [-u USERNAME] [-p PASSWORD] [-s SSH_PORT] [-fh FORTIGATE-HOSTNAME] [-io INPUT_OLD] [-in INPUT_NEW] [-c CSV] [-o OUTPUT]

Options:
    -h, --help show this help message and exit
    -f FORTIGATE, --fortigate FORTIGATE The IP or FQDN of the FortiGate. Optional
    -u USERNAME, --username USERNAME Name of the user with JSON API access rights. Optional
    -p PASSWORD, --password PASSWORD Password of the user. Optional
    -fh FORTIGATE-HOSTNAME, --fortigate-hostname FORTIGATE-HOSTNAME The hostname of the FortiGate. Always takes priority. Optional
    -io INPUT-OLD, --input-old INPUT_OLD The old FortiGate filesystem hash file (raw format or JSON). Optional
    -in INPUT-NEW, --input-new INPUT_NEW The new FortiGate filesystem hash file (raw format or JSON). Optional
    -c CSV, --csv CSV Path to a CSV file with the parameters for multiple FortiGate devices. Optional
    -o OUTPUT, --output OUTPUT Path where files will be saved. Optional

CSV format:
fortigate,username,password,ssh_port,fortigate_hostname,input_old,input_new,output
'''

import os
import sys
import csv
import re
import json
import datetime
import time
import argparse

__author__ = "Kevin Guenay"
__version__ = "1.0.0"
__maintainer__ = "Kevin Guenay"
__email__ = "kevin.guenay@email.com"
__status__ = "Maintained"

def get_info_from_csv(csv_path) -> tuple[str, str, str, int, str, str, str, str]:
    '''Get the information from the CSV file and return the variables as a list of dictionaries

    Args:
        csv_path (str): The path to the CSV file
    
    Returns:
        csv_return (list): A list of dictionaries containing the variables for each row in the CSV
    '''

    csv_return = []

    with open(csv_path, 'r', encoding='utf-8') as csv_file:
        reader = csv.DictReader(csv_file)
        for row in reader:
            csv_return.append(row)

    return csv_return

def get_raw_output(fortigate, username, password, ssh_port) -> str:
    '''
    Get the raw FortiGate filesystem hash output via SSH
    
    Args:
        fortigate (str): The IP or FQDN of the FortiGate
        username (str): The username to use for SSH connection
        password (str): The password to use for SSH connection
        ssh_port (int): The SSH port to use for connection

    Returns:
        raw_output (str): The raw output from the "diagnose sys filesystem hash" command
    '''

    # Paramiko is imported here because it's only used in this function and it's not a standard library.
    # If the user doesn't have paramiko installed and they are not using the SSH functionality, they can still use the script without having to install paramiko.
    import paramiko

    raw_output = ''

    if fortigate is None or username is None or password is None:
        print("FortiGate IP/FQDN, username, or password not provided. Skipping SSH connection.")
        return None

    print(f"Connecting to FortiGate {fortigate} via SSH...")

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(fortigate, port=ssh_port, username=username, password=password, look_for_keys=False, allow_agent=False, timeout=30)

    remote_conn = ssh.invoke_shell()
    time.sleep(1)

    # We only care about the filesystem hash command output
    remote_conn.send("diagnose sys filesystem hash\n")
    time.sleep(1)

    # The command returns a lot of data, so we read it in chunks
    while remote_conn.recv_ready():
        raw_output += remote_conn.recv(65535).decode('utf-8')
        time.sleep(1)

    ssh.close()

    return raw_output

def convert_raw_to_json(raw) -> tuple[str,str]:
    '''
    Convert the raw FortiGate filesystem hash output to JSON

    Args:
        raw (str): The raw output from the "diagnose sys filesystem hash" command

    Returns:
        hostname (str): The hostname of the FortiGate extracted from the raw output
        hash_json (dict): A dictionary containing the filename as key and the hash as value, along with the hostname as the last key-value pair
    '''

    hostname = ''
    hash_list = []
    hash_dict = {}

    if isinstance(raw, str) and '\n' in raw:
        raw_data = raw.splitlines()
    else:
        with open(raw, 'r', encoding='utf-8') as f:
            raw_data = f.readlines()

    for line in raw_data:
        if ('#' or '$') in line:
            # Extract hostname from the prompt line
            hostname = (re.search(r'(.*)(?=\s(#|\$))', line)).group(1)
            raw_data.remove(line)
        elif ('Hash contents:' not in line) and ('Filesystem hash complete.' not in line) and ('Error reading simlink for file' not in line) and ('Error reading file' not in line) and line.strip() != '':
            # Replace spaces before '/' with a comma
            line = re.sub(r'\s+\/', ',/', line).strip()
            # Remove the sysmlink information
            line = re.sub(r'\s\-\>.*', '', line).strip()

            hash_list.append(line.split(',', 1))

    # Convert the hash list to a dictionary and then to JSON
    for item in hash_list:
        hash_dict[item[1]] = item[0]
    hash_dict['hostname'] = hostname
    hash_str = json.dumps(hash_dict)
    hash_json = json.loads(hash_str)

    return hostname, hash_json

def check_file_is_json(file_path) -> bool:
    '''
    Check if the given file is in JSON format
    
    Args:
        file_path (str): The path to the file to check
    
    Returns:
        is_json (bool): True if the file is in JSON format, False otherwise
    '''

    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            json.loads(file.read())
        is_json = True

    except Exception:
        is_json = False

    return is_json

def save_hash_json(hash_list, fortigate_hostname, output_path) -> tuple[str, str]:
    '''
    Save the hash list to a file

    Args:
        hash_list (dict): The dictionary containing the filename as key and the hash as value,
        fortigate_hostname (str): The hostname of the FortiGate
        output_path (str): The path where output file will be saved
    
    Returns:
        filename (str): The name of the hash list file
        fortigate_hostname (str): The hostname of the FortiGate, which is returned in case it was not provided as an argument but was extracted from the hash list
    '''

    # Set the hostname variable according to its content
    if fortigate_hostname is None:
        fortigate_hostname = hash_list.get('hostname')
        if fortigate_hostname == '':
            fortigate_hostname = 'UNKNOWN-HOSTNAME'

    # Create the output filename with timestamp and hostname
    filename = f"{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}_{fortigate_hostname}_fortigate_fs_hashes.json"

    # Ensure the output path ends with a slash
    if (output_path is not None and output_path != '') and not output_path.endswith('/'):
        output_path = output_path + '/'

    # Save the hash list as a file
    if output_path is not None:
        print(f"\nSaving new hash file to {output_path + filename}\n")
        with open(output_path + filename, 'w', encoding='utf-8') as f:
            f.write(json.dumps(hash_list, indent=4))

    # We return the filename for a print statement later
    return filename, fortigate_hostname

def get_new_hash_json(fortigate, username, password, ssh_port, input_new, new_path, fortigate_hostname, output) -> str:
    '''
    Get the new hash JSON from the input_new variable, which can be a file path or a raw string, and save it if an output path is provided
    
    Args:
        fortigate (str): The IP or FQDN of the FortiGate
        username (str): The username to use for SSH connection
        password (str): The password to use for SSH connection
        ssh_port (int): The SSH port to use for connection
        input_new (str): The new hash file, either as a file path or a raw string
        new_path (str): The path to the new hash file
        fortigate_hostname (str): The hostname of the FortiGate
        output (str): The path where output files will be saved

    Returns:
        input_new (str or dict): The new hash file, either as a file path or a dictionary
        new_path (str): The path to the new hash file, if it was saved
    '''

    # If input_new is not provided, retrieve it via SSH as raw output
    # Convert the raw output to JSON format and save it if an output path is provided
    if input_new is None or input_new == '':
        if not all([fortigate, username, password, ssh_port]):
            print("FortiGate IP/FQDN, username, password, or SSH port not provided. Cannot retrieve new filesystem hashes via SSH.")
            sys.exit()
        input_new = get_raw_output(fortigate, username, password, ssh_port)
        input_new = convert_raw_to_json(input_new)[1]
        if output is not None:
            # The function returns the filename
            new_path, fortigate_hostname = save_hash_json(input_new, fortigate_hostname,output)
    else:
        # If input_new is provided, check if it's JSON or raw format
        # If raw, convert to JSON and save if an output path is provided
        if not check_file_is_json(input_new):
            input_new = convert_raw_to_json(input_new)[1]
            if output is not None:
                new_path, fortigate_hostname = save_hash_json(input_new, fortigate_hostname, output)

    return input_new, new_path, fortigate_hostname

def compare_caller(old_path, input_old, new_path, input_new, fortigate_hostname, output) -> None:
    '''
    Reusable function to compare old and new hash files, called from both the CSV loop and the single FortiGate processing

    Args:
        old_path (str): The path to the old hash file
        input_old (str or dict): The old hash file, either as a file path or a dictionary
        new_path (str): The path to the new hash file
        input_new (str or dict): The new hash file, either as a file path or a dictionary
        fortigate_hostname (str): The hostname of the FortiGate
        output (str): The path where output files will be saved

    Returns:
        None
    '''

    # We set a compare boolean, because if a CSV file is provided we cannot simply exit, because another row might have the old hash file provided, so we just skip the comparison for that row and move on to the next one.
    compare = True

    # Ensure the output path ends with a slash
    if (output is not None and output != '') and not output.endswith('/'):
        output = output + '/'

    # If input_old is provided, check if it's JSON or raw format
    # If raw, convert to JSON
    if input_old is not None and input_old != '':
        if not check_file_is_json(input_old):
            input_old = convert_raw_to_json(input_old)[1]
    else:
        print('Old filesystem hash file not provided. Not comparing hashes.\n')
        compare = False

    if compare:
        try:
            print(f"Comparing filesystem hashes between {os.path.basename(old_path)} and {os.path.basename(new_path)}\n")
        except TypeError:
            print(f"Comparing filesystem hashes between {os.path.basename(old_path)} and the new hashes retrieved via SSH and no saved file\n")

        compare_old_new(input_old, input_new, fortigate_hostname, output)

def compare_old_new(old, new, fortigate_hostname, output_path) -> None:
    '''
    Compare old and new FortiGate filesystem hash files
    
    Args:
        old (str or dict): The old hash file, either as a file path or a dictionary
        new (str or dict): The new hash file, either as a file path or a dictionary
        fortigate_hostname (str): The hostname of the FortiGate
        output_path (str): The path where output files will be saved
    '''

    change_detected = False
    results = ''

    # We try loading the files as JSON and if it fails it's already a dictionary
    try:
        with open(old, 'r', encoding='utf-8') as old_file:
            old_hash_file = json.loads(old_file.read())
    except TypeError:
        old_hash_file = old

    try:
        with open(new, 'r', encoding='utf-8') as new_file:
            new_hash_file = json.loads(new_file.read())
    except TypeError:
        new_hash_file = new

    # Set the hostname variable according to its content
    if fortigate_hostname is None or fortigate_hostname == '':
        try:
            fortigate_hostname = new_hash_file['hostname']
        except KeyError:
            try:
                fortigate_hostname = old_hash_file['hostname']
            except KeyError:
                fortigate_hostname = 'UNKNOWN-HOSTNAME'

    print(f"Processing FortiGate {fortigate_hostname} hashes...\n")

    # The actual comparison between old and new hash files
    for filename, filehash in new_hash_file.items():
        if filename == 'hostname':
            continue
        if filename in old_hash_file:
            if filehash != old_hash_file[filename]:
                print(f"MODIFIED: {filename} - NEW HASH: {filehash} - OLD HASH: {old_hash_file[filename]}")
                results += f"\nMODIFIED: {filename} - NEW HASH: {filehash} - OLD HASH: {old_hash_file[filename]}"
                change_detected = True
        else:
            print(f"ADDED: {filename} - HASH: {filehash}")
            results += f"\nADDED: {filename} - HASH: {filehash}"
            change_detected = True

    for filename, filehash in old_hash_file.items():
        if filename not in new_hash_file:
            print(f"REMOVED: {filename} - HASH: {filehash}")
            results += f"\nREMOVED: {filename} - HASH: {filehash}"
            change_detected = True

    if change_detected is False:
        print("Everything is OK. No changes detected between the old and new filesystem hash files.")
        results += "Everything is OK. No changes detected between the old and new filesystem hash files."

    if output_path is not None and output_path != '':
        # Create the output filename with timestamp and hostname
        filename = f"{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}_{fortigate_hostname}_fortigate_fs_hash_comparison_result.txt"

        print(f"\nSaving results to {output_path + filename}\n------------------------------------------------------------")
        with open(output_path + filename, 'w', encoding='utf-8') as f:
            f.write(results.strip())

if __name__ == "__main__":

    parser = argparse.ArgumentParser()
    parser.add_argument('-f', '--fortigate', help="Destination FortiGate FQDN or IP address. Optional", default=None)
    parser.add_argument('-u', '--username', help="Username for FortiGate login. Optional", default=None)
    parser.add_argument('-p', '--password', help="Password for FortiGate login. Optional", default=None)
    parser.add_argument('-s', '--ssh-port', help="SSH port for FortiGate login. Optional", default=22, type=int)
    parser.add_argument('-fh', '--fortigate-hostname', help="Hostname of the FortiGate. Always takes priority. Optional", default=None)
    parser.add_argument('-io', '--input-old', help="Path to the old FortiGate filesystem hash file (raw format or JSON). Optional", default=None)
    parser.add_argument('-in', '--input-new', help="Path to the new FortiGate filesystem hash file (raw format or JSON). Optional", default=None)
    parser.add_argument('-c', '--csv', help="Path to a CSV file with the parameters for multiple FortiGates. Optional", default=None)
    parser.add_argument('-o', '--output', help="Path to the results file. Optional", default=None)
    args = parser.parse_args()

    old_path = args.input_old
    new_path = args.input_new

    input_old = args.input_old

    # We check if a CSV file is provided and if any other parameters are provided. If both are provided, we print a message and exit.
    # If only a CSV file is provided, we get the variables from the CSV file.
    # If no CSV file is provided, we get the variables from the command line arguments.
    if args.csv is not None and (args.fortigate is not None or args.username is not None or args.password is not None or args.fortigate_hostname is not None or args.input_old is not None or args.input_new is not None or args.output is not None):
        print("If a CSV file is provided, all other parameters are ignored. Please provide either a CSV file or the parameters for a single FortiGate.")
    elif args.csv is not None:
        csv_rows = get_info_from_csv(args.csv)
        for row in csv_rows:
            fortigate = row['fortigate']
            username = row['username']
            password = row['password']
            fortigate_hostname = row['fortigate_hostname']
            try:
                ssh_port = int(row['ssh_port'])
            except ValueError:
                if fortigate_hostname is None and (fortigate is not None and username is not None and password is not None):
                    print(f"No SSH port value in CSV row for FortiGate {row['fortigate_hostname']} at line {csv_rows.index(row) + 1}. Defaulting to 22.")
                    ssh_port = 22
                elif fortigate_hostname is None and (fortigate is not None and username is not None and password is not None):
                    print(f"No SSH port value in CSV row for FortiGate at line {csv_rows.index(row) + 1}. Defaulting to 22.")
                    ssh_port = 22
            input_old = row['input_old']
            old_path = row['input_old']
            input_new = row['input_new']
            new_path = row['input_new']
            output = row['output']

            input_new, new_path, fortigate_hostname = get_new_hash_json(fortigate, username, password, ssh_port, input_new, new_path, fortigate_hostname, output)

            compare_caller(old_path, input_old, new_path, input_new, fortigate_hostname, output)

    if args.csv is None:
        fortigate = args.fortigate
        username = args.username
        password = args.password
        ssh_port = args.ssh_port
        new_path = args.input_new
        input_new = args.input_new

        if args.fortigate_hostname is not None:
            fortigate_hostname = args.fortigate_hostname
        else:
            fortigate_hostname = None

        # Ensure the output path ends with a slash
        if args.output is not None and not args.output.endswith('/'):
            output = args.output + '/'
        else:
            output = args.output

        input_new, new_path, fortigate_hostname = get_new_hash_json(fortigate, username, password, ssh_port, input_new, new_path, fortigate_hostname, output)

        if input_old is not None:
            compare_caller(old_path, input_old, new_path, input_new, fortigate_hostname, output)
