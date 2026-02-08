# The FortiGate filesystem hash checker

Created and maintained by Kevin Guenay at <https://guenay.at>

A FortiGate best practice is to [periodically check the hashes of the FortiGate filesystem with known-good values](https://community.fortinet.com/t5/FortiGate/Technical-Tip-Best-practice-Periodically-do-FortiGate-files/ta-p/322502). Changes in hashes can be Indicators of Compromise (IoC). This comparison is a manual task, and the FortiGate filesystem hash checker is supposed to make this easier by doing the comparison using a script where you have to supply a known-good list of hashes and either a new list or credentials so the script can get the new list via an SSH connection. The script can be used for a single FortiGate or for a CSV file to handle multiple FortiGates.

Please read the associated blog post for some more information.

## Requirements

* Python
* Standard Python libraries
* Paramiko

Paramiko is technically optional if you always supply your own files. If you never connect to FortiGates using SSH paramiko is not necessary, and the script can run without it, making it portable.

The script was tested on both Windows and Ubuntu.

## Help message

```
usage: fortigate_fs_hash_checker.py [-h] [-f FORTIGATE] [-u USERNAME] [-p PASSWORD] [-s SSH_PORT] [-fh FORTIGATE_HOSTNAME] [-io INPUT_OLD] [-in INPUT_NEW] [-c CSV] [-o OUTPUT]

options:
  -h, --help            show this help message and exit
  -f FORTIGATE, --fortigate FORTIGATE
                        Destination FortiGate FQDN or IP address. Optional
  -u USERNAME, --username USERNAME
                        Username for FortiGate login. Optional
  -p PASSWORD, --password PASSWORD
                        Password for FortiGate login. Optional
  -s SSH_PORT, --ssh-port SSH_PORT
                        SSH port for FortiGate login. Optional
  -fh FORTIGATE_HOSTNAME, --fortigate-hostname FORTIGATE_HOSTNAME
                        Hostname of the FortiGate. Always takes priority. Optional
  -io INPUT_OLD, --input-old INPUT_OLD
                        Path to the old FortiGate filesystem hash file (raw format or JSON). Optional
  -in INPUT_NEW, --input-new INPUT_NEW
                        Path to the new FortiGate filesystem hash file (raw format or JSON). Optional
  -c CSV, --csv CSV     Path to a CSV file with the parameters for multiple FortiGates. Optional
  -o OUTPUT, --output OUTPUT
                        Path to the results file. Optional
```

## Usage

### Getting the initial hash list

As a first step, you have to get a known-good list of hashes. This can be accomplished in two ways:

1. Execute the `diagnose sys filesystem hash` command on a FortiGate and save the output to a file
   1. If you use this method, copy all contents starting with the initial prompt where the command is. This way, the hostname will be taken directly from the output, but you can also supply a hostname directly to the script **and the supplied hostname will always take priority***.
   2. This output is considered "raw" for this script.
   3. Example of a file with raw content:
```
70G-01 # diagnose sys filesystem hash
Hash contents: /bin
7a710e821b8a8f5437fcf9841f801172b99e46967f856b37b64edfeb00b9b75e        /bin/zebos_launcher -> /bin/init
7a710e821b8a8f5437fcf9841f801172b99e46967f856b37b64edfeb00b9b75e        /bin/wpad_client -> /bin/init
7a710e821b8a8f5437fcf9841f801172b99e46967f856b37b64edfeb00b9b75e        /bin/wpad_ac -> /bin/init
...
Lots of lines
...
Hash contents: /usr/local
ce95e59e1f7fed0ebda42b61de49d213f85ed31b73214cccf08b47cb98f81814        /usr/local/apache2/conf/mime.types
e5c4bd4cea0d7862b2321994f48e4cea475f6e29521356ab095e03e5806c1abf        /usr/local/apache2/conf/httpd.conf
365e069735ce7bdd0f27db0e8815560fc3a3479c91b1860e01d0d730d6bb0974        /usr/local/apache2/conf/admin-vhost.conf
Filesystem hash complete. Hashed 3695 files.
```
2. Execute the script while supplying information to connect to a FortiGate using SSH and supply an output path.
   1. This will save the hashes into a JSON file.
   2. The JSON will also include the hostname
```
python3 fortigate_fs_hash_checker.py -f 192.168.1.201 -u admin -p admin -o /tmp/hash_checker
Connecting to FortiGate 192.168.1.201 via SSH...

Saving new hash file to /tmp/hash_checker/20260208_092430_70G-01_fortigate_fs_hashes.json
```

Once you have a known-good list, you can start comparing.

### Comparing old and new hash values

By supplying both an old and a new file to the script, the hashes will be compared. For this process, it doesn't matter what format the files are, and all combinations work.

|| Raw | JSON |
|------|-----|------|
| Raw  |:white_check_mark:|:white_check_mark:|
| JSON |:white_check_mark:|:white_check_mark:|

The script only ever works with JSON, so if you supply a raw file, it will get converted first. If you supply an output path, the result will be saved.

```
python3 fortigate_fs_hash_checker.py -io hash_old.json -in hash_new.json -o /tmp/hash_checker
Comparing filesystem hashes between hash_old.json and hash_new.json

Processing FortiGate 70G-01 hashes...

Everything is OK. No changes detected between the old and new filesystem hash files.

Saving results to /tmp/hash_checker/20260208_095852_70G-01_fortigate_fs_hash_comparison_result.txt
------------------------------------------------------------
```

If you only supply an old file, as well as information to a FortiGate, the script will get the new hash values before comparing the information. If you supply an output path, both the new hash list and the result will be saved.

```
python3 fortigate_fs_hash_checker.py -f 192.168.1.201 -u admin -p admin -io hash_old.json -o /tmp/hash_checker
Connecting to FortiGate 192.168.1.201 via SSH...

Saving new hash file to /tmp/hash_checker/20260208_100013_70G-01_fortigate_fs_hashes.json

Comparing filesystem hashes between hash_old.json and 20260208_100013_70G-01_fortigate_fs_hashes.json

Processing FortiGate 70G-01 hashes...

Everything is OK. No changes detected between the old and new filesystem hash files.

Saving results to /tmp/hash_checker/20260208_100013_70G-01_fortigate_fs_hash_comparison_result.txt
------------------------------------------------------------
```

### Changes in hash values and files

If the script notices additions, modifications, or removals, it will highlight them. If all values are identical, a corresponding OK message will be displayed (see above). If you supply an output path, the result will be saved.

```
python3 fortigate_fs_hash_checker.py -io hash_old.json -in hash_new.json -o /tmp/hash_checker
Comparing filesystem hashes between hash_old.json and hash_new.json

Processing FortiGate 70G-01 hashes...

MODIFIED: /bin/zebos_launcher - NEW HASH: 7a710e821b8a8f5437fcf9841f801172b99e46967f856b37b64edfeb00b9b75f - OLD HASH: 7a710e821b8a8f5437fcf9841f801172b99e46967f856b37b64edfeb00b9b75e
ADDED: /bin/new_test_hash - HASH: 7a710e821b8a8f5437fcf9841f801172b99e46967f856b37b64edfeb00b9b75e
REMOVED: /bin/wlac_hlp - HASH: 7a710e821b8a8f5437fcf9841f801172b99e46967f856b37b64edfeb00b9b75e

Saving results to /tmp/hash_checker/20260208_100213_70G-01_fortigate_fs_hash_comparison_result.txt
------------------------------------------------------------
```

### Using a CSV to check multiple FortiGates

The script can take in a CSV file if you want to handle multiple FortiGates, and all functions are supported in this mode as well. An example CSV file is supplied in this project. When using a CSV, no other parameters must be supplied.

A CSV can look like the following, with all fields filled:

```
fortigate,username,password,ssh_port,fortigate_hostname,input_old,input_new,output
192.168.1.201,admin,admin,22,70G-01,/tmp/hash_checker/hash_old_01.json,/tmp/hash_checker/hash_new_01.json,/tmp/hash_checker
192.168.1.202,admin,admin,22,70G-02,/tmp/hash_checker/hash_old_02.json,/tmp/hash_checker/hash_new_02.json,/tmp/hash_checker
```

```
python3 fortigate_fs_hash_checker.py -c hash_checker.csv
Comparing filesystem hashes between hash_old_01.json and hash_new_01.json

Processing FortiGate 70G-01 hashes...

Everything is OK. No changes detected between the old and new filesystem hash files.

Saving results to /tmp/hash_checker/20260208_101313_70G-01_fortigate_fs_hash_comparison_result.txt
------------------------------------------------------------
Comparing filesystem hashes between hash_old_02.json and hash_new_02.json

Processing FortiGate 70G-02 hashes...

Everything is OK. No changes detected between the old and new filesystem hash files.

Saving results to /tmp/hash_checker/20260208_101313_70G-02_fortigate_fs_hash_comparison_result.txt
------------------------------------------------------------
```

You can, of course, supply files for one FortiGate in a CSV, and connect via SSH to another to get the new hash list.

```
fortigate,username,password,ssh_port,fortigate_hostname,input_old,input_new,output
192.168.1.201,admin,admin,22,70G-01,/tmp/hash_checker/hash_old_01.json,,/tmp/hash_checker
,,,,,/tmp/hash_checker/hash_old_02.json,/tmp/hash_checker/hash_new_02.json,/tmp/hash_checker
```

```
python3 fortigate_fs_hash_checker.py -c hash_checker.csv
Connecting to FortiGate 192.168.1.201 via SSH...

Saving new hash file to /tmp/hash_checker/20260208_102806_70G-01_fortigate_fs_hashes.json

Comparing filesystem hashes between hash_old_01.json and 20260208_102806_70G-01_fortigate_fs_hashes.json

Processing FortiGate 70G-01 hashes...

Everything is OK. No changes detected between the old and new filesystem hash files.

Saving results to /tmp/hash_checker/20260208_102807_70G-01_fortigate_fs_hash_comparison_result.txt
------------------------------------------------------------
Comparing filesystem hashes between hash_old_02.json and hash_new_02.json

Processing FortiGate 70G-02 hashes...

Everything is OK. No changes detected between the old and new filesystem hash files.

Saving results to /tmp/hash_checker/20260208_102807_70G-02_fortigate_fs_hash_comparison_result.txt
------------------------------------------------------------
```