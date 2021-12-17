[![Gitter Chat](https://img.shields.io/badge/gitter-join%20chat-brightgreen.svg)](https://gitter.im/CiscoSecurity/Threat-Response "Gitter Chat")
[![Travis CI Build Status](https://travis-ci.com/CiscoSecurity/tr-05-serverless-relay.svg?branch=develop)](https://travis-ci.com/CiscoSecurity/tr-05-serverless-relay)

# Secure Network Analytics Host Group Responder

Utilizing SecureX to automate the updating of SNA Host Groups


## Rationale

We need to easily update host groups in SNA for log4j vulnerabilities from any data source reachable via http

## Required Dependencies

* System running python3 and ability to install packages - Required
* SecureX instance with API credentials - Required
* Secure Network Analytics deployment with admin user access - Optional

## Application Setup


## Step 1: Requirements Installation

First of all, make sure that you already have Python 3 installed by typing
```
python3 --version
```
in your command-line shell.

The application has been implemented and tested using `Python 3.7`. You may try
to use any higher versions if you wish as they should be backward-compatible.

After that, you have to create a "virtual environment" to isolate the
application-specific requirements from the libraries globally installed to your
system. Here are the steps to follow:

1. Create a virtual environment named `venv`:

   `python3 -m venv venv`

2. Activate the virtual environment:
   - Linux/Mac: `source venv/bin/activate`
   - Windows: `venv\Scripts\activate.bat`

3. Upgrade PIP (optional):

   `pip install --upgrade pip`

**NOTE**. The virtual environment has to be created only once, you just have
to make sure to activate it each time you are working on or playing with the
application (modern IDEs can automatically do that for you). You can deactivate
a previously activated virtual environment by simply typing `deactivate` in
your command-line shell.

Finally, install the libraries required for the application to function from
the [requirements.txt](requirements.txt) file:

```
pip install --upgrade --requirement requirements.txt
```

### Configuration

All configuration is expected in a config.yml file. An example template file has been provided that needs to be 
populated with required information and **renamed to config.yml**

## Step 2: Running Application

Run the main.py file with the appropriate data and flags as noted below:

#### The required arguments and flags are below

 * Operation: full_lookup, url_lookup, orbital_lookup
 * -u: Comma deliminated list of pages to scrape for observables, no spaces
 * -s: **Optional** Update Secure Network Analytics Host Group IPs with those found in url lookup
 * -q: **Optional** SQL query for orbital to execute
 * -n: **Optional** Comma seperated list of nodes for Orbital to query, defaults to all, no spaces

```
main.py full_lookup -u https://s3.amazonaws.com/talos-intelligence-site/production/document_files/files/000/095/701/original/IOCs_20211216.txt?1639690764,https://s3.amazonaws.com/talos-intelligence-site/production/document_files/files/000/095/700/original/Dec1521IOCs.txt?1639683730 -s -q "SELECT DISTINCT pos.pid, p.name, p.cmdline, pos.local_address, pos.local_port, pos.remote_address, pos.remote_port FROM processes p JOIN process_open_sockets pos USING (pid) WHERE pos.remote_address NOT IN (\"\", \"0.0.0.0\", \"127.0.0.1\", \"::\", \"::1\", \"0\");"
```

### Script execution flow

1. Splits provided data source IP's and URL's
2. For each data source, scrapes web page and cleans up HTML tags
3. Sends cleaned page text to Cisco Threat Response for inspection of observables
4. Adds each IP address discovered from CTR to malicious IP list
5. Performs lookup within CTR for all domain IOC's judgements
6. For Suspicious or Malicious domains, performs DNS lookup to identify IP addresses
7. Identified IP addresses added to malicious IP list
8. Write output to malicious_ip.txt

Optional SNA Tasks

1. Create SNA API session
2. Lookup tenant ID and Host Group ID using provided name
3. Append all unique IP addresses in malicious IP list to Host Group Ranges
4. Update SNA Host Group Via API
 
