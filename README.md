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

## Step 2: Running Application

Run the main.py file with the appropriate data and flags as noted below:

#### The required arguments and flags are below

 * Urls to scrape for IOC's: Comma seperated list of IP addresses and hostnames
 * SecureX API Client ID: -c 
 * SecureX API Client Secret: -s 
 * Secure Network Analytics Manager IP: -i Optional
 * Secure Network Analytics Username: -u Optional
 * Secure Network Analytics Password: -p Optional
 * Secure Network Analytics Host Group: -g Optional

```
main.py https://blog.talosintelligence.com/2021/12/apache-log4j-rce-vulnerability.html -c securex-api-client -s securex-api-secret -i SNA-IP-Address -u sna-admin-user -p sna-admin-password -g sna-destination-host-group-name
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
 
