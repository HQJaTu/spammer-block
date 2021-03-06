# Spammer Blocker

Email (SMTP) spam filtering can be effectively done by simply filtering out "bad IP neighbourhoods".
As the address ranges for these "bad neighbourhoods" are not generally known, a method for creating
such a list is to observe a spam, record its IP-address and flag the sender's IP-range as a "bad" one.

This tool to help maintaining such a list works by accepting IP-address as input, querying the
AS-number for given IP-address and listing all CIDRs associated with the given ASN.

Thus, we get a complete map of the network neighbourhood via single address.

## Installation
1. Git clone
1. Install:
```bash
pip3 install .
```

### ipwhois-library
For querying ASN-data, there is a dependency into https://pypi.org/project/ipwhois/.
This library will use https://www.radb.net/query/ service for queries. However, the query
won't return complete full data for ASN-query.

As author refuses to update the library, there is a fork with same name https://github.com/HQJaTu/ipwhois
using commercial https://ipinfo.io/ for ASN-queries. That query will return full and complete dataset as response.

Limit: A non-paid API of ipinfo.ip will serve 5 ASN-queries / day / IP-address.

## Usage
```text
usage: spammer-block.py [-h] --ip IP [--skip-overlapping] [--output OUTPUT]
                        [--log LOG] [--ipinfo-token IPINFO_TOKEN]
                        [--debug-asn-result-file DEBUG_ASN_RESULT_FILE]

Block IP-ranges of a spammer

optional arguments:
  -h, --help            show this help message and exit
  --ip IP, -i IP        IPv4 address to query for
  --skip-overlapping    Don't display any overlapping subnets
  --output OUTPUT, -o OUTPUT
                        Output format. Default "postfix"
  --log LOG             Set logging level. Python default is: WARNING
  --ipinfo-token IPINFO_TOKEN
                        ipinfo.io API access token if using paid ASN query
                        service
  --debug-asn-result-file DEBUG_ASN_RESULT_FILE
                        Debugging: To conserve ASN-queries, use existing
                        result from a cache file.
```

## Postfix configuration
To use the tool output, a file is used.

In `main.cf` of a Postfix-installation, there is:
```text
smtpd_client_restrictions =
        permit_mynetworks
        permit_sasl_authenticated
        check_client_access cidr:/etc/postfix/client_checks.cidr
```

File `/etc/postfix/client_checks.cidr` will contain listings of all known spammers' networks.

## Example:
Default output is in Postfix-configuration format.
```text
$ ./spammer-block.py -i 185.162.126.236
# Confirmed spam from IP: 185.162.126.236
# AS56378 has following nets:
31.133.100.0/24         554 Go away spammer!    # O.M.C. COMPUTERS & COMMUNICATIONS LTD (CLOUDWEBMANAGE-IL-JR)
31.133.103.0/24         554 Go away spammer!    # O.M.C. COMPUTERS & COMMUNICATIONS LTD (CLOUDWEBMANAGE-IL-JR)
103.89.140.0/24         554 Go away spammer!    # Nsof Networks Ltd (NSOFNETWORKSLTD-AP)
162.251.146.0/24        554 Go away spammer!    # Cloud Web Manage (CLOUDWEBMANAGE)
185.162.125.0/24        554 Go away spammer!    # O.M.C. COMPUTERS & COMMUNICATIONS LTD (IL-OMC-20160808)
185.162.126.0/24        554 Go away spammer!    # O.M.C. COMPUTERS & COMMUNICATIONS LTD (IL-OMC-20160808)
```

