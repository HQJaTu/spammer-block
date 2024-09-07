# Spammer Blocker

Email (SMTP) spam filtering can be effectively done by simply filtering out "bad IP neighbourhoods".
As the address ranges for these "bad neighbourhoods" are not generally known, a method for creating
such a list is to observe a spam, record its IP-address and flag the sender's IP-range as a "bad" one.

This tool to help maintaining such a list works by accepting IP-address as input, querying the
AS-number for given IP-address and listing all CIDRs associated with the given ASN.

Thus, we get a complete map of the network neighbourhood via single address.

## Installation

### From RPM
1. For downloaded or built RPM: `rpm --freshen -h spammer-block-0.7.1-2.x86_64.rpm`
2. Done!

### From Git
1. Git clone
2. (optional for development) `python -m venv <directory for virtual env>`
3. Install dependencies, libraries and CLI-utilities:
```bash
pip install .
```
4. Done!

### D-Bus
See directory `systemd.service/` for details on daemon-based reporting.

### ipwhois-library
For querying ASN-data, there is a dependency into https://pypi.org/project/ipwhois/.
This library will use https://www.radb.net/query/ service for queries. However, the query
won't return complete full data for ASN-query.

As author refuses to update the library, there is a fork with same name https://github.com/HQJaTu/ipwhois
using commercial https://ipinfo.io/ for ASN-queries. That query will return full and complete dataset as response.

Limit: A non-paid API of ipinfo.ip will serve 5 ASN-queries / day / IP-address.

## Usage
* Spammer block:
```text
usage: spammer-blocker [-h] [--asn ASN] [--skip-overlapping]
                       [--allow-non-exact-overlapping] [--output-format OUTPUT_FORMAT]
                       [--output-file OUTPUT_FILE] [--postfix-rule POSTFIX_RULE]
                       [--log-level LOG_LEVEL] [--ipinfo-token IPINFO_TOKEN]
                       [--ipinfo-db-file IPINFO_DB_FILE]
                       [--asn-result-json-file ASN_RESULT_JSON_FILE] [-c FILE]
                       IP

Block IP-ranges of a spammer

positional arguments:
  IP                    IPv4 address to query for

options:
  -h, --help            show this help message and exit
  --asn ASN, -a ASN     Skip querying for ASN
  --skip-overlapping, --merge-overlapping
                        Don't display any overlapping subnets. Larger network will be merged to hide smaller ones. Default: yes
  --allow-non-exact-overlapping
                        When merging overlapping, reduce number of networks by allowing non-exact merge. Default: no
  --output-format OUTPUT_FORMAT, -o OUTPUT_FORMAT
                        Output format. Choices: none, json, postfix
                        Default: "postfix" will produce Postfix CIDR-table
  --output-file OUTPUT_FILE
                        Output to a file.
  --postfix-rule POSTFIX_RULE
                        CIDR-table rule to apply for a net.
                        Dynamic AS-number assignment with "{ASN}".
                        Default: "554 Go away spammer!"
                        Example: "PREPEND X-Spam-ASN: AS{ASN}"
  --log-level LOG_LEVEL
                        Set logging level (CRITICAL, FATAL, ERROR, WARNING, INFO, DEBUG). Python default is: WARNING
  --ipinfo-token IPINFO_TOKEN
                        ipinfo.io API access token for using paid ASN query service
  --ipinfo-db-file IPINFO_DB_FILE
                        ipinfo.io ASN DB file
  --asn-result-json-file ASN_RESULT_JSON_FILE
                        To conserve ASN-queries, save query result
                        or use existing result from a previous query.
                        Dynamic AS-number assignment with "{ASN}".
  -c FILE, --config-file FILE
                        Specify config file

Args that start with '--' can also be set in a config file (/etc/spammer-
block/blocker.conf or ~/.spammer-blocker or specified via -c). Config file syntax
allows: key=value, flag=true, stuff=[a,b,c] (for details, see syntax at
https://goo.gl/R74nmi). In general, command-line values override config file values
which override defaults.
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

## Configuration File
ConfigArgParse Pypi page: https://goo.gl/R74nmi

Any configuration option with `--` can be specified in a simple key-value configuration file.

## Example:

### Simple
Default output is in Postfix-configuration format.
```text
$ spammer-block 185.162.126.236
# Confirmed spam from IP: 185.162.126.236
# AS56378 has following nets:
31.133.100.0/24         554 Go away spammer!    # O.M.C. COMPUTERS & COMMUNICATIONS LTD (CLOUDWEBMANAGE-IL-JR)
31.133.103.0/24         554 Go away spammer!    # O.M.C. COMPUTERS & COMMUNICATIONS LTD (CLOUDWEBMANAGE-IL-JR)
103.89.140.0/24         554 Go away spammer!    # Nsof Networks Ltd (NSOFNETWORKSLTD-AP)
162.251.146.0/24        554 Go away spammer!    # Cloud Web Manage (CLOUDWEBMANAGE)
185.162.125.0/24        554 Go away spammer!    # O.M.C. COMPUTERS & COMMUNICATIONS LTD (IL-OMC-20160808)
185.162.126.0/24        554 Go away spammer!    # O.M.C. COMPUTERS & COMMUNICATIONS LTD (IL-OMC-20160808)
```

### Advanced
Instead of instructing Postfix to block spam, let all spam pass,
but add new mail header to indicate classification as spam and spam origin.
Additionally, cache IPinfo.io response JSON-data into a file to save on outgoing requests.
Their limit is 5 per day from single IPv4.
```text
$ spammer-block 185.162.126.236 \
  --postfix-rule "PREPEND X-Spam-ASN: AS{ASN}" \
  --asn-result-json-file "/tmp/AS{ASN}.json"
# Confirmed spam from IP: 185.162.126.236
# AS56378 has following nets:
31.133.100.0/24         PREPEND X-Spam-ASN: AS44709     # O.M.C. COMPUTERS & COMMUNICATIONS LTD
31.133.103.0/24         PREPEND X-Spam-ASN: AS44709     # O.M.C. COMPUTERS & COMMUNICATIONS LTD (CLOUDWEBMANAGE-IL-JR)
103.89.140.0/24         PREPEND X-Spam-ASN: AS44709     # Nsof Networks Ltd (NSOFNETWORKSLTD-AP)
162.251.146.0/24        PREPEND X-Spam-ASN: AS44709     # Cloud Web Manage (CLOUDWEBMANAGE)
185.162.125.0/24        PREPEND X-Spam-ASN: AS44709     # O.M.C. COMPUTERS & COMMUNICATIONS LTD (IL-OMC-20160808)
185.162.126.0/24        PREPEND X-Spam-ASN: AS44709     # O.M.C. COMPUTERS & COMMUNICATIONS LTD
```

# Spammer reporter

Utility `spammer-reporter.py` is used to report received email to organization
fighting against spam. An example of one would be [SpamCop](https://www.spamcop.net/).

## Usage
```text
usage: spammer-reporter [-h] [--from-address FROM_ADDRESS]
                        [--smtpd-address SMTPD_ADDRESS]
                        [--spamcop-report-address REPORT-ADDRESS]
                        [--mock-report-address REPORT-ADDRESS] [--report-from-stdin]
                        [--report-from-file FILENAME] [--dbus BUS-TYPE-TO-USE]
                        [--log-level LOG_LEVEL] [--config-file TOML-CONFIGURATION-FILE]

Report received email as spam

options:
  -h, --help            show this help message and exit
  --from-address FROM_ADDRESS
                        Send mail to Spamcop using given sender address. Default:
                        joe.user@example.com
  --smtpd-address SMTPD_ADDRESS
                        Send mail using SMTPd at address. Default: 127.0.0.1
  --spamcop-report-address REPORT-ADDRESS
                        Report to Spamcop using given address
  --mock-report-address REPORT-ADDRESS
                        Report to given e-mail address. Simulate reporting for test
                        purposes.
  --report-from-stdin   Read email from STDIN and report it as spam
  --report-from-file FILENAME
                        Read email from a RFC2822 file and report it as spam
  --dbus BUS-TYPE-TO-USE
                        Use D-Bus for reporting. Ignoring all arguments, except must use
                        --report-from-file. Choices: system, session
  --log-level LOG_LEVEL
                        Set logging level. Python default is: WARNING
  --config-file TOML-CONFIGURATION-FILE
                        Configuration Toml-file
```

## Example: Manual reporting from Maildir
Any identified email from a Maildir stored file can be reported by running following command:
```bash
$ spammer-reporter \
  --spamcop-report-address submit.-your-id-here-@spam.spamcop.net \
  --spamcop-report-from-file Mail/cur/-the-mail-file-here-
```
