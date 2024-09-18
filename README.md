# spki_python
Proof-of-concept python code supporting X.509 SubjectPublicKeyInfo research.

The intent of this project has been to extend the research performed by `spki_openssl` but using Python to access live hosts as a form of inventory gathering.  


This project relies on stock cryptographic libraries available to Python and the underlying operating system.  This being said, these modules may not connect to TLS endpoints which support deprecated protocols like SSLv2, TLS 1.0 or even TLS 1.1.  This tool is meant to prove the concept of expanding our knowlege of certificate inventory, it was not meant to replace tools like `sslscan` or `nmap` to seek out vulnerabilities with deprecated protocol support.
- [openssl s_client](https://docs.openssl.org/1.0.2/man1/s_client/)
- [sslscan](https://github.com/rbsec/sslscan)
- [Nmap ssl-cert NSE](https://nmap.org/nsedoc/scripts/ssl-cert.html)


# Methods of Execution






## spki_python.console.crawl

The crawl module accesses a given host and completes the TCP and TLS handshake to obtain the server certificate.  Once these handshakes are complete, the session is dropped.  

> Note: 

```shell
$ python -m spki_python.console.crawl --help
usage: crawl.py [-h] [-v] [-n NAMESERVER] -iL INPUT_FILE -d DUMP_FOLDER

options:
  -h, --help            show this help message and exit
  -v, --verbose         Verbose output (-v is info, -vv is debug)
  -n NAMESERVER, --nameserver NAMESERVER
                        IP address of the name server to use for DNS resolution.

required arguments:
  -iL INPUT_FILE        Input file containing list of sites to assess.
  -d DUMP_FOLDER, --dump DUMP_FOLDER
                        Base folder to dump all artifacts to.
```

| Argument       | Description |
|----------------|-------------|
| `--nameserver` | Allows you to use a name server (DNS) of your choosing. |
| `-iL`          | Path to a text file consisting of a list of `domain` or `domain:port` assets. |
| `--dump`       | Folder to save all certificate and inventory files to.  See below for more details. |

The site list consists of a domain (`www.example.com`) and optional domain:port (`example.com:8443`), each on separate lines.  If no port is specified, port `443/tcp` is assumed.  The `crawl` module uses the `--dump` argument to save a variety of files to disk.  Below is a summary of the files and folders created followed by specific examples or descriptions of the fields.

| File or Folder | Description | Example |
|----------------|-------------|---------|
| `certificates.json`     | JSON file containing list of discovered certificates. | `certificates.json` | 
| `websites.json`         | JSON file containing a list of IPv4 and IPv6 addresses, with a listening TCP port, for a given domain. | `websites.json` | 
| `certs/`                | Folder where all certificates are stored. | `certs/` |
| `certs/certificate.der` | Binary encoded (DER) certificate.   | `certs/tls-v1-2.badssl.com_104.154.89.105_1012_sni_true.der` |
| `certs/certificate.pem` | Base64 encoded (ASCII) certificate. | `certs/tls-v1-2.badssl.com_104.154.89.105_1012_sni_true.pem` |

The script takes the list of domains and ports (443 assumed if unspecified) and seeks to identify IPv4 and IPv6 records in DNS.  The results of this discovery (again, just DNS lookup) are saved to the `websites.json` JSON file.  This is then used to perform the actual discovery of certificates.

```json
[
    {
        "Domain": "tls-v1-2.badssl.com",
        "Port": 1012,
        "DNS Records": [
            {
                "A": [
                    "104.154.89.105"
                ]
            },
            {
                "AAAA": []
            }
        ]
    }
]
```

The `certificates.json` contains a list of dictionaries representing the certificates discovered and a bit about _how_ or _where_ it was found.
- What IP address?
- What TCP port?
- Was ServerNameIndication (SNI) enabled?
- What parameters were used in the TLS handshake (protocol, cipher suite)?
- Basic information about the certificate, key type, and key length.
- And our favorites, certificate and SubjectPublicKeyInfo thumbprints (aka fingerprints)

```json
[
    {
        "Domain": "tls-v1-2.badssl.com",
        "Address": "104.154.89.105",
        "Port": 1012,
        "SNI": false,
        "Protocol": "TLSv1.2",
        "Cipher Suite": "ECDHE-RSA-AES256-GCM-SHA384",
        "Certificate": {
            "Key Type": "RSA",
            "Key Length": 2048,
            "PEM": "-----BEGIN CERTIFICATE-----\nMIIE9TCCA92gAwIBAgISA1ab7jTN4ycaUoDUKPwA/0ObMA0GCSqGSIb3DQEBCwUA\nMDMxCzAJBgNVBAYTAlVTMRYwFAYDVQQKEw1MZXQncyBFbmNyeXB0MQwwCgYDVQQD\nEwNSMTEwHhcNMjQwODA5MTUwNTQ0WhcNMjQxMTA3MTUwNTQzWjAXMRUwEwYDVQQD\nDAwqLmJhZHNzbC5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCd\nKl6MexmrIYkfRqx7vdbFaZbnR3XrZSSavFBpbAJEai04zUz4Zz40XB/+GhAHxvPi\nsjBBoMTeIM4sxIhXy1gqbL2WckFpvBOBNII+smLJoonUM9LA8i14fv8jqQTjHQye\nZtDdlM/PRh+orS1Wwg8L3507sDGH7Ex6QEmUiHGTXluqCDUjyGcuQyuc5xZUNdJm\nUZKnVWMbja6RLnecueTBlGfzwZMU/hFXtcZMCuE+FFCwyVYacFfNhMm3ckV5hwFc\nhFBfo3lQzJ8hYLTKMABjXyR+WTPxjriZRYFWOYRcQI15Bo8taAYDh6lXcj5A71QF\ntrlIxPAm57yaVs54c8VdAgMBAAGjggIdMIICGTAOBgNVHQ8BAf8EBAMCBaAwHQYD\nVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMAwGA1UdEwEB/wQCMAAwHQYDVR0O\nBBYEFA17gxGErjYsooUaK+vPPbg1gnv8MB8GA1UdIwQYMBaAFMXPRqTq9MPAemyV\nxC2wXpIvJuO5MFcGCCsGAQUFBwEBBEswSTAiBggrBgEFBQcwAYYWaHR0cDovL3Ix\nMS5vLmxlbmNyLm9yZzAjBggrBgEFBQcwAoYXaHR0cDovL3IxMS5pLmxlbmNyLm9y\nZy8wIwYDVR0RBBwwGoIMKi5iYWRzc2wuY29tggpiYWRzc2wuY29tMBMGA1UdIAQM\nMAowCAYGZ4EMAQIBMIIBBQYKKwYBBAHWeQIEAgSB9gSB8wDxAHYAPxdLT9ciR1iU\nHWUchL4NEu2QN38fhWrrwb8ohez4ZG4AAAGRN+IpPwAABAMARzBFAiEAlOextQPh\n6MzDGzxHzPpPdQSZ16fY0aywyCZCc7Jn97QCIFtgQR4Mln3moYmnspFkbYdScPWL\nFnBQC/DiehhdarEYAHcAdv+IPwq2+5VRwmHM9Ye6NLSkzbsp3GhCCp/mZ0xaOnQA\nAAGRN+IpkgAABAMASDBGAiEA/l8+xhtC9tWAQ9OszOIfH34qXgQYgPp88fjoqlxu\nrKMCIQC9HK+l/Vv0/51JDd9J71Hh58OmCJ9cV3LbFrlRAgEC6zANBgkqhkiG9w0B\nAQsFAAOCAQEAZ7Vcj83IL5Vs0wEC7DPR+maB78xyNgnCMIKcySlYxzWU0rNd30jI\nhnrFlDafM1+yB9Qlp3pI0Dgu5zBPL9BbRh9Y4AQhg0ybgqNH2mY/MWYtm+RtKK+e\nXsCmdSTxZfhfUsUirdC3EIhMwTFdFOGib+6IOYLuwS+20CRUoG4EvZkt/J/qtxMD\norLpVkbESmgUIKtdEbK2+JlL9/RgDRM7TETMy8tKkQtzk56kFf+2MOvHmWS0gi8J\nSZSaZjYuvxRMqgXWgZu1HX3TCwwg7AfGE0VgTJUw3Sps/NvNVzITt/0zf5WvBLrT\nN/s9EaN5iVVgKwn1dC0sYoIoY0v/iv4/eg==\n-----END CERTIFICATE-----\n",
            "Subject": "CN=*.badssl.com",
            "Issuer": "CN=R11,O=Let's Encrypt,C=US",
            "Serial Number": "03:56:9B:EE:34:CD:E3:27:1A:52:80:D4:28:FC:00:FF:43:9B",
            "Not Before": "2024-08-09 15:05:44+00:00",
            "Not After": "2024-11-07 15:05:43+00:00",
            "SPKI Digests": [
                {
                    "SHA256": "4A:BB:5A:BB:A0:EF:7A:FC:00:A9:DA:AB:AC:34:05:54:85:57:FA:5D:C7:CC:4D:76:88:00:30:DC:44:75:FA:38"
                }
            ],
            "Fingerprints": [
                {
                    "SHA256": "FA:A1:63:1B:64:7C:2D:3A:33:67:F7:FA:45:B8:9D:0D:A2:56:F0:F2:9F:9F:8D:D3:30:39:D5:5E:AD:29:D6:27"
                }
            ]
        },
        "Status": "Success",
        "Error Message": null
    }
]
```

Discovered certificates are saved to the `certs/` folder.  Filenames are structured using the following fields, separated by the underscore (`_`) character.  These are saved for offline analysis with other tools if necessary (e.g. `openssl`).

| Field        | Description                               | Example                     |
|--------------|-----------------------------------------|-------------------------------|
| `DOMAIN`     | Domain to assess.                       | `tls-v1-2.badssl.com`         |
| `IP ADDRESS` | IP address of the Domain.               | `104.154.89.105`              |
| `TCP PORT`   | Listening TCP port.                     | `443`                         | 
| `SNI STATE`  | ServerNameIndication true or false.     | `sni_true`                    |
| `ENCODING`   | Extension by encoding (ASCII or Binary) | `.pem` or `.der` respectively |

In the below execution examples, we save our list of domains or targets in the same folder where we plan to _dump_ our data.  This is done to record the scope of of that particular assessment.  It helps to look back sometimes and see what the context had been months prior compared to what is discovered more recently.

### crawl Execution Examples

### badssl.com
```shell
FOLDER=tests/data/badssl/`date '+%Y-%m-%d'`
mkdir -p ${FOLDER}
DOMAINS=${FOLDER}/domains.txt

curl -s https://badssl.com/ \
| grep -Eo '<a href="(.*badssl\.com.*?)"' \
| awk -F '/' '{print $3}' \
| { echo "www.badssl.com"; echo "badssl.com"; cat -; } \
| grep 'badssl' \
| sort | uniq > "${DOMAINS}"

```

1. Define the base `FOLDER` path to save all artifacts.
2. Define the `DOMAINS` file path to save our domain list.
3. Using `curl` we access the `badssl.com` default web page.
    - Look for any HTML `a href` tags
    - Use `awk` to return only the domain and port information from the link
    - Ensure the top-level and redirect domains are included using the `echo` command
        - must include `cat -` to include previous `STDOUT` with `echo` commands.
    - Remove any domains not related to `badssl.com`.
    - Sort and save only unique records to the domain list file.

Next, we can crawl the domains to obtain the certificates for each.

 
```shell
python -m spki_python.console.crawl -vv -iL ${DOMAINS} -d ${FOLDER}
```


#### Other Sites

```shell
# Set some folder and file context.
FOLDER=tests/data/example/`date '+%Y-%m-%d'`
mkdir -p ${FOLDER}
DOMAINS=${FOLDER}/domains.txt

# Create a list of domains
cat <<EOF > "$DOMAINS"
badssl.com
www.badssl.com
tls-v1-2.badssl.com:1012
EOF

# Crawl the domains
python -m spki_python.console.crawl -vv -iL ${DOMAINS} -d ${FOLDER}
```
