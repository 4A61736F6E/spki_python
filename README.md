# spki_python
Proof-of-concept python code supporting X.509 SubjectPublicKeyInfo research.

The intent of this project has been to extend the research performed by `spki_openssl` but using Python to access live hosts as a form of inventory gathering.  


This project relies on stock cryptographic libraries available to Python and the underlying operating system.  This being said, these modules may not connect to TLS endpoints which support deprecated protocols like SSLv2, TLS 1.0 or even TLS 1.1.  This tool is meant to prove the concept of expanding our knowlege of certificate inventory, it was not meant to replace tools like `sslscan` or `nmap` to seek out vulnerabilities with deprecated protocol support.
- [openssl s_client](https://docs.openssl.org/1.0.2/man1/s_client/)
- [sslscan](https://github.com/rbsec/sslscan)
- [Nmap ssl-cert NSE](https://nmap.org/nsedoc/scripts/ssl-cert.html)


# Methods of Execution


## spki_python.console.spki_python



## spki_python.console.crawl

The crawl module accesses a given host and completes the TCP and TLS handshake to obtain the server certificate.  Once these handshakes are complete, the session is dropped.  

> Note: 

```shell
$ python -m spki_python.console.crawl --help
usage: crawl.py [-h] [-v] [-n NAMESERVER] -iL INPUT_FILE -d DUMP_FOLDER [--digest-algorithm DIGEST_ALGORITHM]

options:
  -h, --help            show this help message and exit
  -v, --verbose         Verbose output (-v is info, -vv is debug)
  -n NAMESERVER, --nameserver NAMESERVER
                        IP address of the name server to use for DNS resolution.
  --digest-algorithm DIGEST_ALGORITHM
                        Digest algorithm(s) for the thumbprint calculation.

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
        "Domain": "badssl.com",
        "Port": 443,
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
    },
    {
        "Domain": "www.badssl.com",
        "Port": 443,
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
    },
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
        "Domain": "badssl.com",
        "Address": "104.154.89.105",
        "Port": 443,
        "SNI": true,
        "Protocol": "TLSv1.2",
        "Cipher Suite": "ECDHE-RSA-AES128-GCM-SHA256",
        "Certificate": {
            "PEM": "-----BEGIN CERTIFICATE-----\n[REDACTED_FOR_BREVITY_SAKE]\n-----END CERTIFICATE-----\n",
            "Certificate Thumbprint": {
                "sha256": "faa1631b647c2d3a3367f7fa45b89d0da256f0f29f9f8dd33039d55ead29d627",
                "sha1": "0e9ca203f0af6caeb121174c2c89e25a409a3c9f",
                "md5": "ef3a1bc5a6dfd43af27bee273cc49278"
            },
            "Key Type": "RSA",
            "Key Size": 2048,
            "Subject": "CN=*.badssl.com",
            "Issuer": "CN=R11,O=Let's Encrypt,C=US",
            "Serial Number": "3569bee34cde3271a5280d428fc00ff439b",
            "Validity Period": {
                "Not Before": "2024-08-09T15:05:44+00:00",
                "Not After": "2024-11-07T15:05:43+00:00"
            },
            "SPKI Thumbprint": {
                "sha256": "4abb5abba0ef7afc00a9daabac3405548557fa5dc7cc4d76880030dc4475fa38",
                "sha1": "e066ac9bbee0d7892eb7d5b3c2ca0055d734f080",
                "md5": "b9822d2282d45fc4be98916ec5e99555"
            }
        },
        "Status": "Success",
        "Error Message": null
    },
    {
        "Domain": "badssl.com",
        "Address": "104.154.89.105",
        "Port": 443,
        "SNI": false,
        "Protocol": "TLSv1.2",
        "Cipher Suite": "ECDHE-RSA-AES128-GCM-SHA256",
        "Certificate": {
            "PEM": "-----BEGIN CERTIFICATE-----\n[REDACTED_FOR_BREVITY_SAKE]\n-----END CERTIFICATE-----\n",
            "Certificate Thumbprint": {
                "sha256": "d073b38943b36bd970ec8f61b3a1aea66e58eff160daee143bcb9d9967867813",
                "sha1": "3e9cce49eec17bf15bf891a3ae9f3712e0ba42e9",
                "md5": "8045ad81dc742d26c1f82f59a0dcc599"
            },
            "Key Type": "RSA",
            "Key Size": 2048,
            "Subject": "CN=badssl-fallback-unknown-subdomain-or-no-sni,O=BadSSL Fallback. Unknown subdomain or no SNI.,L=San Francisco,ST=California,C=US",
            "Issuer": "CN=BadSSL Intermediate Certificate Authority,O=BadSSL,L=San Francisco,ST=California,C=US",
            "Serial Number": "cdbc5a4aec9767b1",
            "Validity Period": {
                "Not Before": "2016-08-08T21:17:05+00:00",
                "Not After": "2018-08-08T21:17:05+00:00"
            },
            "SPKI Thumbprint": {
                "sha256": "f522e496c72fccc623f1ffb9da5a79cdefe16340851f22d23d0cd2a58608066f",
                "sha1": "7965dfc93c6ae6fe8381ec482216ec44ef47282a",
                "md5": "336ea6e08c7507def3a25ee9cd202e73"
            }
        },
        "Status": "Success",
        "Error Message": null
    },
    {
        "Domain": "www.badssl.com",
        "Address": "104.154.89.105",
        "Port": 443,
        "SNI": false,
        "Protocol": "TLSv1.2",
        "Cipher Suite": "ECDHE-RSA-AES128-GCM-SHA256",
        "Certificate": {
            "PEM": "-----BEGIN CERTIFICATE-----\n[REDACTED_FOR_BREVITY_SAKE]\n-----END CERTIFICATE-----\n",
            "Certificate Thumbprint": {
                "sha256": "d073b38943b36bd970ec8f61b3a1aea66e58eff160daee143bcb9d9967867813",
                "sha1": "3e9cce49eec17bf15bf891a3ae9f3712e0ba42e9",
                "md5": "8045ad81dc742d26c1f82f59a0dcc599"
            },
            "Key Type": "RSA",
            "Key Size": 2048,
            "Subject": "CN=badssl-fallback-unknown-subdomain-or-no-sni,O=BadSSL Fallback. Unknown subdomain or no SNI.,L=San Francisco,ST=California,C=US",
            "Issuer": "CN=BadSSL Intermediate Certificate Authority,O=BadSSL,L=San Francisco,ST=California,C=US",
            "Serial Number": "cdbc5a4aec9767b1",
            "Validity Period": {
                "Not Before": "2016-08-08T21:17:05+00:00",
                "Not After": "2018-08-08T21:17:05+00:00"
            },
            "SPKI Thumbprint": {
                "sha256": "f522e496c72fccc623f1ffb9da5a79cdefe16340851f22d23d0cd2a58608066f",
                "sha1": "7965dfc93c6ae6fe8381ec482216ec44ef47282a",
                "md5": "336ea6e08c7507def3a25ee9cd202e73"
            }
        },
        "Status": "Success",
        "Error Message": null
    },
    {
        "Domain": "www.badssl.com",
        "Address": "104.154.89.105",
        "Port": 443,
        "SNI": true,
        "Protocol": "TLSv1.2",
        "Cipher Suite": "ECDHE-RSA-AES128-GCM-SHA256",
        "Certificate": {
            "PEM": "-----BEGIN CERTIFICATE-----\n[REDACTED_FOR_BREVITY_SAKE]\n-----END CERTIFICATE-----\n",
            "Certificate Thumbprint": {
                "sha256": "faa1631b647c2d3a3367f7fa45b89d0da256f0f29f9f8dd33039d55ead29d627",
                "sha1": "0e9ca203f0af6caeb121174c2c89e25a409a3c9f",
                "md5": "ef3a1bc5a6dfd43af27bee273cc49278"
            },
            "Key Type": "RSA",
            "Key Size": 2048,
            "Subject": "CN=*.badssl.com",
            "Issuer": "CN=R11,O=Let's Encrypt,C=US",
            "Serial Number": "3569bee34cde3271a5280d428fc00ff439b",
            "Validity Period": {
                "Not Before": "2024-08-09T15:05:44+00:00",
                "Not After": "2024-11-07T15:05:43+00:00"
            },
            "SPKI Thumbprint": {
                "sha256": "4abb5abba0ef7afc00a9daabac3405548557fa5dc7cc4d76880030dc4475fa38",
                "sha1": "e066ac9bbee0d7892eb7d5b3c2ca0055d734f080",
                "md5": "b9822d2282d45fc4be98916ec5e99555"
            }
        },
        "Status": "Success",
        "Error Message": null
    },
    {
        "Domain": "tls-v1-2.badssl.com",
        "Address": "104.154.89.105",
        "Port": 1012,
        "SNI": false,
        "Protocol": "TLSv1.2",
        "Cipher Suite": "ECDHE-RSA-AES256-GCM-SHA384",
        "Certificate": {
            "PEM": "-----BEGIN CERTIFICATE-----\n[REDACTED_FOR_BREVITY_SAKE]\n-----END CERTIFICATE-----\n",
            "Certificate Thumbprint": {
                "sha256": "faa1631b647c2d3a3367f7fa45b89d0da256f0f29f9f8dd33039d55ead29d627",
                "sha1": "0e9ca203f0af6caeb121174c2c89e25a409a3c9f",
                "md5": "ef3a1bc5a6dfd43af27bee273cc49278"
            },
            "Key Type": "RSA",
            "Key Size": 2048,
            "Subject": "CN=*.badssl.com",
            "Issuer": "CN=R11,O=Let's Encrypt,C=US",
            "Serial Number": "3569bee34cde3271a5280d428fc00ff439b",
            "Validity Period": {
                "Not Before": "2024-08-09T15:05:44+00:00",
                "Not After": "2024-11-07T15:05:43+00:00"
            },
            "SPKI Thumbprint": {
                "sha256": "4abb5abba0ef7afc00a9daabac3405548557fa5dc7cc4d76880030dc4475fa38",
                "sha1": "e066ac9bbee0d7892eb7d5b3c2ca0055d734f080",
                "md5": "b9822d2282d45fc4be98916ec5e99555"
            }
        },
        "Status": "Success",
        "Error Message": null
    },
    {
        "Domain": "tls-v1-2.badssl.com",
        "Address": "104.154.89.105",
        "Port": 1012,
        "SNI": true,
        "Protocol": "TLSv1.2",
        "Cipher Suite": "ECDHE-RSA-AES256-GCM-SHA384",
        "Certificate": {
            "PEM": "-----BEGIN CERTIFICATE-----\n[REDACTED_FOR_BREVITY_SAKE]\n-----END CERTIFICATE-----\n",
            "Certificate Thumbprint": {
                "sha256": "faa1631b647c2d3a3367f7fa45b89d0da256f0f29f9f8dd33039d55ead29d627",
                "sha1": "0e9ca203f0af6caeb121174c2c89e25a409a3c9f",
                "md5": "ef3a1bc5a6dfd43af27bee273cc49278"
            },
            "Key Type": "RSA",
            "Key Size": 2048,
            "Subject": "CN=*.badssl.com",
            "Issuer": "CN=R11,O=Let's Encrypt,C=US",
            "Serial Number": "3569bee34cde3271a5280d428fc00ff439b",
            "Validity Period": {
                "Not Before": "2024-08-09T15:05:44+00:00",
                "Not After": "2024-11-07T15:05:43+00:00"
            },
            "SPKI Thumbprint": {
                "sha256": "4abb5abba0ef7afc00a9daabac3405548557fa5dc7cc4d76880030dc4475fa38",
                "sha1": "e066ac9bbee0d7892eb7d5b3c2ca0055d734f080",
                "md5": "b9822d2282d45fc4be98916ec5e99555"
            }
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

Let us crawl the top-level web site of https://badssl.com for any links to related badssl.com subdomains.

```shell
FOLDER=tests/data/badssl/grrcon
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

With our list of domains, and domain port numbers, we can use the Python `crawl` module to complete a TLS handshake and retrieve the site X.509 certificate.
 
```shell
python -m spki_python.console.crawl -vv -iL ${DOMAINS} -d ${FOLDER} --digest-algorithm sha256,sha1,md5
```


### badssl.com short example

```shell
# Set some folder and file context.
FOLDER=tests/data/badssl/`date '+%Y-%m-%d'`
mkdir -p ${FOLDER}
DOMAINS=${FOLDER}/domains.txt

# Create a list of domains
cat <<EOF > "$DOMAINS"
badssl.com
www.badssl.com
tls-v1-2.badssl.com:1012
EOF

# Crawl the domains
python -m spki_python.console.crawl -vv -iL ${DOMAINS} -d ${FOLDER} --digest-algorithm sha256,sha1,md5
```
