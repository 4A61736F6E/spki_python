# spki_python
Proof-of-concept python code supporting X.509 SubjectPublicKeyInfo research.

The intent of this project has been to extend the research performed by [`spki_openssl`](https://github.com/4A61736F6E/spki_openssl) but using Python to access live hosts as a form of inventory gathering.  


This project relies on stock cryptographic libraries available to Python and the underlying operating system.  This being said, these modules may not connect to TLS endpoints which support deprecated protocols like SSLv2, TLS 1.0 or even TLS 1.1.  This tool is meant to prove the concept of expanding our knowlege of certificate inventory, it was not meant to replace tools like `sslscan` or `nmap` to seek out vulnerabilities with deprecated protocol support.
- [openssl s_client](https://docs.openssl.org/1.0.2/man1/s_client/)
- [sslscan](https://github.com/rbsec/sslscan)
- [Nmap ssl-cert NSE](https://nmap.org/nsedoc/scripts/ssl-cert.html)


# Methods of Execution


## spki_python.console.spki_python

The intent of the `spki_python` module is to match similar capabilities to those provided by the [`spki_openssl.sh`](https://github.com/4A61736F6E/spki_openssl/tree/main/bash) shell script.  The goal is to correlate file digests and compare those against digests of the public key material (or SubjectPublicKeyInfo field).

```shell
$ python -m spki_python.console.spki_python --help
usage: spki_python.py [-h] [-v] [--private-key PRIVATE_KEY] [--signing-request SIGNING_REQUEST] [--signed-public-key SIGNED_PUBLIC_KEY]
                      [--password PASSWORD] [--digest-algorithm DIGEST_ALGORITHM] [--output OUTPUT]

Python module comparing certificate and SubjectPublicKeyInfo thumbprints

options:
  -h, --help            show this help message and exit
  -v, --verbose         Verbose output (-v is info, -vv is debug)
  --private-key PRIVATE_KEY
                        Path to private key file.
  --signing-request SIGNING_REQUEST
                        Path to signing request file.
  --signed-public-key SIGNED_PUBLIC_KEY
                        Path to signed public key file.
  --password PASSWORD   Password for the private key.
  --digest-algorithm DIGEST_ALGORITHM
                        Digest algorithm for the thumbprint calculation.
  --output OUTPUT       Output JSON file for the results.
```


### Setup using spki_openssl Files

The following is optional shell code which creates symbolic links to files used with the `spki_openssl` project.  The goal would be to identify the same certificate and key digests between OpenSSL and Python.  It should be noted that the raw file or certificate digest will be different between PEM and DER files due to the file encoding scheme used.  As an example, if seeking to validate operating system certificate or file digests, you need to use the Binary (DER) form of the certificate for a matching digest.

```shell
# Change directories to the root of te spki_project folder.

# sSet a couple environment varibles for ease of use in following script segments.
SOURCE_FOLDER='../../../spki_openssl/tests/demo'
WORKING_FOLDER='tests/demo'

# Create the working folder to play in.
mkdir -p $WORKING_FOLDER

# Create symbolic links.
ln -s $SOURCE_FOLDER/rsa_private-key.der $WORKING_FOLDER/rsa_private-key.der
ln -s $SOURCE_FOLDER/rsa_private-key.pem $WORKING_FOLDER/rsa_private-key.pem

ln -s $SOURCE_FOLDER/rsa_signing-request.der $WORKING_FOLDER/rsa_signing-request.der
ln -s $SOURCE_FOLDER/rsa_signing-request.pem $WORKING_FOLDER/rsa_signing-request.pem

ln -s $SOURCE_FOLDER/rsa_self-signed-public-key.der $WORKING_FOLDER/rsa_self-signed-public-key.der
ln -s $SOURCE_FOLDER/rsa_self-signed-public-key.pem $WORKING_FOLDER/rsa_self-signed-public-key.pem

ln -s $SOURCE_FOLDER/ec_private-key.der $WORKING_FOLDER/ec_private-key.der
ln -s $SOURCE_FOLDER/ec_private-key.pem $WORKING_FOLDER/ec_private-key.pem

ln -s $SOURCE_FOLDER/ec_signing-request.der $WORKING_FOLDER/ec_signing-request.der
ln -s $SOURCE_FOLDER/ec_signing-request.pem $WORKING_FOLDER/ec_signing-request.pem

ln -s $SOURCE_FOLDER/ec_self-signed-public-key.der $WORKING_FOLDER/ec_self-signed-public-key.der
ln -s $SOURCE_FOLDER/ec_self-signed-public-key.pem $WORKING_FOLDER/ec_self-signed-public-key.pem

# Use the `file` command to validate the symbolic links worked. 
file $WORKING_FOLDER/*.*
# If the links are broken, you should see a message similar to "broken symbolic link to".
# Ensure your relative paths to SOURCE or WORKING FOLDER variables is relative to the location, no necessarily from point of exection.

# Quick clean up if needed.
rm *.der; rm *.pem
```

### Example using RSA files

```shell
$ python -m spki_python.console.spki_python \
--private-key $WORKING_FOLDER/rsa_private-key.der \
--signing-request $WORKING_FOLDER/rsa_signing-request.der \
--signed-public-key $WORKING_FOLDER/rsa_self-signed-public-key.der \
--digest-algorithm sha1,sha256
```

The resulting output from the above command. 

```json
{
    "Private Keys": [
        {
            "File": {
                "Path": "tests/demo/rsa_private-key.der",
                "Size": 1218
            },
            "File Thumbprint": {
                "sha1": "471730ba6259bed2765260eed55ce4bae136ef7a",
                "sha256": "603b17e470431ac0284a6d71c1bb2836d8cd248e244870688e2325273559119a"
            },
            "Key Type": "RSA",
            "Key Size": 2048,
            "SPKI Thumbprint": {
                "sha1": "8390f87a7e27d3bd99732c07f4e1ae9a46bead47",
                "sha256": "294a9ad10b503ae60e072fa37ca18eb476f48068f7c57143dad31cfe878ba93d"
            }
        }
    ],
    "Signing Requests": [
        {
            "File": {
                "Path": "tests/demo/rsa_signing-request.der",
                "Size": 675
            },
            "File Thumbprint": {
                "sha1": "cc267ed28cc626e260e669edc10fa740e05666d4",
                "sha256": "ea9ec969c700cfd50f69edc1acd28a5d570590913660b790b6f9bef0ead6602b"
            },
            "Key Type": "RSA",
            "Key Size": 2048,
            "Subject": "CN=43984712-C33F-4A90-A793-0CCE6731DD66,O=WARNING: PRIVATE KEY MADE PUBLIC",
            "SPKI Thumbprint": {
                "sha1": "8390f87a7e27d3bd99732c07f4e1ae9a46bead47",
                "sha256": "294a9ad10b503ae60e072fa37ca18eb476f48068f7c57143dad31cfe878ba93d"
            }
        }
    ],
    "Signed Public Keys": [
        {
            "File": {
                "Path": "tests/demo/rsa_self-signed-public-key.der",
                "Size": 871
            },
            "File Thumbprint": {
                "sha1": "3ad29893f37c64513e26f0b5b1ccd2dccecbee1f",
                "sha256": "870a3f2add9649d698e2a8c9e306c7fda3586daa593095264779b684755c2bb5"
            },
            "Key Type": "RSA",
            "Key Size": 2048,
            "Subject": "CN=43984712-C33F-4A90-A793-0CCE6731DD66,O=WARNING: PRIVATE KEY MADE PUBLIC",
            "Serial Number": "7abf24c37b383c4b29c26bb96a6ebded17f90ad2",
            "Issuer": "CN=43984712-C33F-4A90-A793-0CCE6731DD66,O=WARNING: PRIVATE KEY MADE PUBLIC",
            "Validity Period": {
                "Not Before": "2024-11-20T01:49:00+00:00",
                "Not After": "2024-12-30T01:49:00+00:00"
            },
            "SPKI Thumbprint": {
                "sha1": "8390f87a7e27d3bd99732c07f4e1ae9a46bead47",
                "sha256": "294a9ad10b503ae60e072fa37ca18eb476f48068f7c57143dad31cfe878ba93d"
            }
        }
    ]
}
```

### Example using EC files

```shell
$ python -m spki_python.console.spki_python \
--private-key $WORKING_FOLDER/ec_private-key.der \
--signing-request $WORKING_FOLDER/ec_signing-request.der \
--signed-public-key $WORKING_FOLDER/ec_self-signed-public-key.der \
--digest-algorithm sha1,sha256
```

The resulting output from the above command. 

```json
{
    "Private Keys": [
        {
            "File": {
                "Path": "tests/demo/ec_private-key.der",
                "Size": 121
            },
            "File Thumbprint": {
                "sha1": "7e67d351002a00ab82c2dbdc9ddca52392c0b8a8",
                "sha256": "41af7f0e910d91dc1d1dd437c55f25c8ef0758acbc08b7ed3a61fa8a8f284710"
            },
            "Key Type": "EC",
            "Key Size": 256,
            "SPKI Thumbprint": {
                "sha1": "a7c731ef3c1d1b62b5e58647fa11e3e8360745cc",
                "sha256": "38eda0e609a7f1789babffd03ee6a11cd1f2cb22736c6bd80a63fabed528d1cc"
            }
        }
    ],
    "Signing Requests": [
        {
            "File": {
                "Path": "tests/demo/ec_signing-request.der",
                "Size": 281
            },
            "File Thumbprint": {
                "sha1": "818bba380a3b6b7003c1d1be37bde69b0b59ceea",
                "sha256": "f2d546d1e6e129b4905c6149c88d905a4b33e6b158c132668c682954b2bc7ba1"
            },
            "Key Type": "EC",
            "Key Size": 256,
            "Subject": "CN=3B29B0F8-E045-4827-9E0E-7333526607EE,O=WARNING: PRIVATE KEY MADE PUBLIC",
            "SPKI Thumbprint": {
                "sha1": "a7c731ef3c1d1b62b5e58647fa11e3e8360745cc",
                "sha256": "38eda0e609a7f1789babffd03ee6a11cd1f2cb22736c6bd80a63fabed528d1cc"
            }
        }
    ],
    "Signed Public Keys": [
        {
            "File": {
                "Path": "tests/demo/ec_self-signed-public-key.der",
                "Size": 475
            },
            "File Thumbprint": {
                "sha1": "742d3c2558fc2ec3250a0c366c4d6689773dc3d1",
                "sha256": "21ccd5a9bc80137ade4783efa1511e52c6099e228cc0474434f3dcfb76757db6"
            },
            "Key Type": "EC",
            "Key Size": 256,
            "Subject": "CN=3B29B0F8-E045-4827-9E0E-7333526607EE,O=WARNING: PRIVATE KEY MADE PUBLIC",
            "Serial Number": "3189a99064661c99bdcf9546b0b4306c35dfefc2",
            "Issuer": "CN=3B29B0F8-E045-4827-9E0E-7333526607EE,O=WARNING: PRIVATE KEY MADE PUBLIC",
            "Validity Period": {
                "Not Before": "2024-11-20T01:49:38+00:00",
                "Not After": "2024-12-30T01:49:38+00:00"
            },
            "SPKI Thumbprint": {
                "sha1": "a7c731ef3c1d1b62b5e58647fa11e3e8360745cc",
                "sha256": "38eda0e609a7f1789babffd03ee6a11cd1f2cb22736c6bd80a63fabed528d1cc"
            }
        }
    ]
}
```

## Merging JSON Files

You can use the Linux JSON parser `jq` to merge the file structures together.  In the following example the above `rsa.json` and `ec.json` files are combined into a single `merged.json` file.  Perhaps not the prettiest but . . . _a_ way of doing things.

```shell
jq -s 'reduce .[] as $item ({};
      . * {
          "Private Keys": (.["Private Keys"] + $item["Private Keys"]),
          "Signing Requests": (.["Signing Requests"] + $item["Signing Requests"]),
          "Signed Public Keys": (.["Signed Public Keys"] + $item["Signed Public Keys"])
      })' rsa.json ec.json > merged.json
```

## spki_python.console.crawl

The crawl module accesses a given host and completes the TCP and TLS handshake to obtain the server certificate.  Once these handshakes are complete, the session is dropped.  As a reminder, this module inherits from the security posture of Python crypographic libraries (usually based off of OpenSSL).  Accessing sites using insecure protocols (SSLv2, TLS 1.0, etc.) may not be supported.  This a proof-of-concept tool and not so much a hacking, vulnerability testing tool.


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
