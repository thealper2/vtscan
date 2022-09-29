
# VTSCAN

Scan hashes, urls and ip addresses using VirusTotal API. writes the report to a .txt file after scanning.
#
## Usage

#### Run the following command to install the required modules.

```http
  pip3 install -r requirements.txt
```

| Parameter | Tip      | Açıklama                                 |
| :-------- | :------- | :--------------------------------------- |
| `-h`      | `--help` | Shows the help menu.                     |
| `-k`      | `--key`  | **Required**. VirusTotal API Key.       |
| `-x`      | `--hash` | Hash (MD5, SHA-1, SHA-256).              |
| `-i`      | `--ip`   | IP Address                               |
| `-u`      | `--url`  | URL.                                     |

#### Examples

```http
  python3 vtscan.py -k 'VT_API_KEY' -x 'HASH'
```

```http
  python3 vtscan.yp -k 'VT_API_KEY' -u 'URL'
```
