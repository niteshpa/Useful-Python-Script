# ASG Parser
RITM ASG Parser
Parses a ServiceNow RITM description (plain text) and extracts valid IP addresses, IP ranges, and CIDRs into a JSON array that can be directly added to an existing Application Security Group (ASG) file in GitHub.
---
Requirements
Python 3.6+
No external dependencies — standard library only
---
Usage
```bash
# Output to default file (asg_additions.json)
python3 parse_ritm_asg.py ritm_description.txt

# Output to a specific file
python3 parse_ritm_asg.py ritm_description.txt my_app_asg.json
```
---
Output
A JSON array of ASG rule objects with placeholders for fields you need to fill in manually:
```json
[
  {
    "protocol": "<tcp/udp/all>",
    "destination": "10.20.30.45-10.20.30.48",
    "ports": "<PORT>",
    "description": "<DESCRIPTION>"
  },
  {
    "protocol": "<tcp/udp/all>",
    "destination": "10.99.0.0/24",
    "ports": "<PORT>",
    "description": "<DESCRIPTION>"
  },
  {
    "protocol": "<tcp/udp/all>",
    "destination": "10.20.31.10",
    "ports": "<PORT>",
    "description": "<DESCRIPTION>"
  }
]
```
Copy these objects into the existing ASG JSON array in your GitHub repo, then fill in `protocol`, `ports`, and `description` as appropriate.
---
What it extracts
Input in RITM description	Extracted as
`10.0.0.1`	Single IP
`10.0.0.1, 10.0.0.2, 10.0.0.3` (consecutive)	Consolidated range `10.0.0.1-10.0.0.3`
`10.0.0.1-10.0.0.5`	Range (dash)
`10.0.0.1 – 10.0.0.5`	Range (en-dash)
`10.0.0.1 to 10.0.0.5`	Range (word)
`10.0.0.1 through 10.0.0.5`	Range (word)
`10.0.0.0/24`	CIDR
> Non-consecutive IPs (e.g. `10.0.0.5` and `10.0.0.10`) are kept as separate single-IP rules and are **not** merged into a range.
---
What it ignores (noise filtering)
The following are automatically stripped before extraction so they don't produce false-positive IPs:
Noise type	Example
Email addresses	`john.doe@corp.com`
URLs	`https://10.x.x.x/api/v2` — IP is still extracted
Dates	`2024-12-01`, `01/12/2024`
Version strings	`version: 2.10.3.1`, `v1.0.5`, `RHEL 8.9`
IP:port references	`10.0.0.1:8443` — port stripped, IP kept
Ticket references	`RITM0012345`, `INC001`, `KB00123`, `CHG`, `REQ`, `PRB`
FQDNs	`api.vendor.com` — ignored entirely
---
Example RITM input
```
Please allow access for the below as part of Project Apollo onboarding.

DB servers: 10.20.30.45, 10.20.30.46, 10.20.30.47, 10.20.30.48
Batch cluster: 10.20.30.50 through 10.20.30.53
App pool: 172.16.5.10-172.16.5.20
Monitoring subnet: 10.99.0.0/24
DR node: 10.20.31.10

Requestor: john.doe@corp.com
Agent version: 2.10.3.1
Opened: 2024-12-01
Ref: RITM0098231
```
Output:
```json
[
  { "protocol": "<tcp/udp/all>", "destination": "10.20.30.45-10.20.30.48", "ports": "<PORT>", "description": "<DESCRIPTION>" },
  { "protocol": "<tcp/udp/all>", "destination": "10.20.30.50-10.20.30.53", "ports": "<PORT>", "description": "<DESCRIPTION>" },
  { "protocol": "<tcp/udp/all>", "destination": "10.99.0.0/24",            "ports": "<PORT>", "description": "<DESCRIPTION>" },
  { "protocol": "<tcp/udp/all>", "destination": "172.16.5.10-172.16.5.20", "ports": "<PORT>", "description": "<DESCRIPTION>" },
  { "protocol": "<tcp/udp/all>", "destination": "10.20.31.10",             "ports": "<PORT>", "description": "<DESCRIPTION>" }
]
```
