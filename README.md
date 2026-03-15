What it ignores (noise filtering)

The following are automatically stripped before extraction so they don't produce false-positive IPs:

| Noise type              | Example                                         |
|------------------------|-------------------------------------------------|
| Email addresses        | `john.doe@corp.com`                             |
| URLs                   | `https://10.x.x.x/api/v2` — IP is still extracted|
| Dates                  | `2024-12-01`, `01/12/2024`                     |
| Version strings        | `version: 2.10.3.1`, `v1.0.5`, `RHEL 8.9`      |
| IP:port references     | `10.0.0.1:8443` — port stripped, IP kept       |
| Ticket references      | `RITM0012345`, `INC001`, `KB00123`, `CHG`, `REQ`, `PRB`|
| FQDNs                 | `api.vendor.com` — ignored entirely             
