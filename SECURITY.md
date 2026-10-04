# Security

Report vulnerabilities privately to savagetism@icloud.com — do not open
public issues for exploitable weaknesses.

Scope: will signature verification, order scoping and invocation bounds, heartbeat/dead-man arithmetic, custodian attestation quorum logic, execution-log hash-chaining.

Out of scope: custodian honesty (a hostile quorum can certify death early — mitigate by choosing custodians across trust domains), and what executed orders DO — orders are opaque scoped strings (see THREAT_MODEL.md).
