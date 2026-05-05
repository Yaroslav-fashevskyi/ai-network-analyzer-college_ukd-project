# IP risk rules

IP reputation should be interpreted as a set of signals, not as a final verdict. A public IP can belong to a CDN, cloud provider, hosting provider, ISP customer, VPN exit node, NAT gateway, mail server, or enterprise network. The same IP can host many unrelated services.

Important signals:

- GeoIP and ASN show network ownership and approximate routing context, not the physical location of a person.
- RDAP shows registry information, allocation dates, abuse contacts, and organization fields when available.
- DNSBL listing may indicate spam or abuse history, but false positives are possible.
- Reverse DNS that matches provider naming can be normal for hosting IPs.
- Open ports do not automatically mean compromise. They show exposed services that require correct configuration and updates.
- High packet loss or unstable latency may indicate filtering, congestion, ICMP deprioritization, or a real network issue.

For risk scoring, combine multiple independent signals. A single weak signal should not be treated as proof.
