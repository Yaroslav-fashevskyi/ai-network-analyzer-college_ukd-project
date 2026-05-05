# DNS and TLS interpretation

DNS records describe how a domain is routed and which services are delegated.

Common records:

- A and AAAA point a domain to IPv4 and IPv6 addresses.
- MX records define mail exchangers.
- NS records show authoritative name servers.
- TXT records often contain SPF, DKIM, DMARC, site verification, or operational metadata.
- SOA describes the start of authority for a DNS zone.

TLS certificates prove that a server can present a certificate for a domain, but they do not prove that the service is trustworthy. Important certificate fields are issuer, subject alternative names, validity period, and expiration date.

Red flags:

- expired certificate;
- certificate not matching the domain;
- no HTTPS on a public web service;
- missing MX/TXT records for a domain that claims to send mail;
- suspiciously inconsistent DNS and RDAP ownership context.
