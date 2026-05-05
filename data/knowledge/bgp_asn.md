# BGP and ASN basics

An Autonomous System Number, or ASN, identifies a network that participates in internet routing. BGP is the protocol used by autonomous systems to exchange route information.

Useful ASN/BGP checks:

- Which ASN announces a prefix.
- Whether the ASN belongs to a hosting provider, ISP, CDN, university, enterprise, or government network.
- Which prefixes are announced by an ASN.
- Whether the IP belongs to a route that makes sense for the claimed provider.

BGP data can change over time. A route observed in one database may lag behind real-time routing changes. For incident analysis, compare RIPEstat, route collectors, traceroute, and provider information.
