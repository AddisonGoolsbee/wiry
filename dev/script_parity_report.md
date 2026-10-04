# Script parity: wiry against scapy

Real scapy code, run twice under scapy 2.7.0 and once under wiry, statement by
statement, comparing printed output, `bytes()`, every field of every layer and
every exception. Measured on `feat/script-parity` after merging main at
`fbbeb50` (output parity and utils parity both in).

**Headline: 183 of 2,730 judged scripts (6.7%) produce output identical to
scapy's.** None of the 25 idiomatic scripts does yet; 15 of 83 judged doc
transcripts do; 168 of 2,622 judged `.uts` blocks do. One `.uts` block flips
between runs (183 or 184) in a way the two scapy runs do not catch. The pass
rate is low because the bar is total: one differing character in one `show()`
fails the script. The `cumulative` column is the useful number: fixing the
first four rows alone takes the corpus from 183 to about 1,050.

## What to aim at, by workstream

Each item names the row(s) of the generated table it explains. Counts are
scripts broken; a script broken by two causes counts under both.

### Rendering

1. **`show()` and `show2()` end with one newline; scapy ends with two** (row 3,
   260 scripts, 39 sessions; the top cause in the idiomatic corpus, 19 of 25).
   scapy prints a blank line after the last layer. One-line fix, largest
   cheap win on the board.
2. **`summary()` differs mostly through `IP.src`** (row 13, 65): an `IP(dst=...)`
   built by scapy takes its source from the routing table (`10.0.0.103` on
   this host); wiry writes `127.0.0.1`. The same default shows up as `IP.src`
   under row 16. wiry has the kernel table (E26), so this is reachable. It is
   host-dependent by nature: scapy's own answer changes with the machine.
3. **Packets that come back from `fragment()`, `defragment()` and
   `IPSession` are fully built under wiry, templates under scapy** (rows 19,
   23: `repr()` shows `ihl`, `len`, `chksum`, `src` that scapy omits, `show()`
   prints values where scapy prints `None`). scapy copies the original's
   unset fields into each fragment; wiry hands back wire bytes.
4. Layer-specific text: TLS, RADIUS, 802.11, LDAP `summary()`/`repr()`/`show()`
   (rows 24, 27, 33, 35, 41, 50, 53): enums printed as numbers (`TLS.type`,
   `TLS.version`, `802.11.subtype`), missing `mysummary` for TLS and RADIUS,
   802.11 addresses rendered differently.
5. Smaller: `PacketList` repr names (row 45), `ls()`/`lsc()` text (row 63),
   `json()` (4), `hexdump()`/`linehexdump()` (1 each).

### Layers and field semantics

1. **An unset computed field reads back `0` under wiry, `None` under scapy**
   (row 4, 236 scripts, 32 sessions): `IP().chksum`, `.len`, `.ihl`,
   `TCP().chksum`, `.dataofs`, `IPv6().plen`, `UDP().len`, `Ether().dst`.
   `show()` already prints `None` for these, so attribute access now disagrees
   with wiry's own `show()`. Second-largest cheap win.
2. **Missing layer classes**, by scapy module: `inet6` (row 1, 403 —
   `ICMPv6EchoRequest`/`EchoReply`, node information, mobile IPv6, ND
   options), `dhcp6` (row 2, 340), `bluetooth` (81), `dns` (73 — **`DNSQR` and
   `DNSRR` are not importable names**, though wiry dissects them, plus EDNS0
   and DNSSEC records), `ntp` (72), `dot11` (54), `eap` (46), `bluetooth4LE`
   (36), `sctp` chunks (26), `zigbee` (25), `dot15d4`, `ppp`, `msrpce`,
   `dcerpc`, `netflow`, `pptp`, `smb`, `sixlowpan`, `netbios`, `ntlm`, `smb2`.
   Rows 1 and 2 alone are worth 711 scripts, almost all `sole`.
3. **Layers scapy dissects that wiry leaves as Raw** (row 5, 201): NTP
   control/private modes, `Dot11FCS`, SMB, Kerberos, ICMPv6 echo.
4. **`layers()` reports a trailing `Raw` after DNS** (row 38, 21 of 23) that
   `repr()` does not show and scapy does not have.
5. **wiry dissects TCP port 80 as HTTP; `scapy.all` in 2.7.0 does not load
   `scapy.layers.http`, so scapy says Raw** (row 31, 13 of 26; 10 of the 25
   idiomatic scripts). Whether to match the default session or keep the
   richer dissection is a decision, not a bug fix.
6. **Different layer models**: ND options, RADIUS attributes and TLS records
   are an `options` field in wiry and sub-layers or packet-list fields in
   scapy (rows 14, 15, 18: `TLS.iv/mac/msg/pad`, `Radius.attributes`,
   `ICMPv6ND_NS.options`).
7. **Inactive conditional fields raise `AttributeError`** where scapy returns
   `None` (row 28, 36: `ICMP.gw`, `ICMP.addr_mask`, ... on an echo). Inflated
   by the harness, which reads every field scapy declares; few scripts read
   `gw` off an echo request.
8. `Packet` methods scripts call (row 9, 76): `hashret` (12), `root`, `copy`
   on a layer view, plus fields of layers wiry models differently.
9. Built bytes differ (rows 20, 40): MPLS over Ethernet, ND, VXLAN, IPv6
   routing header, DNS.
10. **`DNS(qd=[])` raises `ValueError: an empty list generates no packets`**
    (in row 74): an empty list given to a list-valued field is taken as an
    empty generator.

### Utilities

`scapy.fields` classes (row 6, 108 — scripts that declare their own layers),
`conf` attributes (row 21, 49: `ifaces`, `contribs`, `mib`, `exts`),
`load_module` (20), `RandUUID` and other volatiles (20), `p0f_impersonate`
(12), `EField` (12), `scapy.arch` internals, `StringBuffer`, `SecurityAssociation`.

### ASN.1 and TLS

ASN.1: `scapy.asn1` (row 7, 84: `ASN1_GENERALIZED_TIME`, `BER_Decoding_Error`,
`BERcodec_INTEGER`, `ASN1_UTC_TIME`), `x509` (24), `kerberos` (12),
`asn1fields`, `asn1packet`, `snmp`. TLS: names (row 10, 74: `PrivKey`,
`Cert`, `CSR`, handshake messages) plus the field and rendering differences
in the layers list above.

## Reading the numbers

- **The oracle is scapy 2.7.0; the campaigns are scapy master.** 693 blocks
  are skipped because 2.7.0 itself fails them. They are not counted against
  wiry.
- **272 blocks are skipped because scapy needs `cryptography`**, which this
  venv lacks. Installing it would bring TLS, Kerberos and IPsec examples into
  judgement; expect the TLS and ASN.1 rows to grow.
- FIELD rows come from reading every field scapy declares on every packet a
  script binds, not only the ones the script prints. Weight them below a
  RENDER or API row of the same count.
- `IP.src`, `Ether.src` and anything derived from them depend on the host's
  routes and interfaces, under scapy and under wiry.
- A cascade (141) is a block that failed only because an earlier block in
  its session failed under wiry. It counts against the rate and is not ranked.
- The wiry run resolves every `scapy.*` import, at any depth, to wiry. The
  scoreboard leak fixed on main in `f68b52a` (a `from scapy.layers.x import`
  executing real scapy) cannot happen here.

<!-- everything below is generated by dev/script_parity.py -->

Generated by `dev/script_parity.py` on 2026-10-04 at wiry `f294e94`, scapy 2.7.0 as the oracle, scapy master checkout at `/tmp/scapy-src` for the doc and `.uts` corpora. Regenerate with `python dev/script_parity.py --report dev/script_parity_report.md`.

A *script* is one idiomatic program, one doc transcript, or one `.uts` test block. `cascade` means wiry failed only because an earlier block in the same session failed under wiry; those count against the rate and are not ranked.

| corpus | sessions | scripts | pass | differ | cascade | skip | rate |
|---|---:|---:|---:|---:|---:|---:|---:|
| scripts | 25 | 25 | 0 | 25 | 0 | 0 | 0.0% |
| doc | 23 | 286 | 15 | 66 | 2 | 203 | 18.1% |
| uts | 83 | 3831 | 168 | 2315 | 139 | 1209 | 6.4% |
| **total** | 131 | 4142 | 183 | 2406 | 141 | 1412 | 6.7% |

## Scripts broken, by owning area

A script broken by causes in two areas counts in both.

| area | scripts |
|---|---:|
| layers | 1819 |
| rendering | 382 |
| utilities | 283 |
| asn1 | 126 |
| behaviour | 124 |
| tls | 74 |

## Causes, ranked by scripts broken

`sole`: scripts this cause alone keeps from passing. `cumulative`: scripts that would pass with this row and every row above it fixed, on top of today's passes. A cascade is counted as passing once its session's other causes are gone, which is optimistic.

| # | scripts | sole | cumulative | sessions | area | cause | where (scripts) |
|---:|---:|---:|---:|---:|---|---|---|
| 1 | 403 | 372 | 555 | 3 | layers | API: names missing from scapy.layers.inet6 | MIP6MH_BU (17), ICMPv6NIQueryIPv4 (14), ICMPv6NIQueryName (14), ICMPv6NIReplyIPv6 (14), ICMPv6NIQueryIPv6 (13), ICMPv6EchoRequest (12), ICMPv6NIReplyIPv4 (12), ICMPv6EchoReply (11), +69 more |
| 2 | 340 | 338 | 893 | 1 | layers | API: names missing from scapy.layers.dhcp6 | DHCP6OptClientId (14), DHCP6OptServerId (12), DHCP6_Solicit (8), DHCP6OptClientArchType (7), DHCP6OptIA_NA (7), DHCP6OptIA_PD (7), DHCP6OptSIPDomains (7), DHCP6OptBCMCSDomains (6), +66 more |
| 3 | 260 | 29 | 922 | 39 | rendering | RENDER: show() trailing blank lines differ | 2 vs 1 (260) |
| 4 | 236 | 0 | 1051 | 32 | layers | FIELD: unset field reads back computed (scapy: None) | IP.chksum (170), IP.len (170), IP.ihl (169), TCP.chksum (157), TCP.dataofs (156), IPv6.plen (49), Ether.dst (25), UDP.chksum (22), +38 more |
| 5 | 201 | 10 | 1083 | 27 | layers | DISSECT: a layer scapy dissects is not in wiry | NTPPrivate (45), Dot11FCS (19), NTPControl (18), NTPHeader (8), SMB_Header (6), Dot11Elt (5), Kerberos (5), ICMPv6EchoRequest (3), +75 more |
| 6 | 108 | 108 | 1191 | 8 | utilities | API: names missing from scapy.fields | ByteField (17), ScalingField (17), UUIDField (7), FieldLenField (6), YesNoByteField (5), MultiFlagsField (4), BitField (3), FieldValueRangeException (3), +35 more |
| 7 | 84 | 84 | 1275 | 5 | asn1 | API: names missing from scapy.asn1 | ASN1_GENERALIZED_TIME (25), BER_Decoding_Error (12), BERcodec_INTEGER (10), ASN1_UTC_TIME (9), BERcodec_Object (3), ASN1_INTEGER (2), ASN1_OID (2), ASN1_SEQUENCE (2), +16 more |
| 8 | 81 | 81 | 1356 | 2 | layers | API: names missing from scapy.layers.bluetooth | HCI_Hdr (63), HCI_Mon_Pcap_Hdr (5), EIR_Hdr (3), HCI_Event_Hdr (3), SM_Hdr (2), BluetoothHCISocket, HCI_Command_Hdr, HCI_Event_Inquiry_Result, +2 more |
| 9 | 76 | 13 | 1394 | 20 | layers | API: Packet lacks a field or attribute scapy has | hashret (12), root (7), protocolOp (6), attributes (5), msg (5), CtlCode (3), mysummary (3), pay (3), +26 more |
| 10 | 74 | 74 | 1468 | 5 | tls | API: names missing from scapy.layers.tls | PrivKey (9), Cert (5), CSR (3), TLSClientKeyExchange (3), Hmac_MD5 (2), PRF (2), TLSCertificateVerify (2), TLSClientHello (2), +41 more |
| 11 | 73 | 70 | 1538 | 9 | layers | API: names missing from scapy.layers.dns | RRlist2bitmap (10), EDNS0TLV (7), DNSQR (6), DNSRR (5), DNSRROPT (5), EDNS0ClientSubnet (5), DNSRRDNSKEY (3), DNSRRNSEC3 (3), +21 more |
| 12 | 72 | 3 | 1610 | 1 | layers | API: names missing from scapy.layers.ntp | NTPPrivate (45), NTPControl (18), NTPHeader (8), NTPAuthenticator |
| 13 | 63 | 0 | 1615 | 29 | rendering | RENDER: summary() of a layer differs | 127.0.0.1 (14), TCP (11), 802.11 (6), HTTP (5), 00:01:02:03:04:05 (4), DNS (4), ICMPv6 (4), UDP (4), +9 more |
| 14 | 61 | 0 | 1616 | 19 | layers | FIELD: a field scapy has is missing in wiry | TLS.iv (9), TLS.mac (9), TLS.msg (9), TLS.pad (9), TLS.padlen (9), Dot11.FCfield2 (8), Dot11.FCfield_bw (8), Dot11.cfe (8), +212 more |
| 15 | 60 | 0 | 1616 | 15 | rendering | RENDER: show() shows a field scapy omits | TLS.options (9), ICMPv6 Neighbor Discovery - Neighbor Solicitation.options (8), RADIUS.options (8), ICMPv6 Neighbor Discovery - Router Advertisement.options (6), LDAP.vars (5), ICMPv6 Neighbor Discovery - Neighbor Advertisement.options (3), ICMPv6 Neighbor Discovery - Router Solicitation.options (3), PadN.len (3), +63 more |
| 16 | 59 | 0 | 1616 | 21 | layers | FIELD: field value differs | IP.src (19), IP.chksum (12), IPv6.hlim (9), Ether.src (6), IPv6.dst (5), TCP.chksum (5), ICMPv6ND_RA.prf (4), IPv6ExtHdrHopByHop.options (4), +47 more |
| 17 | 54 | 37 | 1670 | 1 | layers | API: names missing from scapy.layers.dot11 | Dot11Elt (13), Dot11Action (5), Dot11EltRSN (5), Dot11EltMicrosoftWPA (3), Dot11EltHTCapabilities (2), Dot11EltOBSS (2), Dot11EltVHTOperation (2), Dot11FCS (2), +17 more |
| 18 | 52 | 0 | 1679 | 13 | layers | FIELD: a field only wiry has | TLS.options (9), ICMPv6ND_NS.options (8), Radius.options (8), ICMPv6ND_RA.options (6), LDAP.vars (5), ICMPv6ND_NA.options (3), ICMPv6ND_RS.options (3), GRE.seqnum (2), +12 more |
| 19 | 52 | 0 | 1679 | 15 | rendering | RENDER: repr() shows a field scapy omits | IP.chksum (20), IP.ihl (20), IP.tos (20), IP.version (20), IP.flags (19), IP.id (19), IP.len (19), IP.src (17), +38 more |
| 20 | 50 | 0 | 1679 | 19 | layers | BYTES: built packet has different content | Ether/MPLS/IP (5), IP (5), Ether/IPv6/ICMPv6ND_NS (3), Ether/IPv6/ICMPv6ND_RA (2), IP/Raw (2), IP/TCP (2), IPv6/ICMPv6ND_NS (2), IPv6/IPv6ExtHdrHopByHop (2), +38 more |
| 21 | 49 | 43 | 1722 | 21 | utilities | API: conf lacks an attribute scapy has | ifaces (15), contribs (5), mib (5), exts (4), color_theme (3), tls_session_enable (3), wepkey (3), dot15d4_protocol (2), +8 more |
| 22 | 46 | 45 | 1768 | 2 | layers | API: names missing from scapy.layers.eap | EAPOL (19), EAP (15), EAP_MD5 (3), EAP_PEAP (3), LEAP (3), EAP_FAST, EAP_TLS, EAP_TTLS |
| 23 | 45 | 0 | 1774 | 17 | rendering | RENDER: show() layout differs | ihl = None (17), chksum = &lt;hex&gt; (10), src = &lt;ip&gt; (7), dataofs = None, extension = False, extension = True, hwsrc = &lt;mac&gt;, id = &lt;n&gt;, +11 more |
| 24 | 44 | 0 | 1781 | 16 | rendering | RENDER: repr() text differs | &lt;Ether dst=&lt;mac&gt; src=&lt;mac&gt; type=MPLS \|&lt;MPLS label=&lt;n&gt; cos=&lt;n&gt; s=&lt;n&gt; tt (6), &lt;IP version=&lt;n&gt; ihl=&lt;n&gt; tos=&lt;hex&gt; len=&lt;n&gt; id=&lt;n&gt; flags= frag=&lt;n&gt; ttl=&lt; (4), &lt;DNS qd=[&lt;DNSQR \|&gt;] \|&gt; (2), &lt;Dot11 type=Data \|&lt;LLC dsap=&lt;hex&gt; ssap=&lt;hex&gt; ctrl=&lt;n&gt; \|&lt;SNAP code=IPv4 (2), &lt;Ether dst=&lt;mac&gt; src=&lt;mac&gt; type=IPv4 \|&lt;IP frag=&lt;n&gt; proto=udp src=&lt;ip&gt;  (2), &lt;Ether dst=&lt;mac&gt; src=&lt;mac&gt; type=IPv6 \|&lt;IPv6 nh=ICMPv6 hlim=&lt;n&gt; src=753 (2), &lt;Ether dst=&lt;mac&gt; src=&lt;mac&gt; type=IPv6 \|&lt;IPv6 nh=ICMPv6 hlim=&lt;n&gt; src=::  (2), &lt;IPv6 version=&lt;n&gt; tc=&lt;n&gt; fl=&lt;n&gt; plen=&lt;n&gt; nh=ICMPv6 hlim=&lt;n&gt; src=fe80:e (2), +23 more |
| 25 | 39 | 0 | 1784 | 11 | rendering | RENDER: repr() omits a field scapy shows | Radius.type (8), Radius.value (8), TLS.comp (8), TLS.ext (8), TLS.extlen (8), TLS.gmt_unix_time (8), TLS.msglen (8), TLS.msgtype (8), +156 more |
| 26 | 39 | 0 | 1789 | 13 | rendering | RENDER: show() layer count differs | DNS / DNS Question Record (2), RADIUS / Radius Attribute / EAP-Message / Cisco LEAP / Message-Authenticator / State (2), RADIUS / User-Name / Service-Type / Vendor-Specific / Framed-MTU / Radius Attribute / Radius Attribute / EAP-Message / EAP / Message-Authenticator / Radius Attribute / Vendor-Specific / Vendor-Specific / Framed-IP-Address / NAS-IP-Address / Vendor-Specific / Radius Attribute / NAS-Port-Type / NAS-Port (2), Ethernet / IP / TCP / LDAP / LDAP_BindRequest / LDAP_Authentication_SaslCredentials / NTLM Negotiate, Ethernet / IP / TCP / LDAP / LDAP_BindResponse, Ethernet / IP / TCP / LDAP / LDAP_SearchRequest / LDAP_Filter / LDAP_FilterPresent, Ethernet / IP / TCP / LDAP / LDAP_UnbindRequest, Ethernet / IP / TCP / SSH - Binary Packet / Raw, +32 more |
| 27 | 36 | 36 | 1825 | 2 | layers | API: names missing from scapy.layers.bluetooth4LE | BTLE (34), BTLE_RF (2) |
| 28 | 36 | 0 | 1834 | 16 | layers | FIELD: reading the field raises under wiry | ICMP.addr_mask (25), ICMP.ext (25), ICMP.extpad (25), ICMP.gw (25), ICMP.length (25), ICMP.nexthopmtu (25), ICMP.ptr (25), ICMP.reserved (25), +13 more |
| 29 | 28 | 11 | 1854 | 5 | behaviour | VALUE: nested object rendered differently | cmco (12), w (4), bck_conf (2), conf.iface (2), r (2), reader (2), conf, conf_iface, +3 more |
| 30 | 26 | 3 | 1880 | 1 | layers | API: names missing from scapy.layers.sctp | SCTPChunkInit (3), SCTPChunkInitAck (2), SCTPChunkSACK (2), SCTPChunkAbort, SCTPChunkAddressConf, SCTPChunkAddressConfAck, SCTPChunkAuthentication, SCTPChunkCookieAck, +14 more |
| 31 | 26 | 6 | 1889 | 18 | layers | DISSECT: layer chain differs | HTTP where scapy has Raw (13), IGMP where scapy has Raw (3), Ether where scapy has IP (2), ICMP where scapy has Raw (2), Padding where scapy has IPv6ExtHdrHopByHop (2), TLS where scapy has Padding (2), UDP where scapy has Raw (2), Padding where scapy has Raw |
| 32 | 25 | 24 | 1914 | 1 | layers | API: names missing from scapy.layers.zigbee | ZEP2 (7), ZigbeeAppDataPayload (6), ZigbeeAppCommandPayload (5), ZigbeeNWKCommandPayload (4), ZCLGeneralReadAttributesResponse, ZCLIASZoneZoneEnrollResponse, ZigbeeClusterLibrary |
| 33 | 25 | 0 | 1914 | 8 | rendering | RENDER: show() enum or flag printed as a number | TLS.type (9), TLS.version (9), TLS.len (8), 802.11.subtype (7), IP.ttl (3), RadioTap.present (3), PPP Link Layer.proto, SMB2 Header.Flags, +1 more |
| 34 | 24 | 24 | 1938 | 2 | asn1 | API: names missing from scapy.layers.x509 | X509_Cert (4), OCSP_ResponseBytes (2), X509_AlgorithmIdentifier (2), X509_CRL (2), ASN1P_INTEGER, ASN1P_PRIVSEQ, OCSP_ByKey, OCSP_GoodInfo, +10 more |
| 35 | 24 | 1 | 1948 | 11 | rendering | RENDER: show() value differs | 802.11.addr1 (7), 802.11.addr2 (7), Ethernet.src (7), 802.11.addr3 (6), ICMPv6 Neighbor Discovery - Router Advertisement.prf (4), 802.11.type (2), ICMPv6 Neighbor Discovery - Neighbor Solicitation.cksum (2), SNAP.OUI (2), +10 more |
| 36 | 23 | 21 | 1971 | 1 | layers | API: names missing from scapy.layers.dot15d4 | Dot15d4 (13), Dot15d4FCS (8), Dot15d4AuxSecurityHeader (2) |
| 37 | 23 | 20 | 1994 | 2 | layers | API: names missing from scapy.layers.ppp | PPP_LCP_Configure (5), PPP_CHAP (4), PPP_PAP (2), HDLC, PPP_ECP, PPP_IPCP, PPP_LCP_Auth_Protocol_Option, PPP_LCP_Code_Reject, +7 more |
| 38 | 23 | 0 | 2003 | 14 | layers | DISSECT: wiry dissects a layer past where scapy stops | Raw after DNS (21), HTTP after TCP, Padding after TCP, Raw after Ether |
| 39 | 21 | 12 | 2023 | 4 | layers | API: names missing from scapy.layers.inet | IPerror (3), TCPAOValue (3), calc_tcp_md5_hash (3), IPOption (2), ICMPExtension_Header, ICMPTimeStampField, IPOption_RR, IPOption_SDBM, +6 more |
| 40 | 21 | 0 | 2025 | 8 | rendering | RENDER: repr() value differs | Radius.len (8), TLS.len (8), Radius.code (5), Radius.id (5), Dot11.addr2 (2), BOOTP.chaddr, Dot11.addr1, Dot11.addr3, +2 more |
| 41 | 20 | 20 | 2045 | 4 | layers | API: names missing from scapy.layers.msrpce | NetlogonSSP (4), DCERPC_Client (3), LPSHARE_INFO_1 (3), NetlogonClient (2), UPN_DNS_INFO (2), DCERPC_Server, DRS_EXTENSIONS_INT, ept_lookup_Request, +3 more |
| 42 | 20 | 18 | 2064 | 8 | utilities | API: names missing from scapy.main | load_module (15), _read_config_file (2), list_contrib (2), _usage |
| 43 | 20 | 20 | 2084 | 2 | utilities | API: names missing from scapy.volatile | RandUUID (14), CorruptedBytes, RandOID, RandRegExp, RandSingNum, RandSingString, RandomEnumeration |
| 44 | 20 | 0 | 2094 | 5 | rendering | RENDER: PacketList repr() differs | &lt;No name: TCP:&lt;n&gt; UDP:&lt;n&gt; ICMP:&lt;n&gt; Other:&lt;n&gt;&gt; (16), &lt;Sniffed: TCP:&lt;n&gt; UDP:&lt;n&gt; ICMP:&lt;n&gt; Other:&lt;n&gt;&gt; (4) |
| 45 | 18 | 18 | 2112 | 3 | layers | API: names missing from scapy.layers.dcerpc | DceRpc (10), DceRpc4 (3), NDRPacket (3), DceRpcSession, NDRContextHandle |
| 46 | 18 | 15 | 2130 | 2 | layers | API: names missing from scapy.layers.netflow | NetflowHeader (9), NetflowFlowsetV9 (2), NetflowOptionsFlowsetV9 (2), NetflowSession (2), netflowv9_defragment (2), NetflowTemplateV9 |
| 47 | 18 | 0 | 2136 | 11 | layers | BYTES: built packet has a different length | IPv6/IPv6ExtHdrRouting/TCP (4), DNS (2), Dot11 (2), ARP, Ether/IP/UDP/DNS, IP/UDP/DNS, IP/VRRP, IPv6/IPv6ExtHdrHopByHop/IPv6ExtHdrRouting, +7 more |
| 48 | 16 | 16 | 2152 | 2 | layers | API: names missing from scapy.layers.pptp | PPTPStartControlConnectionReply (2), PPTPCallClearRequest, PPTPCallDisconnectNotify, PPTPEchoReply, PPTPEchoRequest, PPTPIncomingCallConnected, PPTPIncomingCallReply, PPTPIncomingCallRequest, +7 more |
| 49 | 16 | 8 | 2168 | 2 | layers | API: names missing from scapy.layers.smb | NETLOGON (6), SMBMailslot_Write (2), SMBSession_Setup_AndX_Request_Extended_Security (2), SMBSession_Setup_AndX_Response_Extended_Security (2), SMBNegotiate_Request, SMBNegotiate_Response_Extended_Security, SMB_Header, _SMBGeneric |
| 50 | 16 | 0 | 2172 | 6 | rendering | RENDER: repr() enum or flag printed as a number | TLS.type (9), TLS.version (9), Dot11.subtype (3), IP.ttl (3), TLS.len, UDP.sport |
| 51 | 16 | 0 | 2175 | 9 | rendering | RENDER: show() omits a field scapy shows | IPv6 Extension Header - Hop-by-Hop Options Header.autopad (4), PadN.optdata (4), PadN.optlen (4), PadN.otype (4), IPv6 Extension Header - Destination Options Header.autopad (3), RadioTap.notdecoded (3), IPv6 Option Header Routing.addresses (2), IPv6 Option Header Routing.len (2), +53 more |
| 52 | 15 | 6 | 2185 | 8 | layers | DISSECT: wiry stops early where scapy dissects further | NBTSession after TCP (7), Ether after nothing (2), Raw after TCP (2), LDAP after LDAP, Padding after Dot1Q, SSH after SSH, SSH after TCP, TLS after TLS |
| 53 | 15 | 0 | 2199 | 4 | rendering | RENDER: summary() has no per-layer text (mysummary) | TLS (7), Radius (6), LDAP, Raw |
| 54 | 14 | 12 | 2213 | 1 | layers | API: names missing from scapy.layers.sixlowpan | SixLoWPAN (10), LoWPAN_IPHC (3), sixlowpan_fragment |
| 55 | 14 | 5 | 2222 | 10 | rendering | RENDER: printed value: value differs | str a.dst (2), str get_if_list()[i] (2), str iflist[i] (2), printed output, str a.src, str chain, str conf.route6.route('ff00::')[i], str conf_prog_tcpdump, +5 more |
| 56 | 13 | 13 | 2235 | 3 | utilities | API: a name scapy binds is missing from wiry | p0f_impersonate (12), nmap_udppacket_sig |
| 57 | 13 | 13 | 2248 | 2 | utilities | API: names missing from scapy.contrib | EField (12), EoMCW |
| 58 | 12 | 12 | 2260 | 3 | asn1 | API: names missing from scapy.layers.kerberos | KerberosTCPHeader (6), kpasswd (2), AuthorizationData, KRB_AP_REP, KRB_Ticket, Kerberos |
| 59 | 12 | 0 | 2265 | 5 | layers | FIELD: field value has a different Python type | VXLAN.flags (4), RadioTap.present (3), RTP.extension (2), Dot11.SC, PPP.proto, SMB2_Header.Flags |
| 60 | 12 | 3 | 2274 | 7 | behaviour | VALUE: a name is left unbound under wiry | p (2), packet (2), ch, conf_color_theme, i, k, line, sh, +2 more |
| 61 | 12 | 6 | 2284 | 6 | behaviour | VALUE: value differs | r4 (3), conf.route (2), len_r4 (2), conf.route6, len_r6, n, pkts[&lt;n&gt;].time, r6, +3 more |
| 62 | 11 | 11 | 2295 | 2 | layers | API: names missing from scapy.layers.netbios | NBNSHeader (7), NBTDatagram (2), NBNSQueryResponse, _nbns_cache |
| 63 | 11 | 3 | 2300 | 7 | rendering | RENDER: printed text differs | lsc(): IPID_count : Identify IP id values classes in a list of packets (2), ls(): AD_AND_OR : None, ls(): chksum : XShortField = (&lt;str&gt;), ls(): dport : ShortEnumField = (&lt;str&gt;), ls(): dst : DestMACField = None (&lt;str&gt;), ls(): len : ShortField = (&lt;str&gt;), ls(): sport : ShortEnumField = (&lt;str&gt;), ls(): sport : ShortEnumField = &lt;n&gt; (&lt;str&gt;), +11 more |
| 64 | 10 | 5 | 2310 | 7 | utilities | API: wiry refuses by design (NotImplementedError) | wiry has no reply rule for SCTP: answers() knows echo, ICMP errors, TC (2), TCPSession reassembles over a whole capture and has no per-packet form, conf.use_pcap cannot be changed: libpcap is the only capture backend w, these packets start with different link layers, or with one no link ty, wiry has no reply rule for BOOTP: answers() knows echo, ICMP errors, T, wiry has no reply rule for Dot11: answers() knows echo, ICMP errors, T, wiry has no reply rule for Dot11Auth: answers() knows echo, ICMP error, wiry has no reply rule for ICMPv6ND_NA: answers() knows echo, ICMP err, +1 more |
| 65 | 10 | 6 | 2318 | 7 | behaviour | EXC: wiry raises ValueError where scapy succeeds | an empty list generates no packets (3), cannot parse &lt;str&gt; for field &lt;str&gt; (3), TCP options are &lt;n&gt; octets; the header length field holds at most &lt;n&gt;, no layer named &lt;str&gt;; ls() lists them, unknown TCP option &lt;str&gt;, unknown layer &lt;str&gt; |
| 66 | 9 | 9 | 2327 | 2 | layers | API: names missing from scapy.layers.ntlm | NTLM_NEGOTIATE (3), NTLMSSP, NTLM_Header, NTLMv2_ComputeSessionBaseKey, NTLMv2_RESPONSE, NTOWFv2, SEALKEY |
| 67 | 9 | 9 | 2336 | 1 | layers | API: names missing from scapy.layers.smb2 | SMB2_Preauth_Integrity_Capabilities (3), SMB2_IOCTL_RESP_GET_DFS_Referral (2), SMB2_Negotiate_Protocol_Request (2), SMB2_Negotiate_Protocol_Response, SMB2_Query_Info_Response |
| 68 | 9 | 5 | 2344 | 7 | layers | BYTES: a bytes value differs | s (3), r (2), p, pickled, pkt, z |
| 69 | 9 | 0 | 2351 | 6 | rendering | RENDER: show() layer title differs | 'SSH' for 'SSH - Binary Packet' (2), 'IPv6 Extension Header - Destination Options Header' for 'PadN', 'IPv6 Extension Header - Fragmentation header' for 'IPv6 Option Header Routing', 'IPv6 Option Header Routing' for 'IPv6 Extension Header - Destination Options Header', 'IPv6 Option Header Routing' for 'PadN', 'Raw' for 'IP in ICMP', 'Raw' for 'KerberosTCPHeader', 'Raw' for 'PadN', +6 more |
| 70 | 9 | 3 | 2359 | 6 | behaviour | VALUE: list has a different length | l (2), result_ls (2), [layer.__name__ if isinstance(layer, type) else str(layer) for layer in unreach.layers()], [p for p in a], frags1, hosts, routes6[i][i] |
| 71 | 8 | 7 | 2366 | 2 | utilities | API: names missing from scapy.arch | _bsd_iff_flags (5), L3bpfSocket, compile_filter, open_pcap |
| 72 | 8 | 0 | 2374 | 2 | layers | API: names missing from scapy.layers.ipsec | SecurityAssociation (7), NON_ESP |
| 73 | 8 | 8 | 2382 | 3 | layers | API: names missing from scapy.layers.radius | RadiusAttribute (3), RadiusAttr_EAP_Message (2), RadiusAttr_Message_Authenticator, RadiusAttr_NAS_IP_Address, RadiusAttr_User_Name |
| 74 | 8 | 0 | 2382 | 5 | rendering | RENDER: repr() list value rendered differently | IPv6ExtHdrRouting.addresses (5), TCP.dport (2), DHCP.options |
| 75 | 8 | 0 | 2387 | 5 | rendering | RENDER: show() list value rendered differently | IPv6 Option Header Routing.addresses (5), TCP.dport (2), DHCP options.options |
| 76 | 8 | 4 | 2393 | 5 | behaviour | VALUE: result has a different type | list for plist (4), plist for packet (2), list for str, str for dict |
| 77 | 7 | 7 | 2400 | 2 | layers | API: names missing from scapy.layers.gssapi | GSSAPI_BLOB (7) |
| 78 | 7 | 6 | 2407 | 3 | layers | API: names missing from scapy.layers.l2 | Dot1AD (3), GRE_PPTP (2), ARPingResult, Dot3 |
| 79 | 7 | 0 | 2413 | 4 | behaviour | VALUE: packet list has a different length | pkts (4), l (2), packets |
| 80 | 6 | 6 | 2419 | 1 | layers | API: names missing from scapy.layers.http | HTTP_Client (5), HTTPRequest |
| 81 | 6 | 6 | 2425 | 2 | layers | API: names missing from scapy.layers.isakmp | ISAKMP (3), ISAKMP_payload_SA (2), ISAKMP_payload_Hash |
| 82 | 6 | 4 | 2431 | 2 | layers | API: names missing from scapy.layers.ldap | LDAP_Client (3), CLDAP, LDAP_BindRequest, LDAP_SearchRequest |
| 83 | 6 | 6 | 2437 | 1 | utilities | API: scapy submodule paths do not resolve under wiry | wiry.arch.bpf (4), scapy._SCAPY_PKG_DIR, scapy.autorun.autorun_commands |
| 84 | 6 | 3 | 2443 | 5 | behaviour | EXC: wiry raises IndexError where scapy succeeds | list assignment index out of range (2), no matching layer &lt;class &lt;str&gt;&gt; in packet (2), no matching layer slice(&lt;class &lt;str&gt;&gt;, &lt;n&gt;, None) in packet, packet index out of range |
| 85 | 6 | 0 | 2449 | 1 | behaviour | VALUE: wiry returns a dict where scapy returns an object | rrname (3), exchange, nextname, rdata |
| 86 | 5 | 4 | 2454 | 1 | layers | API: names missing from scapy.layers.llmnr | LLMNRResponse (3), LLMNRQuery (2) |
| 87 | 5 | 4 | 2459 | 4 | utilities | API: names missing from stdlib names scapy.all re-exports | DHCPOptions, Decimal, reduce, tzinfo, x509_oids_sets |
| 88 | 5 | 4 | 2464 | 3 | behaviour | EXC-MSG: same exception, different message | AttributeError (4), IndexError |
| 89 | 5 | 0 | 2466 | 3 | behaviour | EXC: building or printing the packet raises under wiry | KeyError: &lt;str&gt; (3), ValueError: an empty list generates no packets, ValueError: cannot parse &lt;str&gt; for field &lt;str&gt; |
| 90 | 5 | 0 | 2471 | 4 | rendering | RENDER: show() unset value printed as computed | Ethernet.dst (4), IP.chksum, IP.ihl, IP.len, TCP.chksum, TCP.dataofs |
| 91 | 5 | 0 | 2476 | 2 | behaviour | VALUE: wiry returns a int where scapy returns an object | Ext, MCS, NextProtocol, Rate, TXFlags |
| 92 | 4 | 0 | 2479 | 4 | layers | API: Packet lacks an attribute scapy has | ttl (3), chksum |
| 93 | 4 | 4 | 2483 | 3 | behaviour | EXC: scapy raises, wiry succeeds | ValueError: Interface &lt;str&gt; not found ! (3), TypeError: a bytes-like object is required, not &lt;str&gt; |
| 94 | 4 | 4 | 2487 | 1 | behaviour | EXC: wiry raises a different exception | PermissionError for ValueError (3), NotImplementedError for ValueError |
| 95 | 4 | 4 | 2491 | 1 | rendering | RENDER: json() differs | pkt.json() (4) |
| 96 | 4 | 0 | 2493 | 1 | behaviour | VALUE: wiry returns a non-packet where scapy returns a packet |  (2), None (2) |
| 97 | 3 | 3 | 2496 | 3 | utilities | API: TypeError under wiry (signature or type differs) | &lt;str&gt; object is not subscriptable, RandEnumKeys.__init__() got an unexpected keyword argument &lt;str&gt;, unsupported value for field &lt;str&gt;: NoneType |
| 98 | 3 | 2 | 2499 | 3 | utilities | API: names missing from scapy | scapy (2), _parse_tag |
| 99 | 3 | 3 | 2502 | 1 | utilities | API: names missing from scapy.autorun | autorun_get_text_interactive_session (3) |
| 100 | 3 | 3 | 2505 | 3 | utilities | API: names missing from scapy.base_classes | OID, ScopedIP, _ScopedIP |
| 101 | 3 | 3 | 2508 | 1 | layers | API: names missing from scapy.layers.l2tp | L2TP (3) |
| 102 | 3 | 3 | 2511 | 1 | layers | API: names missing from scapy.layers.lltd | LLTD, LLTDAttribute, LLTDAttributeMachineName |
| 103 | 3 | 3 | 2514 | 2 | layers | API: names missing from scapy.layers.smbclient | smbclient (3) |
| 104 | 3 | 3 | 2517 | 1 | layers | API: names missing from scapy.layers.vrrp | VRRPv3 (3) |
| 105 | 3 | 3 | 2520 | 2 | utilities | API: names missing from scapy.libs | MATPLOTLIB, _test_pyx, load_extcap |
| 106 | 3 | 3 | 2523 | 2 | utilities | API: names missing from scapy.sessions | StringBuffer (3) |
| 107 | 3 | 0 | 2526 | 1 | behaviour | EXC: wiry raises KeyError where scapy succeeds | &lt;str&gt; (3) |
| 108 | 3 | 0 | 2529 | 1 | rendering | RENDER: show() value printed as None | IP.ihl (3), IP.len (3), IP.chksum (2), TCP.chksum, TCP.dataofs, UDP.len |
| 109 | 3 | 0 | 2532 | 2 | behaviour | VALUE: wiry returns a list where scapy returns an object | _fix, layers, rdata |
| 110 | 2 | 1 | 2534 | 2 | utilities | API: AttributeError under wiry | __setstate__, no flag &lt;str&gt; |
| 111 | 2 | 2 | 2536 | 2 | asn1 | API: names missing from scapy.asn1fields | ASN1F_INTEGER, ASN1F_PACKET |
| 112 | 2 | 2 | 2538 | 1 | asn1 | API: names missing from scapy.asn1packet | ASN1_Packet (2) |
| 113 | 2 | 2 | 2540 | 1 | layers | API: names missing from scapy.layers.dhcp | DHCPOptionsField, RandDHCPOptions |
| 114 | 2 | 1 | 2542 | 1 | layers | API: names missing from scapy.layers.mgcp | MGCP (2) |
| 115 | 2 | 2 | 2544 | 1 | layers | API: names missing from scapy.layers.ppi | PPI (2) |
| 116 | 2 | 2 | 2546 | 1 | layers | API: names missing from scapy.layers.rip | RIPEntry (2) |
| 117 | 2 | 2 | 2548 | 1 | asn1 | API: names missing from scapy.layers.snmp | SNMPvarbind (2) |
| 118 | 2 | 2 | 2550 | 1 | layers | API: names missing from scapy.layers.ssh | Mpint, _ComaStrField |
| 119 | 2 | 2 | 2552 | 1 | layers | API: names missing from scapy.layers.tftp | TFTP_DATA, TFTP_read |
| 120 | 2 | 2 | 2554 | 2 | layers | API: names missing from scapy.layers.tuntap | LinuxTunPacketInfo, TunTapInterface |
| 121 | 2 | 1 | 2556 | 1 | utilities | API: names missing from scapy.packet | rfc, split_layers |
| 122 | 2 | 1 | 2558 | 2 | behaviour | BEHAVIOUR: assertion holds under scapy, fails under wiry | assert _test_select(), assert pkt.getlayer(LDAP, &lt;n&gt;) |
| 123 | 2 | 0 | 2559 | 2 | behaviour | VALUE: a predicate differs | _old_usepcap, bytes(whole[&lt;n&gt;]) == bytes(IP(bytes(big))) |
| 124 | 2 | 0 | 2561 | 2 | behaviour | VALUE: unset value printed as computed | pkt[IP].chksum, whole[&lt;n&gt;][IP].len |
| 125 | 2 | 0 | 2563 | 1 | behaviour | VALUE: wiry returns a NoneType where scapy returns an object | network_stats (2) |
| 126 | 2 | 1 | 2565 | 1 | behaviour | VALUE: wiry returns a str where scapy returns an object | name, network_name |
| 127 | 1 | 1 | 2566 | 1 | utilities | API: RandMAC lacks an attribute scapy has | _fix |
| 128 | 1 | 1 | 2567 | 1 | utilities | API: RandString lacks an attribute scapy has | _fix |
| 129 | 1 | 1 | 2568 | 1 | utilities | API: names missing from scapy.as_resolvers | AS_resolver_multi |
| 130 | 1 | 1 | 2569 | 1 | utilities | API: names missing from scapy.config | _version_checker |
| 131 | 1 | 0 | 2570 | 1 | utilities | API: names missing from scapy.interfaces | network_name |
| 132 | 1 | 1 | 2571 | 1 | layers | API: names missing from scapy.layers.hsrp | HSRPmd5 |
| 133 | 1 | 1 | 2572 | 1 | layers | API: names missing from scapy.layers.mobileip | MobileIP |
| 134 | 1 | 0 | 2573 | 1 | layers | API: names missing from scapy.layers.rtp | RTPExtension |
| 135 | 1 | 1 | 2574 | 1 | layers | API: names missing from scapy.layers.skinny | Skinny |
| 136 | 1 | 1 | 2575 | 1 | layers | API: names missing from scapy.layers.smbserver | smbserver |
| 137 | 1 | 1 | 2576 | 1 | layers | API: names missing from scapy.layers.spnego | SPNEGOSSP |
| 138 | 1 | 1 | 2577 | 1 | utilities | API: names missing from scapy.pipetool | ConsoleSink |
| 139 | 1 | 1 | 2578 | 1 | utilities | API: names missing from scapy.scapypipes | SniffSource |
| 140 | 1 | 1 | 2579 | 1 | utilities | API: names missing from scapy.sendrecv | _parse_tcpreplay_result |
| 141 | 1 | 1 | 2580 | 1 | utilities | API: names missing from scapy.tools | TestCampaign |
| 142 | 1 | 1 | 2581 | 1 | behaviour | EXC: wiry raises PermissionError where scapy succeeds | permission denied opening en0: (cannot open BPF device) /dev/bpf0: Per |
| 143 | 1 | 0 | 2582 | 1 | layers | FIELD: field reads back differently (enum or flag printed as a number) | NTPHeader.orig |
| 144 | 1 | 0 | 2583 | 1 | layers | FIELD: field reads back differently (value differs) | VRRP.chksum |
| 145 | 1 | 0 | 2583 | 1 | rendering | RENDER: hexdump() differs | hexdump(), hexdump(pkt, dump=True) |
| 146 | 1 | 0 | 2584 | 1 | rendering | RENDER: linehexdump() differs | linehexdump(pkt, dump=True) |
| 147 | 1 | 0 | 2584 | 1 | rendering | RENDER: printed value: number printed as a name | printed output |
| 148 | 1 | 0 | 2584 | 1 | rendering | RENDER: repr() layer name differs | Dot11 for TypeError: |
| 149 | 1 | 0 | 2585 | 1 | rendering | RENDER: show() field order differs | VXLAN |
| 150 | 1 | 0 | 2586 | 1 | rendering | RENDER: show() text differs | &lt;TypeError: unhashable type: &lt;str&gt;&gt; |
| 151 | 1 | 0 | 2587 | 1 | rendering | RENDER: show2() trailing blank lines differ | 2 vs 1 |
| 152 | 1 | 0 | 2588 | 1 | rendering | RENDER: summary() layer count differs | Ether |
| 153 | 1 | 0 | 2589 | 1 | behaviour | VALUE: dict has different keys | chains |

## Not judged

| scripts | reason |
|---:|---|
| 626 | scapy 2.7.0 fails here (NameError) |
| 240 | scapy needs its environment (ModuleNotFoundError) |
| 49 | needs needs_root |
| 48 | scapy 2.7.0 fails here (AttributeError) |
| 42 | needs a linux host |
| 38 | needs netaccess |
| 32 | scapy needs its environment (ImportError) |
| 26 | uses PipeEngine |
| 23 | uses sr |
| 19 | uses send |
| 19 | scapy 2.7.0 fails here (ImportError) |
| 17 | uses sniff |
| 16 | uses load_layer |
| 16 | uses sr1 |
| 14 | uses subprocess |
| 14 | scapy 2.7.0 fails here (AssertionError) |
| 13 | uses load_contrib |
| 11 | uses Automaton |
| 9 | calls .recv() |
| 8 | scapy 2.7.0 fails here (Exception) |
| 8 | scapy 2.7.0 fails here (RuntimeError) |
| 7 | uses traceroute |
| 7 | uses AsyncSniffer |
| 7 | scapy 2.7.0 fails here (KeyError) |
| 6 | calls .sr() |
