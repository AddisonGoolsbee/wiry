"""DHCPv6: scapy's object tree over the Rust DHCP6 layer, and the two agreeing.

Every message is hand-built from RFC 8415, never captured and never produced
by running scapy.
"""

import wiry
from wiry import (
    DHCP6, DHCP6_Advertise, DHCP6_RelayForward, DHCP6_Reply, DHCP6_Solicit,
    DHCP6OptClientArchType, DHCP6OptClientId, DHCP6OptDNSServers,
    DHCP6OptElapsedTime, DHCP6OptIA_NA, DHCP6OptIAAddress, DHCP6OptOptReq,
    DHCP6OptRelayMsg, DHCP6OptServerId, DHCP6OptStatusCode, DHCP6OptVSS,
    DUID_LL, DUID_LLT, IPv6, UDP, Ether, Raw, rdpcap, wrpcap,
)

# RFC 8415 §18.2.1 Solicit, transaction id 0x0a0b0c: Client Identifier
# carrying a DUID-LL (§11.4) for 00:11:22:33:44:55, Option Request for 23 and
# 24, Elapsed Time 0.
SOLICIT = bytes([
    0x01, 0x0A, 0x0B, 0x0C,
    0x00, 0x01, 0x00, 0x0A, 0x00, 0x03, 0x00, 0x01,
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
    0x00, 0x06, 0x00, 0x04, 0x00, 0x17, 0x00, 0x18,
    0x00, 0x08, 0x00, 0x02, 0x00, 0x00,
])

# Rust's names for the option codes RFC 8415 §21 gives.
RUST_OPT = {1: "clientid", 2: "serverid", 3: "IA_NA", 6: "oro", 8: "elapsedtime",
            9: "relaymsg", 13: "status", 23: "dnsservers"}


def frame(msg, sport=546, dport=547):
    return Ether(bytes(Ether() / IPv6() / UDP(sport=sport, dport=dport) / Raw(msg)))


def test_a_solicit_dissects_into_scapys_classes():
    pkt = frame(SOLICIT)
    assert pkt.layers() == ["Ether", "IPv6", "UDP", "DHCP6_Solicit",
                            "DHCP6OptClientId", "DHCP6OptOptReq",
                            "DHCP6OptElapsedTime"]
    sol = pkt[DHCP6_Solicit]
    assert sol.msgtype == 1 and sol.trid == 0x0A0B0C
    assert isinstance(pkt[DHCP6OptClientId].duid, DUID_LL)
    assert pkt[DHCP6OptClientId].duid.lladdr == "00:11:22:33:44:55"
    assert pkt[DHCP6OptOptReq].reqopts == [23, 24]
    assert bytes(pkt[UDP].payload) == SOLICIT


def test_the_rust_layer_still_answers_to_its_name():
    pkt = frame(SOLICIT)
    assert DHCP6 not in pkt
    assert "DHCP6" in pkt
    assert pkt["DHCP6"].msgtype == 1
    assert [n for n, _ in pkt["DHCP6"].options] == ["clientid", "oro", "elapsedtime"]


def test_a_relayed_message_reaches_the_inner_one():
    """RFC 8415 §9.1 Relay-forward carrying the Solicit in a Relay Message."""
    relay = bytes([0x0C, 0x00]) + bytes(32) + bytes([0x00, 0x09]) + \
        len(SOLICIT).to_bytes(2, "big") + SOLICIT
    pkt = frame(relay, 547, 547)
    assert isinstance(pkt[DHCP6_RelayForward], DHCP6_RelayForward)
    assert isinstance(pkt.message, DHCP6_Solicit)
    assert pkt.message.trid == 0x0A0B0C


def test_stacking_writes_the_ports_each_direction_uses():
    """RFC 8415 §7.2: clients listen on 546, servers and relays on 547."""
    assert (UDP() / DHCP6_Solicit()).dport == 547
    adv = UDP() / DHCP6_Advertise()
    assert (adv.sport, adv.dport) == (547, 546)
    rep = UDP() / wiry.DHCP6_AddrRegReply()
    assert (rep.sport, rep.dport) == (547, 546)


def test_a_message_built_then_read_back_is_the_same_message():
    pkt = (Ether() / IPv6() / UDP() / DHCP6_Reply(trid=9)
           / DHCP6OptServerId(duid=DUID_LLT(lladdr="00:00:5e:00:53:01"))
           / DHCP6OptIA_NA(iaid=1, ianaopts=[
               DHCP6OptIAAddress(addr="2001:db8::5", preflft=300, validlft=600),
               DHCP6OptStatusCode(statuscode=0, statusmsg=b"ok")]))
    again = Ether(bytes(pkt))
    assert again.layers()[3:] == ["DHCP6_Reply", "DHCP6OptServerId", "DHCP6OptIA_NA"]
    addr, status = again[DHCP6OptIA_NA].ianaopts
    assert addr.addr == "2001:db8::5" and addr.validlft == 600
    assert status.statusmsg == b"ok"
    assert bytes(again) == bytes(pkt)


def test_writing_through_the_rust_layer_redecodes_the_model():
    pkt = frame(SOLICIT)
    assert pkt[DHCP6_Solicit].trid == 0x0A0B0C
    pkt.trid = 7
    assert pkt[DHCP6_Solicit].trid == 7
    pkt[DHCP6OptElapsedTime].elapsedtime = 9
    assert bytes(pkt)[-2:] == b"\x00\x09"
    assert pkt["DHCP6"].trid == 7


def test_a_short_address_list_stops_instead_of_raising():
    """RFC 8415 §21.1 bounds the option; a stray tail is not an address."""
    opt = DHCP6OptDNSServers(b"\x00\x17\x00\x14" + bytes(15) + b"\x01" + b"\xde\xad\xbe\xef")
    assert opt.dnsservers == ["::1"]


def test_vss_data_excludes_its_type_octet():
    """RFC 6607 §3.4: option-len counts the type octet and the data."""
    opt = DHCP6OptVSS(b"\x00\x44\x00\x03\x01ab\x00\x08\x00\x02\x00\x00")
    assert opt.type == 1 and opt.data == b"ab"
    assert isinstance(opt.payload, DHCP6OptElapsedTime)


def test_the_bulk_path_and_the_object_tree_agree(tmp_path):
    frames = [
        Ether() / IPv6() / UDP(sport=546, dport=547) / Raw(SOLICIT),
        Ether() / IPv6() / UDP() / DHCP6_Solicit(trid=0x123456)
        / DHCP6OptClientId(duid=DUID_LL(lladdr="00:00:5e:00:53:02"))
        / DHCP6OptClientArchType(archtypes=[7]),
        Ether() / IPv6() / UDP() / DHCP6_RelayForward(
            hopcount=2, linkaddr="2001:db8::1", peeraddr="fe80::2")
        / DHCP6OptRelayMsg(message=DHCP6_Solicit(trid=5)),
        Ether() / IPv6() / UDP() / DHCP6_Reply(trid=3)
        / DHCP6OptDNSServers(dnsservers=["2001:db8::53"]),
    ]
    path = tmp_path / "dhcp6.pcap"
    wrpcap(str(path), frames)
    pl = rdpcap(str(path))
    cols = pl.columns([(DHCP6, f) for f in
                       ("msgtype", "trid", "hopcount", "linkaddr", "peeraddr", "options")])
    for i in range(len(frames)):
        msg = pl[i][UDP].payload
        assert cols["DHCP6.msgtype"][i] == msg.msgtype, i
        relay = msg.msgtype in (12, 13)
        assert cols["DHCP6.trid"][i] == (None if relay else msg.trid), i
        for f in ("hopcount", "linkaddr", "peeraddr"):
            assert cols[f"DHCP6.{f}"][i] == (getattr(msg, f) if relay else None), i
        opts = []
        opt = msg.payload
        while opt:
            raw = bytes(opt)[: 4 + opt.optlen]
            opts.append((RUST_OPT.get(opt.optcode, str(opt.optcode)), raw[4:]))
            opt = opt.payload
        assert cols["DHCP6.options"][i] == opts, i
    assert len(pl.filter(DHCP6, where=[(DHCP6, "msgtype", "==", 7)])) == 1
