"""`AnsweringMachine`: what it answers, checked without answering anything.

The split that makes this testable is the same one the active tools use — what
counts as a request and what the reply is are arithmetic over packets, and only
the sending needs an interface. `replies_to` runs that arithmetic over a list.
"""

import pytest

from wiry import ARP, AnsweringMachine, Ether, IP, TCP, UDP


class ArpResponder(AnsweringMachine):
    function_name = "fake_arpd"
    filter = "arp"

    def parse_options(self, mac="aa:bb:cc:dd:ee:ff"):
        self.mac = mac

    def is_request(self, req):
        return "ARP" in req.layers() and req["ARP"].op == 1

    def make_reply(self, req):
        arp = req["ARP"]
        return (Ether(dst=arp.hwsrc, src=self.mac) /
                ARP(op=2, hwsrc=self.mac, psrc=arp.pdst,
                    hwdst=arp.hwsrc, pdst=arp.psrc))


def who_has(target="10.0.0.9"):
    return Ether(src="11:22:33:44:55:66") / ARP(
        op=1, hwsrc="11:22:33:44:55:66", psrc="10.0.0.1", pdst=target)


def test_a_machine_answers_the_requests_it_recognises():
    am = ArpResponder(verbose=0)
    replies = am.replies_to([who_has(), Ether() / IP() / TCP()])
    assert len(replies) == 1
    assert replies[0]["ARP"].op == 2
    assert replies[0]["ARP"].hwsrc == "aa:bb:cc:dd:ee:ff"
    assert replies[0]["ARP"].pdst == "10.0.0.1"


def test_a_packet_that_is_not_a_request_draws_no_reply():
    am = ArpResponder(verbose=0)
    reply = who_has()
    reply["ARP"].op = 2
    assert am.replies_to([reply]) == []


def test_a_machine_with_nothing_to_say_sends_nothing():
    class Silent(ArpResponder):
        function_name = ""

        def make_reply(self, req):
            return None

    assert Silent(verbose=0).replies_to([who_has()]) == []


def test_its_own_options_reach_parse_options():
    am = ArpResponder(mac="00:11:22:33:44:55", verbose=0)
    assert am.replies_to([who_has()])[0]["ARP"].hwsrc == "00:11:22:33:44:55"


def test_a_machine_is_published_under_its_function_name():
    from wiry import ansmachine

    assert ansmachine.fake_arpd.__name__ == "fake_arpd"


def test_a_machine_with_no_make_reply_cannot_be_built():
    class Abstract(AnsweringMachine):
        pass

    with pytest.raises(TypeError):
        Abstract()


def test_the_sniff_keywords_are_kept_apart_from_the_send_keywords():
    am = ArpResponder(verbose=0, store=0, iface="eth0", inter=1)
    assert am.defoptsniff["iface"] == "eth0"
    assert am.defoptsniff["store"] == 0
    assert am.defoptsend["inter"] == 1
    assert am.defoptsend["verbose"] == 0
    assert am.defoptsniff["filter"] == "arp"


def test_a_reply_prints_a_summary_only_when_asked(capsys):
    ArpResponder(verbose=0).replies_to([who_has()])
    assert capsys.readouterr().out == ""
    am = ArpResponder(verbose=1)
    am.reply(who_has(), send_function=lambda _: None)
    assert "ARP" in capsys.readouterr().out


def test_a_machine_can_answer_on_a_source_other_than_an_interface():
    """What ``offline=`` buys: the whole reply path, driven from a capture."""
    class UdpEcho(AnsweringMachine):
        function_name = ""

        def is_request(self, req):
            return "UDP" in req.layers()

        def make_reply(self, req):
            ip, udp = req["IP"], req["UDP"]
            return (Ether() / IP(src=ip.dst, dst=ip.src) /
                    UDP(sport=udp.dport, dport=udp.sport))

    pkts = [Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / UDP(sport=5, dport=53)]
    out = UdpEcho(verbose=0).replies_to(pkts)
    assert out[0]["UDP"].dport == 5 and out[0]["IP"].dst == "10.0.0.1"
