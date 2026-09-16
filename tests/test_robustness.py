"""Hostile input: no entry point may panic or allocate without a bound."""

import pytest

import packetry
from packetry import IP, TCP

_b = packetry._packetry


def pkt():
    return IP() / TCP() / b"payload"


@pytest.mark.parametrize("layer", [3, 99, 2**32])
def test_payload_past_the_stack_raises(layer):
    p = pkt()._materialize()
    with pytest.raises(IndexError):
        p.payload(layer)


@pytest.mark.parametrize("layer", [3, 99, 2**32])
def test_set_payload_past_the_stack_raises(layer):
    p = pkt()._materialize()
    with pytest.raises(IndexError):
        p.set_payload(layer, b"x")


def test_payload_within_the_stack_still_works():
    p = pkt()._materialize()
    assert p.payload(0) == bytes(TCP() / b"payload")


@pytest.mark.parametrize("fn", [_b.build_packet, _b.build_and_serialize])
def test_building_with_no_layers_raises(fn):
    with pytest.raises(ValueError):
        fn([], [], [], [], b"x", [])
