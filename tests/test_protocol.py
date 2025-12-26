import argparse

import pytest

from tests._helpers import FakeSocket
from tlslp import protocol


class TestReceiveMessage:
    def test_receive_message(self, socket_pair):

        s1, s2 = socket_pair
        message_to_receive = b"HELLOBACK\n"

        _ = s1.sendall(message_to_receive)
        received_message = protocol.receive_message(s2)

        assert received_message == "HELLOBACK"

    def test_receive_message_non_utf(self, socket_pair, readout):
        s1, s2 = socket_pair
        message_to_receive = "æ\n".encode("cp1252")

        _ = s1.sendall(message_to_receive)
        with pytest.raises(protocol.ProtocolError) as e:
            protocol.receive_message(s2)

        assert "Receive failed: invalid UTF-8" in str(e.value)

    def test_receive_message_no_newline(self, socket_pair, readout):
        s1, s2 = socket_pair
        message_to_receive = b"HELLOBACK"

        _ = s1.sendall(message_to_receive)
        with pytest.raises(protocol.TransportError) as e:
            protocol.receive_message(s2)

        assert "Receive timeout:" in str(e.value)

    def test_receive_empty_message(self, socket_pair, readout):
        s1, s2 = socket_pair
        s1.close()

        with pytest.raises(protocol.TransportError) as e:
            protocol.receive_message(s2)

        assert "Receive failed: peer closed connection" in str(e.value)

    def test_receive_non_bytes(self, socket_pair, readout):
        sock = FakeSocket()
        with pytest.raises(protocol.ProtocolError) as e:
            protocol.receive_message(sock)
        assert "Receive failed: expected bytes, got" in str(e.value)

    def test_receive_long_line(self, socket_pair, readout):
        s1, s2 = socket_pair
        message_to_receive = bytes([3]) * 1001 + b"\n"

        _ = s1.sendall(message_to_receive)
        with pytest.raises(protocol.ProtocolError) as e:
            protocol.receive_message(s2)
        assert "Receive failed: line too long" in str(e.value)


class TestSendMessage:
    @pytest.mark.parametrize(
        "payload, expected_bytes",
        [
            ("HELLO\n", b"HELLO\n"),
            ("HELLO", b"HELLO\n"),  # newline should be added
        ],
    )
    def test_send_message(self, socket_pair, payload, expected_bytes):

        s1, s2 = socket_pair

        protocol.send_message(payload, s1)
        received = s2.recv(1024)

        assert received == expected_bytes

    def test_send_message_non_str_raises_protocol_error(self, socket_pair):
        s1, _ = socket_pair

        with pytest.raises(protocol.ProtocolError, match=r"expected str"):
            protocol.send_message(b"HELLO\n", s1)

    def test_send_message_bad_utf8_raises_protocol_error(self, socket_pair):
        s1, _ = socket_pair

        # A lone surrogate can't be encoded to UTF-8
        bad = "\ud800"

        with pytest.raises(protocol.ProtocolError, match=r"could not encode UTF-8"):
            protocol.send_message(bad, s1)

    def test_send_message_transport_error_is_wrapped(self):

        class FakeSendSock:
            def sendall(self, _data):
                raise TimeoutError("boom")

        with pytest.raises(protocol.TransportError, match=r"Send failed while sending"):
            protocol.send_message("HELLO", FakeSendSock())


class TestParsePositiveInt:

    def test_parse_positive_int_accepts_positive_int(self):
        """Valid positive integers should parse and return an int."""
        assert protocol._parse_positive_int("42") == 42

    def test_parse_positive_int_rejects_non_integer(self):
        """Non-integer strings should raise ArgumentTypeError and log an exception."""
        with pytest.raises(argparse.ArgumentTypeError, match=r"must be an integer"):
            protocol._parse_positive_int("abc")

    def test_parse_positive_int_rejects_zero_or_negative(self):
        """Zero/negative integers should raise ArgumentTypeError and log an exception."""
        with pytest.raises(argparse.ArgumentTypeError, match=r"must be > 0"):
            protocol._parse_positive_int("0")
