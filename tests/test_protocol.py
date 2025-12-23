import argparse
import logging

import pytest
from helpers import FakeSocket

from tlslp import protocol


class TestReceiveMessage:
    def test_receive_message(self, socket_pair, caplog):
        logger = logging.getLogger("test_protocol")

        s1, s2 = socket_pair
        message_to_receive = b"HELLOBACK\n"

        _ = s1.sendall(message_to_receive)
        received_message = protocol.receive_message(s2, logger)

        assert received_message == "HELLOBACK"

        with caplog.at_level(logging.DEBUG):
            logger.debug("Received HELLO")

        # Verify the message exists in the logs
        assert "Received HELLO" in caplog.text

    def test_receive_message_non_utf(self, socket_pair, readout, caplog):
        logger = logging.getLogger("test_protocol")
        s1, s2 = socket_pair
        message_to_receive = "æ\n".encode("cp1252")

        _ = s1.sendall(message_to_receive)
        with pytest.raises(protocol.ProtocolError) as e:
            protocol.receive_message(s2, logger)

        assert "Receive failed.  Invalid UTF-8" in str(e)

    def test_receive_message_no_newline(self, socket_pair, readout, caplog):
        logger = logging.getLogger("test_protocol")
        s1, s2 = socket_pair
        message_to_receive = b"HELLOBACK"

        _ = s1.sendall(message_to_receive)
        with pytest.raises(protocol.TransportError) as e:
            protocol.receive_message(s2, logger)

        assert "Receive timeout" in str(e)

    def test_receive_empty_message(self, socket_pair, readout):
        logger = logging.getLogger("test_protocol")
        s1, s2 = socket_pair
        s1.close()

        with pytest.raises(protocol.ProtocolError) as e:
            protocol.receive_message(s2, logger)

        assert "Receive failed.  Received empty string" in str(e)

    def test_receive_non_bytes(self, socket_pair, readout):
        logger = logging.getLogger("test_protocol")
        sock = FakeSocket()
        with pytest.raises(protocol.ProtocolError) as e:
            protocol.receive_message(sock, logger)
        assert "Receive failed.  Unexpected type" in str(e)

    def test_receive_long_line(self, socket_pair, readout):
        logger = logging.getLogger("test_protocol")
        s1, s2 = socket_pair
        message_to_receive = bytes([3]) * 1001 + b"\n"

        _ = s1.sendall(message_to_receive)
        with pytest.raises(ValueError) as e:
            protocol.receive_message(s2, logger)
        assert "Line too long" in str(e)


class TestParsePositiveInt:

    def test_parse_positive_int_accepts_positive_int(self, caplog):
        """Valid positive integers should parse and return an int."""
        assert protocol._parse_positive_int("42") == 42

        assert caplog.records == []

    def test_parse_positive_int_rejects_non_integer(self, caplog):
        """Non-integer strings should raise ArgumentTypeError and log an exception."""
        with (
            caplog.at_level(logging.ERROR, logger=protocol.logger.name),
            pytest.raises(argparse.ArgumentTypeError, match=r"must be an integer"),
        ):
            protocol._parse_positive_int("abc")

        assert "must be an integer" in caplog.text

    def test_parse_positive_int_rejects_zero_or_negative(self, caplog):
        """Zero/negative integers should raise ArgumentTypeError and log an exception."""
        with (
            caplog.at_level(logging.ERROR, logger=protocol.logger.name),
            pytest.raises(argparse.ArgumentTypeError, match=r"must be > 0"),
        ):
            protocol._parse_positive_int("0")

        assert "must be > 0" in caplog.text
