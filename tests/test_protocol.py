import argparse
import logging

import pytest
from helpers import FakeSocket

from tlscc import protocol


class TestReceiveMessage:
    def test_receive_message(self, socket_pair, caplog):
        logger = logging.getLogger("tlscc")

        s1, s2 = socket_pair
        message_to_receive = b"EHLO\n"

        _ = s1.sendall(message_to_receive)
        received_message = protocol.receive_message(s2, logger)

        assert received_message == "EHLO"

        with caplog.at_level(logging.DEBUG):
            logger.debug("Received HELO")

        # Verify the message exists in the logs
        assert "Received HELO" in caplog.text
        # Verify the log level
        assert caplog.records[0].levelname == "DEBUG"

    def test_receive_message_non_utf(self, socket_pair, readout, caplog):
        logger = logging.getLogger("tlscc")
        s1, s2 = socket_pair
        message_to_receive = "æ".encode("cp1252")

        _ = s1.sendall(message_to_receive)
        with pytest.raises(ValueError, match=r"Receive failed.  Invalid UTF-8:"):
            protocol.receive_message(s2, logger)

    def test_receive_message_no_newline(self, socket_pair, readout):
        logger = logging.getLogger("tlscc")
        s1, s2 = socket_pair
        s1.settimeout(1)
        message_to_receive = b"EHLO"

        _ = s1.sendall(message_to_receive)
        with pytest.raises(TimeoutError, match=r"Receive timeout"):
            protocol.receive_message(s2, logger)

    def test_receive_empty_message(self, socket_pair, readout):
        logger = logging.getLogger("tlscc")
        s1, s2 = socket_pair
        s1.close()

        with pytest.raises(
            protocol.TransportError, match=r"Receive failed.  Received empty string."
        ):
            protocol.receive_message(s2, logger)

    def test_receive_non_bytes(self, socket_pair, readout):
        logger = logging.getLogger("tlscc")
        sock = FakeSocket()
        with pytest.raises(TypeError, match=r"Receive failed.  Unexpected type:"):
            protocol.receive_message(sock, logger)

    def test_receive_long_line(self, socket_pair, readout):
        logger = logging.getLogger("tlscc")
        s1, s2 = socket_pair
        message_to_receive = bytes([3]) * 1001 + b"\n"

        _ = s1.sendall(message_to_receive)
        with pytest.raises(ValueError, match=r"Line too long"):
            protocol.receive_message(s2, logger)


class TestParsePositiveInt:

    def test_parse_positive_int_accepts_positive_int(self, caplog):
        """Valid positive integers should parse and return an int."""
        assert protocol._parse_positive_int("42") == 42

        print(f"\ncaplog: {caplog}")
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
