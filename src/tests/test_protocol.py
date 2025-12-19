import logging

import pytest

from tlslp import protocol

from .helpers import FakeSocket


class TestReceiveMessage:
    def test_receive_message(self, socket_pair, caplog):
        logger = logging.getLogger("tlslp")

        s1, s2 = socket_pair
        message_to_receive = b"HELLOBACK\n"

        _ = s1.sendall(message_to_receive)
        received_message = protocol.receive_message(s2, logger)

        assert received_message == "HELLOBACK"

        with caplog.at_level(logging.DEBUG):
            logger.debug("Received HELLO")

        # Verify the message exists in the logs
        assert "Received HELLO" in caplog.text
        # Verify the log level
        assert caplog.records[0].levelname == "DEBUG"

    def test_receive_message_non_utf(self, socket_pair, readout, caplog):
        logger = logging.getLogger("tlslp")
        s1, s2 = socket_pair
        message_to_receive = "æ".encode("cp1252")

        _ = s1.sendall(message_to_receive)
        with pytest.raises(ValueError, match=r"Receive failed.  Invalid UTF-8:"):
            protocol.receive_message(s2, logger)

    def test_receive_message_no_newline(self, socket_pair, readout):
        logger = logging.getLogger("tlslp")
        s1, s2 = socket_pair
        s1.settimeout(1)
        message_to_receive = b"HELLOBACK"

        _ = s1.sendall(message_to_receive)
        with pytest.raises(TimeoutError, match=r"Receive timeout"):
            protocol.receive_message(s2, logger)

    def test_receive_empty_message(self, socket_pair, readout):
        logger = logging.getLogger("tlslp")
        s1, s2 = socket_pair
        s1.close()

        with pytest.raises(
            protocol.TransportError, match=r"Receive failed.  Received empty string."
        ):
            protocol.receive_message(s2, logger)

    def test_receive_non_bytes(self, socket_pair, readout):
        logger = logging.getLogger("tlslp")
        sock = FakeSocket()
        with pytest.raises(TypeError, match=r"Receive failed.  Unexpected type:"):
            protocol.receive_message(sock, logger)

    def test_receive_long_line(self, socket_pair, readout):
        logger = logging.getLogger("tlslp")
        s1, s2 = socket_pair
        message_to_receive = bytes([3]) * 1001 + b"\n"

        _ = s1.sendall(message_to_receive)
        with pytest.raises(ValueError, match=r"Line too long"):
            protocol.receive_message(s2, logger)
