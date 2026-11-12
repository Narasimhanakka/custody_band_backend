import sys
import unittest
from pathlib import Path
from unittest.mock import patch

BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from app.receiver import packet_parser, tcp_server


class FakeTCPConnection:
    def __init__(self, chunks):
        self.chunks = list(chunks)
        self.sent = []
        self.closed = False

    def settimeout(self, timeout):
        self.timeout = timeout

    def recv(self, size):
        if size <= 0:
            raise ValueError("recv size must be positive")
        return self.chunks.pop(0) if self.chunks else b""

    def sendall(self, data):
        self.sent.append(data)

    def close(self):
        self.closed = True


class FakeUDPSocket:
    def __init__(self, datagram):
        self.datagram = datagram
        self.sent = []

    def setsockopt(self, level, option, value):
        self.socket_options = (level, option, value)

    def bind(self, address):
        self.bound_address = address

    def recvfrom(self, size):
        if size <= 0:
            raise ValueError("recvfrom size must be positive")
        if self.datagram is None:
            raise OSError("test receiver stop")
        data = self.datagram
        self.datagram = None
        return data, ("127.0.0.1", 9002)

    def sendto(self, data, address):
        self.sent.append((data, address))


class ReceiverDiagnosticsTests(unittest.TestCase):
    def test_tcp_frame_diagnostics_and_protocol_reply(self):
        frame = packet_parser.build_frame("MNYD", "TEST_DEVICE_1", "PING")
        connection = FakeTCPConnection([frame])

        with patch.object(tcp_server, "_DIAGNOSTICS_ENABLED", True):
            with self.assertLogs("custody_tcp", level="INFO") as captured:
                tcp_server.handle_tcp_client(connection, ("127.0.0.1", 12345))

        logs = "\n".join(captured.output)
        self.assertIn("received", logs)
        self.assertIn("extracted 1 complete frame", logs)
        self.assertIn("device=TEST_DEVICE_1 command=PING", logs)
        self.assertIn("client disconnected", logs)
        self.assertTrue(connection.closed)
        self.assertEqual(
            connection.sent,
            [packet_parser.build_frame("MNYD", "TEST_DEVICE_1", "PING,1")]
        )

    def test_udp_frame_diagnostics_and_protocol_reply(self):
        frame = packet_parser.build_frame("MNYD", "TEST_DEVICE_2", "PING")
        udp_socket = FakeUDPSocket(frame)

        with (
            patch.object(tcp_server, "_DIAGNOSTICS_ENABLED", True),
            patch.object(tcp_server.socket, "socket", return_value=udp_socket),
            self.assertLogs("custody_tcp", level="INFO") as captured
        ):
            tcp_server.run_udp_server()

        logs = "\n".join(captured.output)
        self.assertIn("UDP received", logs)
        self.assertIn("UDP extracted 1 complete frame", logs)
        self.assertIn("device=TEST_DEVICE_2 command=PING", logs)
        self.assertEqual(
            udp_socket.sent,
            [(
                packet_parser.build_frame("MNYD", "TEST_DEVICE_2", "PING,1"),
                ("127.0.0.1", 9002)
            )]
        )

    def test_packet_command_log_does_not_include_payload(self):
        with self.assertLogs("custody_tcp", level="INFO") as captured:
            command, reply = packet_parser.parse_packet(
                "MNYD", "TEST_DEVICE_3", b"PING,SENSITIVE_PAYLOAD"
            )

        self.assertEqual(command, "PING")
        self.assertEqual(
            reply,
            packet_parser.build_frame("MNYD", "TEST_DEVICE_3", "PING,1")
        )
        self.assertIn("command=PING", "\n".join(captured.output))
        self.assertNotIn("SENSITIVE_PAYLOAD", "\n".join(captured.output))

    def test_gps_parse_error_logs_exception_context_without_exception_message(self):
        packet = (
            b"UD,261106,110000,A,17.445000,N,78.370000,E,"
            b"16.5,142.0,510.0,8,95,73,1250,00000000,0,0,0,0,0"
        )
        with (
            patch.object(
                packet_parser.gps_service,
                "process_location_record",
                side_effect=RuntimeError("SENSITIVE_PAYLOAD")
            ),
            self.assertLogs("custody_tcp", level="ERROR") as captured
        ):
            result = packet_parser.parse_ud(packet, "TEST_DEVICE_ERROR", "MNYD")

        self.assertIsNone(result)
        logs = "\n".join(captured.output)
        self.assertIn("exception_type=RuntimeError", logs)
        self.assertNotIn("SENSITIVE_PAYLOAD", logs)

    def test_gps_diagnostic_reports_validation_and_completed_stages(self):
        packet = (
            b"UD,261106,110000,A,17.445000,N,78.370000,E,"
            b"16.5,142.0,510.0,8,95,73,1250,00000000,0,0,0,0,0"
        )
        with (
            patch.object(packet_parser, "_DIAGNOSTICS_ENABLED", True),
            patch.object(
                packet_parser.gps_service,
                "process_location_record",
                side_effect=lambda record: record
            ),
            patch.object(packet_parser.device_service, "update_position"),
            patch.object(packet_parser.alert_service, "check_battery_alert"),
            self.assertLogs("custody_gps", level="INFO") as captured
        ):
            record = packet_parser.parse_ud(packet, "TEST_DEVICE_4", "MNYD")

        self.assertTrue(record["gps_valid"])
        self.assertIn("status=A coordinates_valid=True", "\n".join(captured.output))
        self.assertIn(
            "gps_processing_succeeded=True device_position_update_succeeded=True",
            "\n".join(captured.output)
        )

    def test_invalid_gps_passes_no_coordinates_and_completes_device_update(self):
        packet = (
            b"UD,261106,110100,V,0.000000,N,0.000000,E,"
            b"0.0,0.0,0.0,0,40,65,1260,00000000,0,0,0,0,0"
        )
        with (
            patch.object(packet_parser, "_DIAGNOSTICS_ENABLED", True),
            patch.object(
                packet_parser.gps_service,
                "process_location_record",
                side_effect=lambda record: record
            ),
            patch.object(packet_parser.device_service, "update_position") as update,
            patch.object(packet_parser.alert_service, "check_battery_alert"),
            self.assertLogs("custody_gps", level="INFO") as captured
        ):
            record = packet_parser.parse_ud(packet, "TEST_DEVICE_5", "MNYD")

        self.assertFalse(record["gps_valid"])
        self.assertIsNone(record["latitude"])
        update.assert_called_once()
        self.assertIsNone(update.call_args.kwargs["lat"])
        self.assertIsNone(update.call_args.kwargs["lon"])
        logs = "\n".join(captured.output)
        self.assertIn("status=V coordinates_valid=False", logs)
        self.assertIn("device_position_update_succeeded=True", logs)


if __name__ == "__main__":
    unittest.main()
