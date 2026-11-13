import sys
import threading
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from app.receiver import packet_parser, packet_validator, tcp_server


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

    def settimeout(self, timeout):
        self.timeout = timeout

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

    def close(self):
        self.closed = True


class ReceiverDiagnosticsTests(unittest.TestCase):
    def test_fragmented_and_coalesced_frames_are_extracted_exactly(self):
        first = packet_parser.build_frame("MNYD", "TEST_DEVICE_1", "PING")
        second = packet_parser.build_frame("MNYD", "TEST_DEVICE_2", "KA,1,0,50")

        frames, remainder, rejected = packet_validator.extract_frames_with_errors(first[:11])
        self.assertEqual(frames, [])
        self.assertEqual(remainder, first[:11])
        self.assertEqual(rejected, 0)

        frames, remainder, rejected = packet_validator.extract_frames_with_errors(
            remainder + first[11:] + second
        )
        self.assertEqual(
            frames,
            [
                ("MNYD", "TEST_DEVICE_1", b"PING"),
                ("MNYD", "TEST_DEVICE_2", b"KA,1,0,50"),
            ]
        )
        self.assertEqual(remainder, b"")
        self.assertEqual(rejected, 0)

    def test_declared_length_mismatch_is_rejected_without_losing_next_frame(self):
        malformed = b"[MNYD*TEST_DEVICE_BAD*0001*PING]"
        valid = packet_parser.build_frame("MNYD", "TEST_DEVICE_OK", "PING")

        frames, remainder, rejected = packet_validator.extract_frames_with_errors(
            malformed + valid
        )

        self.assertEqual(frames, [("MNYD", "TEST_DEVICE_OK", b"PING")])
        self.assertEqual(remainder, b"")
        self.assertGreaterEqual(rejected, 1)

    def test_tcp_connection_keeps_processing_after_malformed_frame(self):
        malformed = b"[MNYD*TEST_DEVICE_BAD*0001*PING]"
        valid = packet_parser.build_frame("MNYD", "TEST_DEVICE_OK", "PING")
        connection = FakeTCPConnection([malformed + valid])

        with (
            patch.object(packet_parser.device_service, "update_heartbeat"),
            self.assertLogs("custody_tcp", level="WARNING")
        ):
            tcp_server.handle_tcp_client(connection, ("127.0.0.1", 12340))

        self.assertEqual(
            connection.sent,
            [packet_parser.build_frame("MNYD", "TEST_DEVICE_OK", "PING,1")]
        )
        self.assertFalse(tcp_server.active_connections)

    def test_fragmented_and_multiple_tcp_packets_are_all_dispatched(self):
        first = packet_parser.build_frame("MNYD", "TEST_DEVICE_MULTI", "PING")
        second = packet_parser.build_frame("MNYD", "TEST_DEVICE_MULTI", "PING")
        connection = FakeTCPConnection([first[:13], first[13:] + second])

        with patch.object(packet_parser.device_service, "update_heartbeat"):
            tcp_server.handle_tcp_client(connection, ("127.0.0.1", 12341))

        self.assertEqual(
            connection.sent,
            [
                packet_parser.build_frame("MNYD", "TEST_DEVICE_MULTI", "PING,1"),
                packet_parser.build_frame("MNYD", "TEST_DEVICE_MULTI", "PING,1"),
            ]
        )

    def test_cr_command_delivery_uses_registered_device_connection(self):
        connection = FakeTCPConnection([])
        tcp_server.register_client("TEST_DEVICE_COMMAND", connection)
        try:
            self.assertTrue(
                tcp_server.send_command_to_device("TEST_DEVICE_COMMAND", "CR")
            )
            self.assertEqual(
                connection.sent,
                [packet_parser.build_frame("MNYD", "TEST_DEVICE_COMMAND", "CR")]
            )
        finally:
            tcp_server.unregister_client("TEST_DEVICE_COMMAND", connection)

    def test_reconnection_cannot_be_unregistered_by_old_connection(self):
        old_connection = FakeTCPConnection([])
        new_connection = FakeTCPConnection([])
        tcp_server.register_client("TEST_DEVICE_RECONNECT", old_connection)
        tcp_server.register_client("TEST_DEVICE_RECONNECT", new_connection)
        try:
            tcp_server.unregister_client("TEST_DEVICE_RECONNECT", old_connection)
            self.assertIs(
                tcp_server.active_connections["TEST_DEVICE_RECONNECT"],
                new_connection
            )
            self.assertTrue(old_connection.closed)
        finally:
            tcp_server.unregister_client("TEST_DEVICE_RECONNECT", new_connection)

    def test_simultaneous_devices_have_independent_connections(self):
        first = FakeTCPConnection([])
        second = FakeTCPConnection([])
        tcp_server.register_client("TEST_DEVICE_A", first)
        tcp_server.register_client("TEST_DEVICE_B", second)
        try:
            self.assertEqual(tcp_server.get_active_clients_count(), 2)
            self.assertTrue(tcp_server.is_device_connected("TEST_DEVICE_A"))
            self.assertTrue(tcp_server.is_device_connected("TEST_DEVICE_B"))
        finally:
            tcp_server.unregister_client("TEST_DEVICE_A", first)
            tcp_server.unregister_client("TEST_DEVICE_B", second)

    def test_receiver_startup_is_idempotent_and_shutdown_signals_listeners(self):
        started = []

        def fake_listener(ready_event, stop_event, _startup_errors):
            started.append(threading.current_thread().name)
            ready_event.set()
            stop_event.wait(1)

        with (
            patch.object(tcp_server, "run_tcp_server", side_effect=fake_listener),
            patch.object(tcp_server, "run_udp_server", side_effect=fake_listener)
        ):
            tcp_server.start_receiver_background()
            tcp_server.start_receiver_background()
            self.assertEqual(len(started), 2)
            tcp_server.stop_receiver()

        self.assertFalse(tcp_server._receiver_started)
        self.assertFalse(tcp_server._listener_threads)

    def test_tcp_bind_failure_is_reported_to_startup(self):
        class FailingListener:
            def setsockopt(self, *_args):
                pass

            def bind(self, _address):
                raise OSError("address in use")

            def close(self):
                pass

        ready = threading.Event()
        errors = {}
        with (
            patch.object(tcp_server.socket, "socket", return_value=FailingListener()),
            self.assertLogs("custody_tcp", level="CRITICAL")
        ):
            tcp_server.run_tcp_server(ready, threading.Event(), errors)

        self.assertTrue(ready.is_set())
        self.assertIn("tcp", errors)

    def test_tcp_frame_diagnostics_and_protocol_reply(self):
        frame = packet_parser.build_frame("MNYD", "TEST_DEVICE_1", "PING")
        connection = FakeTCPConnection([frame])

        with patch.object(tcp_server, "_DIAGNOSTICS_ENABLED", True):
            with (
                patch.object(packet_parser.device_service, "update_heartbeat"),
                self.assertLogs("custody_tcp", level="INFO") as captured
            ):
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

    def test_tcp_gps_packet_is_dispatched_with_trusted_source_and_watch_time(self):
        packet_time = datetime.now(timezone.utc)
        received_epoch = packet_time.timestamp() + 1
        expected_received_at = datetime.fromtimestamp(
            received_epoch,
            timezone.utc
        ).isoformat()
        payload = (
            f"UD,{packet_time:%y%m%d},{packet_time:%H%M%S},A,"
            "17.445000,N,78.370000,E,0.0,90.0,0.0,0,0,,,00000000"
        )
        frame = packet_parser.build_frame("MNYD", "TEST_DEVICE_GPS", payload)
        connection = FakeTCPConnection([frame])

        with (
            patch.object(
                packet_parser.gps_service,
                "process_location_record",
                side_effect=lambda record: record
            ) as process_record,
            patch.object(packet_parser.device_service, "update_position") as update_position,
            patch.object(tcp_server.time, "time", return_value=received_epoch)
        ):
            tcp_server.handle_tcp_client(connection, ("127.0.0.1", 12346))

        record = process_record.call_args.args[0]
        self.assertTrue(record["gps_valid"])
        self.assertEqual(record["gps_source"], "watch_tcp")
        self.assertEqual(
            record["timestamp"],
            packet_time.replace(microsecond=0).isoformat()
        )
        self.assertEqual(record["received_at"], expected_received_at)
        self.assertEqual(update_position.call_args.kwargs["gps_source"], "watch_tcp")
        self.assertEqual(
            update_position.call_args.kwargs["received_at"],
            expected_received_at
        )

    def test_ping_receives_manufacturer_ack_and_records_server_receipt_time(self):
        received_epoch = datetime.now(timezone.utc).timestamp()
        expected_received_at = datetime.fromtimestamp(
            received_epoch,
            timezone.utc
        ).isoformat()
        with (
            patch.object(packet_parser.device_service, "update_heartbeat") as heartbeat,
            self.assertLogs("custody_tcp", level="INFO")
        ):
            command, reply = packet_parser.parse_packet(
                "MNYD",
                "TEST_DEVICE_PING",
                b"PING",
                received_at=received_epoch
            )

        self.assertEqual(command, "PING")
        self.assertEqual(
            reply,
            packet_parser.build_frame("MNYD", "TEST_DEVICE_PING", "PING,1")
        )
        heartbeat.assert_called_once_with(
            "TEST_DEVICE_PING",
            None,
            None,
            received_at=expected_received_at
        )

    def test_udp_frame_diagnostics_and_protocol_reply(self):
        frame = packet_parser.build_frame("MNYD", "TEST_DEVICE_2", "PING")
        udp_socket = FakeUDPSocket(frame)

        with (
            patch.object(tcp_server, "_DIAGNOSTICS_ENABLED", True),
            patch.object(tcp_server.socket, "socket", return_value=udp_socket),
            patch.object(packet_parser.device_service, "update_heartbeat"),
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
        with (
            patch.object(packet_parser.device_service, "update_heartbeat"),
            self.assertLogs("custody_tcp", level="INFO") as captured
        ):
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
            result = packet_parser.parse_ud(
                packet, "TEST_DEVICE_ERROR", "MNYD", gps_source="watch_tcp"
            )

        self.assertIsNone(result)
        logs = "\n".join(captured.output)
        self.assertIn("exception_type=RuntimeError", logs)
        self.assertNotIn("SENSITIVE_PAYLOAD", logs)

    def test_gps_diagnostic_reports_validation_and_completed_stages(self):
        packet_time = datetime.now(timezone.utc)
        packet = (
            f"UD,{packet_time:%y%m%d},{packet_time:%H%M%S},A,"
            "17.445000,N,78.370000,E,16.5,142.0,510.0,8,95,73,1250,"
            "00000000,0,0,0,0,0"
        ).encode("latin-1")
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
            record = packet_parser.parse_ud(
                packet, "TEST_DEVICE_4", "MNYD", gps_source="watch_tcp"
            )

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
            record = packet_parser.parse_ud(
                packet, "TEST_DEVICE_5", "MNYD", gps_source="watch_tcp"
            )

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
