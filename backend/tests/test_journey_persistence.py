import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from app.services.firestore_service import FirestoreService
from app.services.journey_service import JourneyService


class JourneyRegressionTests(unittest.TestCase):
    def test_explicit_journey_id_ends_only_that_journey(self):
        service = JourneyService()
        active_journey = {
            "journey_id": "journey-active",
            "device_id": "device-1",
            "status": "ACTIVE",
            "start_time": "2026-11-10T10:00:00+00:00",
            "route_coordinates": [],
            "total_distance_km": 0.0,
        }
        requested_journey = {
            "journey_id": "journey-requested",
            "device_id": "device-1",
            "status": "ACTIVE",
            "start_time": "2026-11-10T10:00:00+00:00",
            "route_coordinates": [],
            "total_distance_km": 0.0,
        }
        service._active_journeys["device-1"] = active_journey

        with (
            patch(
                "app.services.journey_service.firestore_service.get_journey",
                return_value=requested_journey,
            ) as get_journey,
            patch("app.services.journey_service.firestore_service.save_journey"),
        ):
            ended = service.end_journey("device-1", journey_id="journey-requested")

        get_journey.assert_called_once_with("journey-requested")
        self.assertEqual(ended["journey_id"], "journey-requested")
        self.assertEqual(ended["status"], "COMPLETED")
        self.assertEqual(service._active_journeys["device-1"]["journey_id"], "journey-active")
        self.assertEqual(active_journey["status"], "ACTIVE")

    def test_explicit_journey_id_cannot_end_another_devices_journey(self):
        service = JourneyService()
        requested_journey = {
            "journey_id": "journey-other-device",
            "device_id": "device-2",
            "status": "ACTIVE",
        }

        with patch(
            "app.services.journey_service.firestore_service.get_journey",
            return_value=requested_journey,
        ), patch("app.services.journey_service.firestore_service.save_journey") as save_journey:
            ended = service.end_journey("device-1", journey_id="journey-other-device")

        self.assertIsNone(ended)
        save_journey.assert_not_called()

    def test_sqlite_reconstructs_journey_locations_with_zero_coordinates(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            database_path = Path(temp_dir) / "journeys.db"
            with (
                patch("app.services.firestore_service.LOCAL_DB", database_path),
                patch("app.services.firestore_service.is_firebase_active", return_value=False),
            ):
                service = FirestoreService()
                active_journey = {
                    "journey_id": "journey-active-zero",
                    "device_id": "device-zero",
                    "status": "ACTIVE",
                    "start_time": "2026-11-10T10:00:00+00:00",
                    "end_time": None,
                    "start_location": {
                        "latitude": 0.0,
                        "longitude": 12.5,
                        "timestamp": "2026-11-10T10:00:00+00:00",
                    },
                    "end_location": None,
                    "route_coordinates": [],
                    "total_distance_km": 0.0,
                    "duration_seconds": 0,
                    "duration_formatted": "00:00:00",
                    "points_count": 0,
                }
                service.save_journey(active_journey)

                active = service.get_active_journey("device-zero")
                self.assertEqual(
                    active["start_location"]["latitude"], 0.0
                )
                self.assertEqual(
                    active["start_location"]["longitude"], 12.5
                )

                completed_journey = {
                    **active_journey,
                    "journey_id": "journey-completed-zero",
                    "status": "COMPLETED",
                    "end_time": "2026-11-10T11:00:00+00:00",
                    "end_location": {
                        "latitude": -12.5,
                        "longitude": 0.0,
                        "timestamp": "2026-11-10T11:00:00+00:00",
                    },
                }
                service.save_journey(completed_journey)

                by_id = service.get_journey("journey-completed-zero")
                self.assertEqual(by_id["start_location"]["latitude"], 0.0)
                self.assertEqual(by_id["end_location"]["longitude"], 0.0)

                by_device = service.get_device_journeys("device-zero")
                completed = next(
                    journey
                    for journey in by_device
                    if journey["journey_id"] == "journey-completed-zero"
                )
                self.assertEqual(completed["start_location"]["latitude"], 0.0)
                self.assertEqual(completed["end_location"]["longitude"], 0.0)


if __name__ == "__main__":
    unittest.main()
