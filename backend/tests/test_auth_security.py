import unittest
import hashlib

#from backend.app.core.security import hash_password, verify_password
from app.core.security import hash_password, verify_password

class PasswordVerificationTests(unittest.TestCase):
    def test_verifies_legacy_sha256_password_hash(self):
        stored_hash = hashlib.sha256(
            ("custody_salt_2026" + "Admin@123").encode("utf-8")
        ).hexdigest()

        self.assertTrue(verify_password("Admin@123", stored_hash))

    def test_rejects_wrong_password_for_legacy_hash(self):
        stored_hash = hashlib.sha256(
            ("custody_salt_2026" + "Admin@123").encode("utf-8")
        ).hexdigest()

        self.assertFalse(verify_password("admin", stored_hash))

    def test_verifies_newly_generated_password_hash(self):
        stored_hash = hash_password("Officer@123")

        self.assertTrue(verify_password("Officer@123", stored_hash))
        self.assertFalse(verify_password("wrong-password", stored_hash))

    def test_rejects_unrecognized_hash(self):
        self.assertFalse(verify_password("Admin@123", "not-a-supported-hash"))


if __name__ == "__main__":
    unittest.main()
