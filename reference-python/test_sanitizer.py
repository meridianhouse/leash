# These are synthetic test fixtures, not real credentials
from nova_edr.sanitizer import Sanitizer, ScanMode

def test_sanitizer():
    sanitizer = Sanitizer(mode=ScanMode.REDACT)
    
    cases = [
        (
            "Here is my api key: sk-proj-12345678901234567890",
            "Here is my api key: [REDACTED_OPENAI_KEY]"
        ),
        (
            "My secret is password = 'supersecret123'",
            "My secret is password = '[REDACTED_GENERIC_SECRET]'"
        ),
        (
            "Contact me at user@example.com or 555-123-4567",
            "Contact me at [REDACTED_EMAIL] or [REDACTED_PHONE_US]"
        ),
        (
            "Use Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
            "Use Bearer [REDACTED_BEARER_TOKEN]"
        ),
        (
            "My AWS key is AKIA1234567890123456",
            "My AWS key is [REDACTED_AWS_ACCESS_KEY]"
        ),
        (
            "password: supersecret (no quotes)",
            "password: [REDACTED_GENERIC_SECRET_UNQUOTED] (no quotes)"
        ),
        (
            "Unrelated text should be untouched.",
            "Unrelated text should be untouched."
        )
    ]
    
    for original, expected in cases:
        redacted, findings = sanitizer.sanitize_text(original)
        if redacted != expected:
            print(f"FAIL: '{original}' -> '{redacted}' (expected '{expected}')")
            for f in findings:
                print(f"  Finding: {f.rule_name} at {f.start}-{f.end}")
        else:
            print(f"PASS: '{original}'")

if __name__ == "__main__":
    test_sanitizer()
