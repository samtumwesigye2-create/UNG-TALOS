"""
UNG-TALOS — attribute-based access control (ABAC), scoped honestly.

Real ABAC checks a user's attributes against a resource's attributes.
This project has exactly one attribute on each side worth checking:
role-derived clearance vs. an incident's classification. It does NOT
implement nationality or geofence checks — those would need an identity
provider and a location signal this system has neither of, and faking
them with a hardcoded "always passes" rule would be theater, not
security. Add real attributes here if/when the data to back them exists.
"""

CLEARANCE_LEVEL = {"analyst": 1, "security_admin": 2}
CLASSIFICATION_LEVEL = {"internal": 1, "restricted": 2}


def can_view(user_role: str, classification: str) -> bool:
    return CLEARANCE_LEVEL.get(user_role, 0) >= CLASSIFICATION_LEVEL.get(classification, 99)