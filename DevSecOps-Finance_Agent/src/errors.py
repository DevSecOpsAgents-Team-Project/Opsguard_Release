"""Finance Agent error types and response formatters."""


class ContractViolation(Exception):
    """Raised when assumption contract validation fails."""

    def __init__(self, errors):
        """
        Args:
            errors: List of dicts with keys: field, code, message, allowed
        """
        self.errors = errors
        super().__init__(str(errors))


def contract_error_response(e, incident_id):
    """Build fixed-format error response for contract violation.

    Args:
        e: ContractViolation instance (with .errors)
        incident_id: incident_id string from request

    Returns:
        dict with keys: error.type, error.incident_id, error.items
    """
    return {
        "error": {
            "type": "ASSUMPTION_CONTRACT_VIOLATION",
            "incident_id": incident_id,
            "items": [
                {
                    "field": item.get("field", ""),
                    "code": item.get("code", ""),
                    "message": item.get("message", ""),
                    "allowed": item.get("allowed", []),
                }
                for item in e.errors
            ],
        }
    }
