"""ReconPilot - Global Exclusions Tests.

Tests that global TLD exclusions (.gov, .mil, .edu) are always blocked.
"""


def test_protected_tld_blocked(client):
    """Test that protected TLDs (.gov, .mil, .edu) are always blocked."""
    pass


def test_normal_tld_allowed(client):
    """Test that normal TLDs are allowed."""
    pass
