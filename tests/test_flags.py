"""SoftWebauthnDevice tests for AuthenticatorDataFlags"""

import pytest
from soft_webauthn import AuthenticatorDataFlags, SoftWebauthnDevice


def test_valid_enum():
    """Tests flags with only enums"""

    assert SoftWebauthnDevice.convert_flags([
        AuthenticatorDataFlags.USER_PRESENT,
        AuthenticatorDataFlags.USER_VERIFIED
    ]) == (0b00000101).to_bytes(1, "little")


def test_valid_int():
    """Tests flags with only ints"""

    assert SoftWebauthnDevice.convert_flags([
        (1 << 0),
        (1 << 2)
    ]) == (0b00000101).to_bytes(1, "little")


def test_valid_mixed():
    """Tests flags with both enums and ints"""

    assert SoftWebauthnDevice.convert_flags([
        AuthenticatorDataFlags.USER_PRESENT,
        (1 << 2)
    ]) == (0b00000101).to_bytes(1, "little")


def test_invalid_instance():
    """Tests if an error is raised if a flag is not the correct type"""

    with pytest.raises(ValueError):
        SoftWebauthnDevice.convert_flags([
            "something",
            AuthenticatorDataFlags.USER_PRESENT
        ])


def test_out_of_range():
    """Tests if an error is raised if a flag is out of range"""

    with pytest.raises(ValueError):
        SoftWebauthnDevice.convert_flags([
            (1 << 0),
            (1 << 8)
        ])
