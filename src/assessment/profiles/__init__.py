"""Device-specific security profiles for targeted assessment."""

from .base import DeviceProfile
from .detect import detect_profile
from .openwrt import OpenWrtProfile
from .linksys import LinksysProfile
from .cisco import CiscoIOSProfile

__all__ = [
    "DeviceProfile",
    "detect_profile",
    "OpenWrtProfile",
    "LinksysProfile",
    "CiscoIOSProfile",
]
