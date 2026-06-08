"""
Auto-detection: selects the best device profile based on device_info gathered during assessment.
"""

from typing import Dict, List, Optional, Type

from .base import DeviceProfile
from .openwrt import OpenWrtProfile
from .linksys import LinksysProfile
from .cisco import CiscoIOSProfile

PROFILE_REGISTRY: List[Type[DeviceProfile]] = [
    LinksysProfile,
    OpenWrtProfile,
    CiscoIOSProfile,
]


def detect_profile(device_info: Dict) -> Optional[Type[DeviceProfile]]:
    """Select the best-matching profile for the given device info.

    Returns the profile class with highest confidence above 0.5 threshold,
    or None if no profile matches confidently.
    """
    best_match: Optional[Type[DeviceProfile]] = None
    best_score = 0.0

    for profile_cls in PROFILE_REGISTRY:
        score = profile_cls.matches(device_info)
        if score > best_score:
            best_score = score
            best_match = profile_cls

    if best_score >= 0.5:
        return best_match
    return None
