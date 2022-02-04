# pylint: disable=W1203, C0103, W0631, W0703
"""Nautobot Master."""

from nautobot.nautobot_fun import SANE_DEVICE
from helper.local_helper import log


def NautobotClient(device_data):
    """Nautobot Object create function.

    Args:
        nat_data (dict): LB Data.
    """
    device = SANE_DEVICE()
    for device1 in device_data:
        device.device_data = device1
        device.device()
