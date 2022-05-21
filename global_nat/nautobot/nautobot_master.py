# pylint: disable=W1203, C0103, W0631, W0703
"""Nautobot Master."""

import os
from nautobot.nautobot_fun import SANE_DEVICE
from helper.local_helper import log

url     = os.environ.get("RD_OPTION_NAUTOBOT_URL")
token   = os.environ.get("RD_OPTION_NAUTOBOT_KEY")


def NautobotClient(device_data):
    """Nautobot Object create function.

    Args:
        nat_data (dict): LB Data.
    """
    log.info("Starting Nautobot Master...")
    device = SANE_DEVICE(url=url, token=token)
    for device1 in device_data:
        device.device_data = device1
        device.device()
