import os

# from helper.variables_firewall import PALO_DEVICE_TO_QUERY

PALO_DEVICE_TO_QUERY = os.environ.get("RD_OPTION_DEVICES", "All")


def device_filter(device):
    """Device list."""
    if (
        ("All" in PALO_DEVICE_TO_QUERY or device.get("hostname") in PALO_DEVICE_TO_QUERY)
        and (device.get("ha") == "passive" and device.get("connected") == "yes")
    ):
        return True
