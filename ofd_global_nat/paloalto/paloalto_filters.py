from helper.variables_firewall import PALO_DEVICE_TO_QUERY


def device_filter(device):
    if (
        ("All" in PALO_DEVICE_TO_QUERY or device.get("hostname") in PALO_DEVICE_TO_QUERY)
        and (device.get("ha") == "passive" and device.get("connected") == "yes")
    ):
        return True
