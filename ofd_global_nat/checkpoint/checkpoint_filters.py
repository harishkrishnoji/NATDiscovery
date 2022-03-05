import os
from helper.variables_firewall import DISREGAR_PKG

CP_DEVICE_TO_QUERY = os.environ.get("RD_OPTION_DEVICES", "All")


def device_filter(domain):
    if "All" in CP_DEVICE_TO_QUERY or domain in CP_DEVICE_TO_QUERY:
        return True


def pkg_filter(domain):
    for disr in DISREGAR_PKG:
        if domain == disr.get("domain"):
            return disr.get("pkg")
    return []
