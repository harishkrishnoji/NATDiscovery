from helper.variables_firewall import CP_DEVICE_TO_QUERY, DISREGAR_PKG


def device_filter(domain):
    if "All" in CP_DEVICE_TO_QUERY or domain in CP_DEVICE_TO_QUERY:
        return True


def pkg_filter(domain):
    for disr in DISREGAR_PKG:
        if domain == disr.get("domain"):
            return disr.get("pkg")
    return []
