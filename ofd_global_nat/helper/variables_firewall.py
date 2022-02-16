# pylint: disable=W1203, C0103, W0631
"""Script local config."""

#########################################################################
#   List of Keys/values which need to be collected from PAN / MDM
#########################################################################

PALO_DEVICE_FIELDS = ['serial', 'connected', 'hostname', 'ip-address', 'model', 'sw-version', 'ha', 'multi-vsys', 'vsys']
CP_DEVICE_FIELDS = ["name", "type", "operating-system", "hardware", "version", "ipv4-address", "network-security-blades"]
DEVICE_ROLE = {"name": "firewall", "slug": "firewall", "description": "CheckPoint and PaloAlto Firewall role"}

#########################################################################
#   List of Devices to pull data from PAN / MDM
#########################################################################

PALO_DEVICE_TO_QUERY = list(["All"])
# CP_DEVICE_TO_QUERY = list(["TEST"])
CP_DEVICE_TO_QUERY = list(["All"])

DISREGAR_PKG = [{"domain": "FISERV_RMTCENTERS", "pkg": ["Standard"]}]
