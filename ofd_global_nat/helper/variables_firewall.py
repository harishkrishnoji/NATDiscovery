# pylint: disable=W1203, C0103, W0631
"""Script local config."""

#########################################################################
#   List of Keys/values which need to be collected from PAN / MDM
#########################################################################

PALO_DEVICE_FIELDS = ['serial', 'connected', 'hostname', 'ip-address', 'model', 'sw-version', 'ha', 'multi-vsys', 'vsys']
CP_DEVICE_FIELDS = ["name", "type", "operating-system", "hardware", "version", "ipv4-address", "network-security-blades"]

#########################################################################
#   List of Devices to pull data from PAN / MDM
#########################################################################

PALO_DEVICE_TO_QUERY = list(["All"])
CP_DEVICE_TO_QUERY = list(["All"])

"""
hide/many-to-one
	src - interface, dst - ip 
	src_translation_type - dynamic ip and port
		address_type - interface address
		address_type - src_translation_address (if we want to use different IP from interface)
	src_translation_type - dynamic ip
		address_type - src_translation_address
static-bidirectional
	src - ip, dst - ip 
	src_translation_type - static ip
	src_translation_address - 110.10.10.x
	bidirectional option check
inbound
	src - ip, dst - ip 
	dst_translation_address - 110.10.10.x
	bidirectional option check
"""