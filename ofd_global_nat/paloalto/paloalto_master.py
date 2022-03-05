"""Palo Alto Rules - Log Profile Update."""
from panos import panorama
from helper.local_helper import log
from helper.local_helper import uploadfile, get_credentials_pan
from paloalto.paloalto_fun import Palo_NAT_Function
from paloalto.paloalto_filters import device_filter


def palo_master(site):
    """NAT Rule Master function."""
    site_lst = site.lower().split("_")
    env = site_lst[0]
    site1 = site_lst[2] if len(site_lst) == 3 else "prod"
    if "OFD" in site:
        pan_name = "panorama_ofd"
        HOSTNAME = "panorama.1dc.com"
    elif "OFS" in site:
        if "Lowers" in site:
            pan_name = "panorama_lower"
            HOSTNAME = "exinnpafw01.security.onefiserv.net"
        elif "Virtual" in site:
            pan_name = "panorama_vms"
            HOSTNAME = "lxspapafw.security.onefiserv.net"
        elif "Main" in site:
            HOSTNAME = "jcpanorama.onefiserv.net"
            pan_name = "panorama_m500s"
        elif "AZUpper" in site:
            pan_name = "panorama_azure_upper"
            HOSTNAME = "azurpanorama.onefiserv.net"
        elif "AZLower" in site:
            pan_name = "panorama_ofs_corp"
            HOSTNAME = "jccorepanorama.onefiserv.net"
        elif "Corp" in site:
            pan_name = "panorama_ofs_corp"
            HOSTNAME = "jccorepanorama.onefiserv.net"
    API_KEY = get_credentials_pan(pan_name)
    pan = panorama.Panorama(HOSTNAME, api_key=API_KEY, port=443)
    pafun = Palo_NAT_Function(pan, env, site1)
    pafun.firewall_devices()
    for device in pafun.device_list:
        if device_filter(device):
            try:
                pafun.get_nat_policy("show running nat-policy-addresses", device)
                pafun.get_nat_policy("show running nat-policy", device)
            except Exception as err:
                log.error(f"Unable to connect : {device} : {err}")
    log.info(f"Total NAT rule count: {len(pafun.rules)}")
    uploadfile(pafun.rules, site)
    log.info("Job done")
