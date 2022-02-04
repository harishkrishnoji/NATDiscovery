"""Palo Alto Rules - Log Profile Update."""
import os
from panos import panorama
from helper.local_helper import log
from paloalto.paloalto_fun import Palo_NAT_Function
from helper_fts.fts_sane import CP_OFD_URL

def palo_master(env, site=""):
    """NAT Rule Master function."""
    if "ofd" in env:
        HOSTNAME = os.environ.get("RD_OPTION_PAN_OFD_NAME")
        API_KEY = os.environ.get("RD_OPTION_PAN_OFD_APIKEY")
    elif "ofs" in env:
        if site == "Lowers":
            HOSTNAME = os.environ.get("RD_OPTION_PAN_LWR_NAME")
            API_KEY = os.environ.get("RD_OPTION_PAN_LWR_APIKEY")
        elif site == "Virtual":
            HOSTNAME = os.environ.get("RD_OPTION_PAN_VIR_NAME")
            API_KEY = os.environ.get("RD_OPTION_PAN_VIR_APIKEY")
        elif site == "Main":
            HOSTNAME = os.environ.get("RD_OPTION_PAN_JC_NAME")
            API_KEY = os.environ.get("RD_OPTION_PAN_JC_APIKEY")
        elif site == "Azure_Upper":
            HOSTNAME = os.environ.get("RD_OPTION_PAN_AZU_NAME")
            API_KEY = os.environ.get("RD_OPTION_PAN_AZU_APIKEY")
        elif site == "Azure_Lower":
            HOSTNAME = os.environ.get("RD_OPTION_PAN_AZL_NAME")
            API_KEY = os.environ.get("RD_OPTION_PAN_AZL_APIKEY")
    pan = panorama.Panorama(HOSTNAME, api_key=API_KEY, port=443)
    pa = Palo_NAT_Function(pan, env, site)
    pa._firewall_devices()
    pa._nat_policy()
    log.info("Job done")
