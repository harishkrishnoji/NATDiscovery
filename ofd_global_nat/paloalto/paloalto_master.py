"""Palo Alto Rules - Log Profile Update."""
import os
from panos import panorama
from helper.local_helper import log, MongoDB, uploadfile
from paloalto.paloalto_fun import Palo_NAT_Function
# from helper_fts.fts_sane import CP_OFD_URL

dbp = os.environ.get("RD_OPTION_DB_PWD")
dbu = os.environ.get("RD_OPTION_DB_USER")
dbh = os.environ.get("RD_OPTION_DB_HOST")
db = MongoDB(dbu, dbp, dbh)


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
    pa.firewall_devices()
    pa.jsonfile(pa.device_list, "DEVICE")
    for device in pa.device_list:
        db.host_collection(device)
    pa.nat_policy()
    pa.jsonfile(pa.rules, "NAT")
    resp = uploadfile(pa.filename)
    log.info(resp.strip())
    for rule in pa.nat_rules:
        db.nat_collection(rule)
    log.info("Job done")
