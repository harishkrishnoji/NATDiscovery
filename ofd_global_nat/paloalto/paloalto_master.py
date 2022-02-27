"""Palo Alto Rules - Log Profile Update."""
import os
from panos import panorama
from helper.local_helper import log
# from helper.local_helper import uploadfile
from paloalto.paloalto_fun import Palo_NAT_Function
from helper.hashi_vault import hashi_vault
from helper.nat_sqlite_fun import WriteToDB
from paloalto.paloalto_filters import device_filter
# from helper_fts.fts_sane import CP_OFD_URL


def hashi_cred(pan_name):
    # Get token from Hashi vault
    token = os.environ.get("HASHI_TOKEN")
    path = "panorama_api_keys_v2"
    vault_data = hashi_vault(token=token, path=path)
    API_KEY = vault_data["data"]["data"][pan_name][0].get("api_key_v9")
    return API_KEY


def palo_master(env, site=""):
    """NAT Rule Master function."""
    if "ofd" in env:
        pan_name = "panorama_ofd"
        HOSTNAME = "10.164.232.91"
    elif "ofs" in env:
        if site == "lowers":
            pan_name = "panorama_lower"
            HOSTNAME = "exinnpafw01.security.onefiserv.net"
        elif site == "virtual":
            pan_name = "panorama_vms"
            HOSTNAME = "lxspapafw.security.onefiserv.net"
        elif site == "main":
            HOSTNAME = "jcpanorama.onefiserv.net"
            pan_name = "panorama_m500s"
        elif site == "azure_upper":
            pan_name = "panorama_azure_upper"
            HOSTNAME = "azurpanorama.onefiserv.net"
        elif site == "azure_lower":
            pan_name = "panorama_ofs_corp"
            HOSTNAME = "jccorepanorama.onefiserv.net"
        elif site == "corp":
            pan_name = "panorama_ofs_corp"
            HOSTNAME = "jccorepanorama.onefiserv.net"
    API_KEY = hashi_cred(pan_name)
    pan = panorama.Panorama(HOSTNAME, api_key=API_KEY, port=443)
    pafun = Palo_NAT_Function(pan, env, site)
    pafun.firewall_devices()
    # Update SQLite DB
    sq_db = WriteToDB(f"{env}_palo_{site}")
    pafun.db = sq_db

    for device in pafun.device_list:
        if device_filter(device):
            try:
                pafun.get_nat_policy("show running nat-policy-addresses", device)
                pafun.get_nat_policy("show running nat-policy", device)
            except Exception as err:
                log.error(f"Unable to connect : {device} : {err}")

    # pafun.jsonfile(pafun.rules, "NAT")
    # resp = uploadfile(pafun.filename)
    # log.info(resp.strip())
    # for rule in pafun.nat_rules:
    #     db.nat_collection(rule)
    log.info("Job done")
