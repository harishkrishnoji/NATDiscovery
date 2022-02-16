"""Palo Alto Rules - Log Profile Update."""
import os
from panos import panorama
from helper.local_helper import log
# from helper.local_helper import log, MongoDB, uploadfile
from paloalto.paloalto_fun import Palo_NAT_Function
from helper.hashi_vault import hashi_vault
from helper.nat_sqlite_fun import WriteToDB
from helper.variables_firewall import PALO_DEVICE_TO_QUERY
# from helper_fts.fts_sane import CP_OFD_URL

# dbp = os.environ.get("RD_OPTION_DB_PWD")
# dbu = os.environ.get("RD_OPTION_DB_USER")
# dbh = os.environ.get("RD_OPTION_DB_HOST")
# db = MongoDB(dbu, dbp, dbh)

# token = os.environ.get("HASHI_TOKEN")


def palo_master(env, site=""):
    token = os.environ.get("HASHI_TOKEN")
    path = "panorama_api_keys_v2"
    vault_data = hashi_vault(token=token, path=path)
    """NAT Rule Master function."""
    if "ofd" in env:
        pan_name = "panorama_ofd"
        HOSTNAME = "10.164.232.91"
    elif "ofs" in env:
        if site == "lowers":
            pan_name = "panorama_lower"
            HOSTNAME = "11.35.129.38"
        elif site == "virtual":
            pan_name = "panorama_vms"
            HOSTNAME = "11.26.142.130"
        elif site == "main":
            HOSTNAME = "jcpanorama.onefiserv.net"
            pan_name = "panorama_m500s"
        elif site == "azure_upper":
            pan_name = "panorama_azure_upper"
            HOSTNAME = "11.38.0.140"
        elif site == "azure_lower":
            pan_name = "panorama_ofs_corp"
            HOSTNAME = "11.130.101.100"
        elif site == "corp":
            pan_name = "panorama_ofs_corp"
            HOSTNAME = "11.130.101.100"
    log.info(vault_data["data"]["data"][pan_name])
    API_KEY = vault_data["data"]["data"][pan_name][0].get("api_key_v9")
    # HOSTNAME = vault_data["data"]["data"][pan_name][0]["ip_address"][0]
    # log.info(API_KEY)
    # '''
    pan = panorama.Panorama(HOSTNAME, api_key=API_KEY, port=443)
    pafun = Palo_NAT_Function(pan, env, site)
    pafun.firewall_devices()
    # log.info(pafun.device_list)
    # pafun.jsonfile(pafun.device_list, "DEVICE")
    # for device in pafun.device_list:
    #     db.host_collection(device)

    # Update SQLite DB
    sq_db = WriteToDB(f"{env}_palo_{site}")
    pafun.db = sq_db

    for device in pafun.device_list:
        # log.info(f'name : {device.get("hostname")}, HA: {device.get("ha")}, connected: {device.get("connected")}')
        # if ("All" in PALO_DEVICE_TO_QUERY or device.get("hostname") in PALO_DEVICE_TO_QUERY) and ("fw02" in device.get("hostname") or "fw03" in device.get("hostname")) and device.get("connected") == "yes":
        if ("All" in PALO_DEVICE_TO_QUERY or device.get("hostname") in PALO_DEVICE_TO_QUERY) and (device.get("ha") == "passive" and device.get("connected") == "yes"):
            try:
                pafun.get_nat_policy("show running nat-policy-addresses", device)
                pafun.get_nat_policy("show running nat-policy", device)
            except Exception as err:
                log.error(f"Unable to connect : {device} : {err}")

    # pafun.nat_policy()
    pafun.jsonfile(pafun.rules, "NAT")
    # resp = uploadfile(pafun.filename)
    # log.info(resp.strip())
    # for rule in pafun.nat_rules:
    #     db.nat_collection(rule)
    log.info("Job done")
