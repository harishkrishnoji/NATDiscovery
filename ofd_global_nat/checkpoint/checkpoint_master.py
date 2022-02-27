"""Palo Alto Rules - Log Profile Update."""
import os
from cp_mgmt.client import CheckPointMGMTClient
from helper_fts.fts_sane import CP_OFD_URL, CP_OFS_URL
from helper.local_helper import log
from helper.hashi_vault import hashi_vault
from helper.nat_sqlite_fun import WriteToDB
from checkpoint.checkpoint_filters import device_filter, pkg_filter
from checkpoint.checkopint_fun import CP_NAT_Function

# from nautobot.nautobot_master import NautobotClient
# from helper.local_helper import uploadfile


def hashi_cred(mdm_addr, url):
    # Get token from Hashi vault
    token = os.environ.get("HASHI_TOKEN")
    path = "checkpoint_secrets"
    vault_data = hashi_vault(token=token, path=path)
    return {
        "username": vault_data["data"]["data"][mdm_addr][0].get("username"),
        "password": vault_data["data"]["data"][mdm_addr][0].get("password"),
        "url": url,
    }


def cp_master(env, fwl):
    if "ofd" in env:
        mdm_addr = "10.116.160.16"
        log.info(CP_OFD_URL)
        url = CP_OFD_URL
    elif "ofs" in env:
        mdm_addr = "10.30.61.89"
        log.info(CP_OFS_URL)
        url = CP_OFS_URL
    data = hashi_cred(mdm_addr, url)
    # Invoke Checkpoint API Client
    cp = CheckPointMGMTClient(**data)
    cpfun = CP_NAT_Function(cp, env)
    log.info("Gathering Domain...")
    cpfun.domain_lst()
    log.info("Gathering Gateways...")
    cpfun.gateways()
    # cpfun.jsonfile(cpfun.gateways_list, "DEVICE")
    # Update Nautobot Devices
    # NautobotClient(cpfun.gateways_list)
    # resp = uploadfile(cpfun.filename)
    # log.info(resp.strip())

    # Update SQLite DB
    sq_db = WriteToDB(f"{env}_{fwl}")
    cpfun.db = sq_db
    for domain in cpfun.domain_list:
        if device_filter(domain):
            log.info(f"Gathering NAT Rules : {domain}...")
            cpfun.disregard_pkg = pkg_filter(domain)
            cpfun.cp = CheckPointMGMTClient(**data, domain=domain)
            cpfun.cma_packages()
    log.info(len(cpfun.nat_rules))

    # cpfun.jsonfile(cpfun.nat_rules, "NAT")
    # resp = uploadfile(cpfun.filename)
    # log.info(resp.strip())
    log.info("Job done")
