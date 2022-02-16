"""Palo Alto Rules - Log Profile Update."""
import os
from cp_mgmt.client import CheckPointMGMTClient
from helper_fts.fts_sane import CP_OFD_URL, CP_OFS_URL
from helper.local_helper import log
from helper.hashi_vault import hashi_vault
from helper.nat_sqlite_fun import WriteToDB
from helper.variables_firewall import CP_DEVICE_TO_QUERY, DISREGAR_PKG
from checkpoint.checkopint_fun import CP_NAT_Function

# from nautobot.nautobot_master import NautobotClient
# from helper.local_helper import MongoDB
# from helper.local_helper import uploadfile

# dbp = os.environ.get("RD_OPTION_DB_PWD")
# dbu = os.environ.get("RD_OPTION_DB_USER")
# dbh = os.environ.get("RD_OPTION_DB_HOST")
# db = MongoDB(dbu, dbp, dbh)


def cp_master(env, fwl):

    # Get token from Hashi vault
    token = os.environ.get("HASHI_TOKEN")
    path = "checkpoint_secrets"
    vault_data = hashi_vault(token=token, path=path)
    if "ofd" in env:
        mdm_addr = "10.116.160.16"
        log.info(CP_OFD_URL)
        url = "https://10.116.160.16/web_api/"
    elif "ofs" in env:
        mdm_addr = "10.30.61.89"
        log.info(CP_OFS_URL)
        # url = CP_OFS_URL
        url = "https://11.30.61.89/web_api/"
    data = {
        "username": vault_data["data"]["data"][mdm_addr][0].get("username"),
        "password": vault_data["data"]["data"][mdm_addr][0].get("password"),
        "url": url,
    }
    # Invoke Checkpoint API Client
    cp = CheckPointMGMTClient(**data)
    cpfun = CP_NAT_Function(cp, env)
    log.info("Gathering Domain...")
    cpfun.domain_lst()
    log.info("Gathering Gateways...")
    cpfun.gateways()
    # cpfun.jsonfile(cpfun.gateways_list, "DEVICE")
    # Update MongoDB
    # log.info("Writting Devices to DB...")
    # for device in cpfun.gateways_list:
    #     device.pop("_id", None)
    #     db.host_collection(device)

    # Update Nautobot Devices
    # NautobotClient(cpfun.gateways_list)
    # resp = uploadfile(cpfun.filename)
    # log.info(resp.strip())

    # Update SQLite DB
    sq_db = WriteToDB(f"{env}_{fwl}")
    cpfun.db = sq_db
    for domain in cpfun.domain_list:
        # log.info(domain)
        if "All" in CP_DEVICE_TO_QUERY or domain in CP_DEVICE_TO_QUERY:
            log.info(f"Gathering NAT Rules : {domain}...")
            for disr in DISREGAR_PKG:
                if domain == disr.get("domain"):
                    cpfun.disregard_pkg = disr.get("pkg")
            cpfun.cp = CheckPointMGMTClient(**data, domain=domain)
            cpfun.cma_packages()
    log.info(len(cpfun.nat_rules))

    # cpfun.jsonfile(cpfun.nat_rules, "NAT")
    # resp = uploadfile(cpfun.filename)
    # log.info(resp.strip())
    # log.info("Writting NAT Rules to DB...")
    # for rule in cpfun.nat_rules:
    #     device.pop("_id", None)
    #     db.nat_collection(rule)

    log.info("Job done")
