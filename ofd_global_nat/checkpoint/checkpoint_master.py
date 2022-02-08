"""Palo Alto Rules - Log Profile Update."""
import os
from cp_mgmt.client import CheckPointMGMTClient
from helper_fts.fts_sane import CP_OFD_URL, CP_OFS_URL
from helper.local_helper import log, MongoDB
# from helper.local_helper import uploadfile
from helper.variables_firewall import CP_DEVICE_TO_QUERY, DISREGAR_PKG
from checkpoint.checkopint_fun import CP_NAT_Function
# from nautobot.nautobot_master import NautobotClient

dbp = os.environ.get("RD_OPTION_DB_PWD")
dbu = os.environ.get("RD_OPTION_DB_USER")
dbh = os.environ.get("RD_OPTION_DB_HOST")
db = MongoDB(dbu, dbp, dbh)


def cp_master(env):
    if "ofd" in env:
        data = {
            "username": os.environ.get("RD_OPTION_CP_OFD_USER"),
            "password": os.environ.get("RD_OPTION_CP_OFD_PWD"),
            "url": CP_OFD_URL,
            # "url": "https://usoma1fwmctl01a.1dc.com/web_api/"
        }
    elif "ofs" in env:
        data = {
            "username": os.environ.get("RD_OPTION_CP_OFS_USER"),
            "password": os.environ.get("RD_OPTION_CP_OFS_PWD"),
            "url": CP_OFS_URL,
            # "url": "https://jcpp1sm1.security.onefiserv.net/web_api/"
            # "url": "https://11.30.61.89/web_api/"
        }
    cp = CheckPointMGMTClient(**data)
    cpfun = CP_NAT_Function(cp, env)
    log.info("Gathering Domain...")
    cpfun.domain_lst()
    log.info("Gathering Gateways...")
    cpfun.gateways()
    cpfun.jsonfile(cpfun.gateways_list, "DEVICE")
    log.info("Writting Devices to DB...")
    for device in cpfun.gateways_list:
        device.pop("_id", None)
        db.host_collection(device)
    # NautobotClient(cpfun.gateways_list)
    # resp = uploadfile(cpfun.filename)
    # log.info(resp.strip())
    for domain in cpfun.domain_list:
        if "All" in CP_DEVICE_TO_QUERY or domain in CP_DEVICE_TO_QUERY:
            log.info(f"Gathering NAT Rules : {domain}...")
            for disr in DISREGAR_PKG:
                if domain == disr.get("domain"):
                    cpfun.disregard_pkg = disr.get("pkg")
            cpfun.cp = CheckPointMGMTClient(**data, domain=domain)
            cpfun.cma_packages()
    cpfun.jsonfile(cpfun.nat_rules, "NAT")
    # resp = uploadfile(cpfun.filename)
    # log.info(resp.strip())
    log.info("Writting NAT Rules to DB...")
    for rule in cpfun.nat_rules:
        device.pop("_id", None)
        db.nat_collection(rule)
    log.info("Job done")
