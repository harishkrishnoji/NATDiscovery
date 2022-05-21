"""Palo Alto Rules - Log Profile Update."""
from cp_mgmt.client import CheckPointMGMTClient
from helper_fts.fts_sane import CP_OFD_URL, CP_OFS_URL
from helper.local_helper import log, get_credentials_cp
from checkpoint.checkpoint_filters import device_filter, pkg_filter
from checkpoint.checkopint_fun import CP_NAT_Function
from helper.local_helper import uploadfile

# from nautobot.nautobot_master import NautobotClient


def cp_master(site):
    if "OFD" in site:
        env = "ofd"
        mdm_addr = "10.116.160.16"
        url = CP_OFD_URL
    elif "OFS" in site:
        env = "ofs"
        mdm_addr = "10.30.61.89"
        url = CP_OFS_URL
    data = get_credentials_cp(mdm_addr, url)
    cp = CheckPointMGMTClient(**data)
    cpfun = CP_NAT_Function(cp, env)
    log.info("Gathering Domain...")
    cpfun.domain_lst()
    log.info("Gathering Gateways...")
    cpfun.gateways()
    # NautobotClient(cpfun.gateways_list)
    for domain in cpfun.domain_list:
        if device_filter(domain):
            log.info(f"Gathering NAT Rules : {domain}...")
            cpfun.disregard_pkg = pkg_filter(domain)
            cpfun.cp = CheckPointMGMTClient(**data, domain=domain)
            cpfun.cma_packages()
    log.info(f"Total NAT rule count: {len(cpfun.nat_rules)}")
    uploadfile(cpfun.nat_rules, site)
    log.info("Job done")
