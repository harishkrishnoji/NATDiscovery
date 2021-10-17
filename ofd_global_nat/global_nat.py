#!/usr/bin/env python3
# Name: OFD Global NAT policy read
# Description: This script is to pull NAT policy file


import time
import datetime
import json
from datetime import date
from cp_mgmt.client import CheckPointMGMTClient
from pa_pano.client import PAN_Client
from helper_fts.email import send_email
from helper_fts.fts_sane import *
from helper_fts.logger import get_logger
from cp_helper import *
from palo_helper import *

printnat = {}
table_data = []
cp_table_data = []
email_data = []

logger = get_logger("OFD NAT")

if __name__ == "__main__":
    logger.info("Starting NAT Collection Script...")
    filename = "RUNDECK_OFD_NAT-" + time.strftime("%m%d%Y-%H%M") + ".json"
    email_data.append("Weekly OFD Global NAT (CheckPoint and PaloAlto)")
    email_data.append("=" * 100)
    email_data.append(f"\nScript start time (CheckPoint) : {datetime.datetime.now()}")
    table_data = {}
    table_data["time"] = {
        "Last_update": str(datetime.datetime.now()),
        "Note": "If update is older than 2 weeks, \
            send email to SANE-FirewallEngineering@fiserv.com",
    }
    table_data["data"] = []

    #################################
    #         Checkpoint            #
    #################################
    ofd = {
        "username": os.environ.get("RD_OPTION_CPUSER"),
        "password": os.environ.get("RD_OPTION_CPPWD"),
        "url": CP_OFD_URL,
    }
    logger.info("CheckPoint")
    cp = CheckPointMGMTClient(**ofd)
    DomainList = get_domain_list(cp)

    if DomainList[0] == 0:
        for i in DomainList[1]:
            logger.info(f"\tDomain : {str(i)}")
            cp = CheckPointMGMTClient(**ofd, domain=i)
            cp_table_data.extend(get_cma_packages_list(cp))
        for i in cp_table_data:
            table_data["data"].extend(i)
    else:
        logger.error(f"\tUnable to pull Domain List - {DomainList[1]}")
    email_data.append(f"Script end time (CheckPoint) : {datetime.datetime.now()}")

    #################################
    #           PaloAlto            #
    #################################
    pano = {}
    pano["url"] = PA_OFD_URL
    pano["site"] = "Prod"
    email_data.append(f"Script start time (Panorama {pano['site']}) : {datetime.datetime.now()}")
    logger.info(f"Panorama {pano['site']}")
    pan = PAN_Client(
        url=pano["url"],
        username=os.environ.get("RD_OPTION_PAUSER"),
        password=os.environ.get("RD_OPTION_PAPWD"),
        ssl_verify=False,
    )
    # Get device group list
    d_group = get_device_group_lst(pan)
    get_address(pan, "/config/shared/address")
    get_gp_lst(pan, "/config/shared/address-group")
    PAN_DG = "/config/devices/entry[@name='localhost.localdomain']/device-group/entry"
    for dGroup in d_group:
        dgrp = dGroup["device"]
        logger.info(f"\t\tDevice Group : {dgrp}")
        xobj = f"{PAN_DG}[@name='{dgrp}']/address"
        xgrp = f"{PAN_DG}[@name='{dgrp}']/address-group"
        get_address(pan, xobj)
        get_gp_lst(pan, xgrp)
        xpath = f"{PAN_DG}[@name='{dgrp}']/pre-rulebase/nat"
        get_nat_lst(pan, xpath, pano["site"], dGroup)
        xpath = f"{PAN_DG}[@name='{dgrp}']/post-rulebase/nat"
        get_nat_lst(pan, xpath, pano["site"], dGroup)
    email_data.append(f"Script end time (Panorama {pano['site']}) : {datetime.datetime.now()}")
    logger.info("Completed pulling NATs from CheckPoint and PaloAlto devices.")
    table_data["data"].extend(outnat)

    # Write Date to file, Upload to remote server, and email notification
    with open(filename, "w+") as json_file:
        json.dump(table_data, json_file, indent=4, separators=(",", ": "), sort_keys=True)
    resp = uploadfile(filename)
    logger.info(resp.strip())
    email_data.append(f"{resp}")
    email_data.append("=" * 100)
    d = {
        "From": "sane_automation@fiserv.com",
        "to": "Rodrigo.Miranda@Fiserv.com",
        "cc": "harish.krishnoji@Fiserv.com, william.dolbow@Fiserv.com, Andy.Clark@Fiserv.com",
        "subject": f"Weekly OFD Global NAT file update - {str(date.today())}",
        "body": email_data,
    }
    send_email(**d)
    logger.info("Email Notification Sent - Task Complete")
