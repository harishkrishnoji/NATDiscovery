# pylint: disable=W1203, C0103, W0631, W0401, W0703, C0412
"""Master."""

import os
from helper.local_helper import log
from paloalto.paloalto_master import palo_master
from checkpoint.checkpoint_master import cp_master


ENV = os.environ.get("RD_OPTION_ENV")

log.debug("Master Initiated.. ")
log.info(f"Environment {ENV}")

if __name__ == "__main__":
    # try:
    if ENV == "OFD_CheckPoint":
        cp_master("ofd")
    elif ENV == "OFD_PaloAlto":
        palo_master("ofd")
    elif ENV == "OFS_CheckPoint":
        cp_master("ofs")
    elif ENV == "OFS_PaloAlto_Lowers":
        palo_master("ofs", "Lowers")
    elif ENV == "OFS_PaloAlto_Virtual":
        palo_master("ofs", "Virtual")
    elif ENV == "OFS_PaloAlto_Main":
        palo_master("ofs", "Main")
    elif ENV == "OFS_PaloAlto_AZUpper":
        palo_master("ofs", "Azure_Upper")
    elif ENV == "OFS_PaloAlto_AZLower":
        palo_master("ofs", "Azure_Lower")
    # except Exception as err:
    #     log.error(f"{err}")
