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
        cp_master("ofd", "cp")
    elif ENV == "OFD_PaloAlto":
        palo_master("ofd", "prod")
    elif ENV == "OFS_CheckPoint":
        cp_master("ofs", "cp")
    elif ENV == "OFS_PaloAlto_Lowers":
        palo_master("ofs", "lowers")
    elif ENV == "OFS_PaloAlto_Virtual":
        palo_master("ofs", "virtual")
    elif ENV == "OFS_PaloAlto_Main":
        palo_master("ofs", "main")
    elif ENV == "OFS_PaloAlto_AZUpper":
        palo_master("ofs", "azure_upper")
    elif ENV == "OFS_PaloAlto_AZLower":
        palo_master("ofs", "azure_lower")
    elif ENV == "OFS_PaloAlto_Corp":
        palo_master("ofs", "corp")
    # except Exception as err:
        # log.error(f"{err}")
