# pylint: disable=W1203, C0103, W0631, W0401, W0703, C0412
"""Master."""

import os
from helper.local_helper import log
from paloalto.paloalto_master import palo_master
from checkpoint.checkpoint_master import cp_master

ENV = os.environ.get("RD_OPTION_ENV")

log.info(f"Environment {ENV}")

if __name__ == "__main__":
    try:
        if "CheckPoint" in ENV:
            cp_master(ENV)
        elif "PaloAlto" in ENV:
            palo_master(ENV)
    except Exception as err:
        log.error(f"{err}")
