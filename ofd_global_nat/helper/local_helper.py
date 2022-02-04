# pylint: disable=W1203, C0103, W0631
"""Script local config."""

import os
import requests
from helper_fts.logger import get_logger
from pymongo import MongoClient

log = get_logger()


def uploadfile(fname):
    """Upload file to remote server.

    Args:
        fname (str): Filename which need to be uploaded
    """
    url = "https://sas-automation.1dc.com/cgi-bin/uploadfile.py"
    files = [("filename", (os.path.basename(fname), open(fname, "rb")))]
    response = requests.request("POST", url, files=files, verify=False)
    return response.text


class MongoDB:
    """Create a MongoDB API client."""

    def __init__(self, usr, pwd, host):
        """Initialize MongoDB API Client.

        Args:
            usr (str): Username to authenticate to MongoDB API.
            pwd (str): Password to authenticate to MongoDB API.
            host (str): MongoDB host.
        """
        self.log = log
        self.client = MongoClient(host=f"mongodb://{usr}:{pwd}@{host}/fdc_inventory?authSource=admin")
        self.log.debug("DB initiated")

    def update_document(self, query, data, db):
        """Update document on MongoDB if diff condition pass.

        Args:
            query (str): DB query string.
            data (dict): data to run diff function.
            db (object): MongoDB Object.
        """
        document = db.find_one(query)
        if document:
            document.pop("_id", None)
            db.replace_one(query, data)
        else:
            db.insert_one(data)

    def host_collection(self, lb_data):
        """Get Device collection from MongoDB.

        Args:
            lb_data (dict): LB Device related info.
        """
        db_vip = self.client.fdc_inventory.sane_devices
        query = {"mgmt_address": lb_data.get("mgmt_address"), "hostname": lb_data.get("hostname")}
        self.update_document(query, lb_data, db_vip)

    def nat_collection(self, nat):
        """Get nat collection from MongoDB.

        Args:
            nat (dict): NAT Rule info.
        """
        db_host = self.client.fdc_inventory.sane_fw_nat
        query = {
            "name": nat.get("name"),
            "Firewall-Name": nat.get("Firewall-Name")
        }
        self.update_document(query, nat, db_host)
