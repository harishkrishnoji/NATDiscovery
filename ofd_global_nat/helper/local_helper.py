# pylint: disable=W1203, C0103, W0631
"""Script local config."""

import os
import json
from helper_fts.logger import get_logger
from helper.gitlab_helper import GitLab_Client
from helper_fts.vault import hashi_vault_rundeck

# from helper_fts.vault import hashi_vault


token = os.environ.get("HASHI_TOKEN")
log = get_logger()

vdata = {
    "namespace": os.environ.get("VAULT_NAMESPACE"),
    "role_id": os.environ.get("VAULT_ROLE_ID"),
    "secret_id": os.environ.get("VAULT_SECRET_ID"),
}


def get_git_keys():
    path = "gitlab"
    # vault_data = hashi_vault(token=token, path=path)
    vdata["path"] = path
    vault_data = hashi_vault_rundeck(**vdata)
    return vault_data["data"]["data"]["access_token"].get("sane_backups")


git_token = get_git_keys()
glab = GitLab_Client(token=git_token)


def uploadfile(sas_vip_info, env):
    """Update VIP data on to remote server and Nautobot."""
    filename = f"{env}.json"
    with open(filename, "w+") as json_file:
        json.dump(sas_vip_info, json_file, indent=4, separators=(",", ": "), sort_keys=True)
    gitUpload(filename, env)


def gitUpload(filename, env):
    glab.filepath = f"fw-nat/{env}.json"
    glab.update_file(filename)


def get_credentials_cp(mdm_addr, url):
    path = "checkpoint_secrets"
    # vault_data = hashi_vault(token=token, path=path)
    vdata["path"] = path
    vault_data = hashi_vault_rundeck(**vdata)
    return {
        "username": vault_data["data"]["data"][mdm_addr][0].get("username"),
        "password": vault_data["data"]["data"][mdm_addr][0].get("password"),
        "url": url,
    }


def get_credentials_pan(pan_name):
    path = "panorama_api_keys_v2"
    # vault_data = hashi_vault(token=token, path=path)
    vdata["path"] = path
    vault_data = hashi_vault_rundeck(**vdata)
    return vault_data["data"]["data"][pan_name][0].get("api_key_v9")


def get_nb_keys(nburl):
    path = "nautobot"
    # vault_data = hashi_vault(token=token, path=path)
    vdata["path"] = path
    vault_data = hashi_vault_rundeck(**vdata)
    if "-cat" in nburl.lower():
        return vault_data["data"]["data"]["keys"].get("cat")
    return vault_data["data"]["data"]["keys"].get("prod")
