import os
import hvac


def hashi_vault(token="", path=""):
    token = os.environ.get("HASHI_TOKEN")
    vault_namespace = "network/net-sane"
    vault_address = "https://vault-enterprise.onefiserv.net"
    vault_client = hvac.Client(verify=False, namespace=vault_namespace, token=token, url=vault_address)
    read_response = vault_client.secrets.kv.read_secret_version(path=path)  # path should reflect the path to your secrets
    return read_response
