import os
import hvac


def hashi_vault(token, path):
    """Hashi Vault function.

    Args:
        token (str):  User token from the Vault UI.
        path (str): Path should reflect the path to your secrets.

    Returns:
        _type_: _description_
    """
    token = os.environ.get("HASHI_TOKEN")
    vault_namespace = "network/net-sane"
    vault_address = "https://vault-enterprise.onefiserv.net"
    vault_client = hvac.Client(verify=False, namespace=vault_namespace, token=token, url=vault_address)
    read_response = vault_client.secrets.kv.read_secret_version(path=path)
    return read_response
