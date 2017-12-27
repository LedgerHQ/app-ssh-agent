# blue-app-ssh-agent

A simple PGP and SSH agent for Ledger Blue, supporting prime256v1 and ed25519 keys.

This agent is compatible with the third party SSH/PGP host client from Roman Zeyde available at https://github.com/romanz/trezor-agent - it is recommended to use it for extra functionalities

## Installation

You'll need [`pipenv`](https://docs.pipenv.org) and Python 2.

Clone this repo somewhere, then run the following inside it:

    pipenv install

This will automatically create a Python 2 "virtualenv" with the Ledger Blue Python libraries this software depends on.

## Usage

Run getPublicKey.py to get the public key in SSH format, to be added to your authorized keys on the target

```
pipenv run python getPublicKey.py
ecdsa-sha2-nistp256 AAAA....
```

Run agent.py, providing the base64 encoded key retrieved earlier 

```
pipenv run python agent.py --key AAAA....
```

Export the environment variables in your shell to use it

You can also set the derivation path from the master seed by providing it with the --path parameter.

