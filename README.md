# app-ssh-agent

## ⚠️ DEPRECATION WARNING

> **This application is no longer maintained and will be deprecated.**
>
> Please migrate to one of the following alternatives:
>
> - **[app-openpgp](https://github.com/LedgerHQ/app-openpgp)** - OpenPGP application for Ledger devices
>   - Check [ssh support](https://github.com/LedgerHQ/app-openpgp/blob/develop/doc/user/app-openpgp.rst#ssh)
> - **[app-security-key](https://github.com/LedgerHQ/app-security-key)** - FIDO2/U2F security key application
>   - Check [Web authn support](https://www.ledger.com/blog/strengthen-the-security-of-your-accounts-with-webauthn)
>
> No further updates or support will be provided for app-ssh-agent.

### Ledger SSH Methods Comparison

| Feature                            | **app-openpgp** (The "Smart Card" Way)                                                   | **app-security-key** (The "Modern" Way)                                                        |
| :--------------------------------- | :--------------------------------------------------------------------------------------- | :--------------------------------------------------------------------------------------------- |
| **Protocol**                       | **OpenPGP Card** (ISO 7816)                                                              | **FIDO2 / WebAuthn** (CTAP2)                                                                   |
| **Integration**                    | **Bridge:** Uses `gpg-agent` as a translator between SSH and the device.                 | **Native:** Built directly into OpenSSH (v8.2+) via the `-sk` extension.                       |
| **Complexity**                     | **Configuration Required:** Involves setting up the GPG agent and environment variables. | **Minimal:** Standard `ssh-keygen` command. No extra software needed.                          |
| **Algorithms**                     | **RSA** (up to 4096), Ed25519, SECP256K1, SECP256R1 (NIST P-256).                        | **Ed25519**, NIST P-256. (**NO RSA**).                                                         |
| **Compatibility**                  | **Universal:** Works with almost any SSH server (legacy & modern).                       | **Modern:** Client requires OpenSSH 8.2+. Server requires recent OpenSSH.                      |
| **Key Storage**                    | **Stateful:** Private keys are stored permanently in the Ledger's NVRAM.                 | **Stateless / Hybrid:** "Key Handle" file stored on PC; Secret derived on Ledger during login. |
| **Agent Used**                     | `gpg-agent` (impersonating `ssh-agent`).                                                 | Standard `ssh-agent`.                                                                          |
| **Touch Policy**                   | **Flexible:** Can be cached for a session (if configured).                               | **Mandatory:** Requires a physical touch for every login attempt.                              |
| **Migration from `app-ssh-agent`** | **Not Possible:** Protocol mismatch. You must generate new keys.                         | **Not Possible:** Protocol mismatch. You must generate new keys.                               |

## App overview

A simple PGP and SSH agent for Ledger Blue, supporting prime256v1 and ed25519 keys.

This agent is compatible with the third party SSH/PGP host client from Roman Zeyde available at [trezor](https://github.com/romanz/trezor-agent).
It is recommended to use it for extra functionalities.

You can also use the SSH functionalities with the following instructions using Python.

Run `getPublicKey.py` to get the public key in SSH format, to be added to your authorized keys on the target

```bash
python getPublicKey.py
ecdsa-sha2-nistp256 AAAA....
```

Run `agent.py`, providing the base64 encoded key retrieved earlier

```bash
python agent.py --key AAAA....
```

Export the environment variables in your shell to use it

You can also set the derivation path from the master seed by providing it with the `--path` parameter.
