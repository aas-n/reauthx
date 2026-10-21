#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""patchcheck.py - SCAN: locate a target across the patch chain and recommend the exploit mode.

Read-only by default (reads the UBR via RemoteRegistry; a low-privilege account is enough - same method
as nxc). With --probe (a DIFFERENT second account), it also tests patch #4 (cross-user re-auth).

Examples:
  patchcheck.py AD.LOCAL/bob:Pass1@10.0.0.5                       # passive scan (1 account)
  patchcheck.py AD.LOCAL/bob:Pass1@10.0.0.5 --probe alice:Pass2   # + test #4 (2nd DIFFERENT account)

The checks: #1 CVE-2025-33073 . #2 CVE-2025-58726 . #4 same-user re-auth (Sep 2026). #1/#2 are inferred
from the UBR (MSRC tables); #4 is a feature flag, not readable from the UBR -> tested only via --probe.
The Mar-2026 loopback-signing fix (24294/26128) is deliberately not checked here: it never changes the
RCE verdict, and build 26100 spans two UBR trains (client 24H2 vs Server 2025) that one threshold cannot
tell apart. The re-auth bypass is used regardless, so lean on --probe.
"""
import argparse
import binascii
import os
import socket
import sys

from impacket.smbconnection import SMBConnection, SessionError
from impacket.dcerpc.v5 import transport, rrp
from impacket.smb3structs import SMB2_SESSION_SETUP, SMB2_DIALECT_30, SMB2_NEGOTIATE_SIGNING_REQUIRED
from impacket.smb3 import SMB2SessionSetup, SMB2SessionSetup_Response
from impacket.spnego import SPNEGO_NegTokenInit, SPNEGO_NegTokenResp, TypesMech
from impacket import ntlm

# Minimum fixed UBR per (major, minor, build): UBR >= value => patched. One UBR (GA) per build, like
# nxc enum_cve. Tables pulled from the MSRC CVRF API. (Limitation shared with nxc: a host on a non-GA
# servicing branch - LTSC/hotpatch/Azure - may be misclassified; see msrc_fetch.py.)
P1_33073 = {
    (10, 0, 10240): 21034, (10, 0, 14393): 8148, (10, 0, 17763): 7434, (10, 0, 19044): 5965,
    (10, 0, 20348): 3807, (10, 0, 22621): 5472, (10, 0, 25398): 1665, (10, 0, 26100): 4270,
}
P2_58726 = {
    (6, 0, 6003): 23571, (6, 1, 7601): 27974, (6, 2, 9200): 25722, (6, 3, 9600): 22824,
    (10, 0, 10240): 21161, (10, 0, 14393): 8519, (10, 0, 17763): 7919, (10, 0, 19044): 6456,
    (10, 0, 20348): 4294, (10, 0, 22621): 6060, (10, 0, 25398): 1913, (10, 0, 26100): 6899,
    (10, 0, 26200): 6899,
}
P4_REAUTH = {}   # same-user re-auth (Sep 2026) - feature flag, no reliable UBR -> --probe

PATCHES = [
    ("#1", "CVE-2025-33073 (client mrxsmb)", P1_33073),
    ("#2", "CVE-2025-58726 (loopback-IP / GhostSPN)", P2_58726),
    ("#4", "same-user re-auth (Sep2026, flag)", P4_REAUTH),
]

STATUS = {0x00000000: "STATUS_SUCCESS", 0xC0000016: "MORE_PROCESSING_REQUIRED",
          0xC000006D: "LOGON_FAILURE", 0xC000000D: "INVALID_PARAMETER", 0xC0000022: "ACCESS_DENIED"}


def sname(st):
    return STATUS.get(st, f"0x{st:08X}")


# ---- output helpers (colour only on a TTY; honour NO_COLOR) ----
_COLOR = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None


def col(code, s):
    return f"\033[{code}m{s}\033[0m" if (_COLOR and s) else s


# short, aligned label per patch for the table
LABEL = {
    "#1": "CVE-2025-33073         client reflection (CMTI)",
    "#2": "CVE-2025-58726         loopback source-IP (GhostSPN)",
    "#4": "same-user re-auth      (Sep 2026, feature flag)",
}
_STAT = {"MISSING": ("32", "absent"), "PATCHED": ("2", "patched"), "UNKNOWN": ("33", "unknown")}
_IMPACT = {"RCE": "1;32", "LPE": "1;33", "CLOSED": "1;31", "?": "33"}


def fmt_status(stat):
    code, word = _STAT.get(stat, ("33", stat.lower()))
    return col(code, word)


def fmt_impact(impact):
    return col(_IMPACT.get(impact, "33"), impact)


def state(table, key, ubr):
    fix = table.get(key)
    if fix is None:
        return "UNKNOWN"
    return "PATCHED" if ubr >= fix else "MISSING"


def trigger_winreg(smb):
    """Trigger-start RemoteRegistry WITHOUT admin (opens \\winreg on IPC$)."""
    import time
    try:
        tid = smb.connectTree("IPC$")
        try:
            smb.openFile(tid, r"\winreg", 0x12019F, creationOption=0x40, fileAttributes=0x80)
        except SessionError as e:
            if "STATUS_PIPE_NOT_AVAILABLE" not in str(e):
                raise
    except Exception:
        pass
    time.sleep(1)


def read_ubr(smb):
    rpc = transport.DCERPCTransportFactory(r"ncacn_np:445[\pipe\winreg]")
    rpc.set_smb_connection(smb)
    dce = rpc.get_dce_rpc()
    dce.connect()
    dce.bind(rrp.MSRPC_UUID_RRP)
    hroot = rrp.hOpenLocalMachine(dce)["phKey"]
    hkey = rrp.hBaseRegOpenKey(dce, hroot, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion")["phkResult"]
    ubr = rrp.hBaseRegQueryValue(dce, hkey, "UBR")[1]
    dce.disconnect()
    return ubr


def signing_required(smb):
    """Whether the server REQUIRES SMB signing (not merely enables it).

    impacket force-sets RequireSigning=True for any SMB 3.1.1 negotiation, so
    isSigningRequired() is a false positive on 3.x hosts that only enable (but
    do not require) signing. For SMB 3.0+ read the real negotiated
    ServerSecurityMode instead (the fix nxc uses); fall back to
    isSigningRequired() for SMBv1 / SMB 2.0.2 / 2.1.
    """
    try:
        conn = smb._SMBConnection._Connection
        if conn["Dialect"] >= SMB2_DIALECT_30:
            return bool(conn["ServerSecurityMode"] & SMB2_NEGOTIATE_SIGNING_REQUIRED)
    except Exception:
        pass
    return smb.isSigningRequired()


# ---- #4 test: cross-user re-auth (adapted from test_A_reauth_swap.py) ----
def reauth_as(smb, user, password, domain, nthash):
    """NTLM re-auth (Type1/Type3) as `user` on the SAME session. Returns the NTSTATUS."""
    t1 = ntlm.getNTLMSSPType1("", domain)
    blob = SPNEGO_NegTokenInit()
    blob["MechTypes"] = [TypesMech["NTLMSSP - Microsoft NTLM Security Support Provider"]]
    blob["MechToken"] = t1.getData()
    ss = SMB2SessionSetup()
    ss["Flags"] = 0
    ss["SecurityMode"] = 1
    ss["SecurityBufferLength"] = len(blob.getData())
    ss["Buffer"] = blob.getData()
    pkt = smb.SMB_PACKET()
    pkt["Command"] = SMB2_SESSION_SETUP
    pkt["Data"] = ss
    ans = smb.recvSMB(smb.sendSMB(pkt))
    if ans["Status"] != 0xC0000016:
        return ans["Status"]
    resp = SMB2SessionSetup_Response(ans["Data"])
    try:
        t2 = SPNEGO_NegTokenResp(resp["Buffer"])["ResponseToken"]
    except Exception:
        raw = resp["Buffer"]
        t2 = raw[raw.index(b"NTLMSSP"):]
    lm = nt = ""
    if nthash:
        lm, nt = binascii.unhexlify("aad3b435b51404eeaad3b435b51404ee"), binascii.unhexlify(nthash)
    type3, _ = ntlm.getNTLMSSPType3(t1, t2, user, password, domain, lmhash=lm, nthash=nt)
    blob2 = SPNEGO_NegTokenResp()
    blob2["ResponseToken"] = type3.getData()
    ss2 = SMB2SessionSetup()
    ss2["Flags"] = 0
    ss2["SecurityMode"] = 1
    ss2["SecurityBufferLength"] = len(blob2.getData())
    ss2["Buffer"] = blob2.getData()
    pkt2 = smb.SMB_PACKET()
    pkt2["Command"] = SMB2_SESSION_SETUP
    pkt2["Data"] = ss2
    ans2 = smb.recvSMB(smb.sendSMB(pkt2))
    return ans2["Status"]


def probe_reauth(target, domain, ua, pa, nta, ub, pb, ntb):
    conn = SMBConnection(target, target, preferredDialect=0x0311)
    conn.login(ua, pa, domain, lmhash="", nthash=(nta or ""))
    try:
        return reauth_as(conn.getSMBServer(), ub, pb, domain, ntb)
    finally:
        try:
            conn.close()
        except Exception:
            pass


def recommend(st, signing_required, is_dc):
    sign_default = ("re-auth signing bypass required" if signing_required
                    else "bypass only if the connection enforces signing")
    dc_hint = ("self-reflection validated against a DC with BOTH cmti and unicode names (the DC "
               "resolves the coercion name via its own DNS); --reauth-bypass required (DC enforces signing)"
               if is_dc else None)

    def pack(label, impact, coercion, relay, signing=None, note=None):
        hints = [("coercion", coercion), ("relay", relay), ("signing", signing or sign_default)]
        if note:
            hints.append(("note", note))
        if dc_hint:
            hints.append(("DC", dc_hint))
        return label, impact, hints

    if st["#1"] == "MISSING":
        return pack("fully unpatched (pre-33073)", "RCE", "CMTI or Unicode", "remote")
    if st["#2"] == "MISSING":
        return pack("33073 patched, 58726 absent", "RCE", "Unicode (CMTI dead)", "remote")
    # #1 and #2 patched from here: RCE is gone, the signing bypass is what keeps a relay alive.
    if st["#4"] == "MISSING":
        return pack("33073+58726 patched, same-user re-auth absent", "LPE",
                    "Unicode", "local forwarder (58726)",
                    signing="re-auth signing bypass required")
    if st["#4"] == "UNKNOWN":
        return pack("likely still open (#4 unconfirmed)", "LPE",
                    "Unicode", "local forwarder (58726)",
                    signing="re-auth signing bypass required",
                    note="re-run with --probe (2nd account) to confirm #4")
    if st["#4"] == "PATCHED":
        return ("chain closed (Sep-2026 same-user re-auth present)", "CLOSED",
                [("reason", "the same-user check blocks the identity swap")])
    return ("undetermined (#4 not confirmed for this build)", "?",
            [("hint", "use --probe")])


def parse_identity(ident):
    creds, target = ident.rsplit("@", 1)
    dom_user, _, password = creds.partition(":")
    domain, _, username = dom_user.partition("/")
    if not username:
        domain, username = "", domain
    return domain, username, password, target


def is_dc(target, timeout=3):
    """Heuristic: a DC listens on LDAP (389)."""
    try:
        socket.create_connection((target, 389), timeout=timeout).close()
        return True
    except Exception:
        return False


def main():
    ap = argparse.ArgumentParser(
        description="reflect_relay - SCAN: locate the target across the patch chain (UBR) + recommend the exploit mode.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  %(prog)s AD.LOCAL/bob:Pass1@10.0.0.5                       # passive scan (1 account)\n"
            "  %(prog)s AD.LOCAL/bob:Pass1@10.0.0.5 --probe alice:Pass2   # + test #4\n\n"
            "--probe (test patch #4): supply a SECOND credential pair, which MUST be a DIFFERENT account\n"
            "from the primary one. Privilege level does NOT matter (two low-priv accounts are fine).\n"
            "Same-user re-auth is always allowed, so reusing the primary account would test NOTHING.\n"
            "Without --probe: passive scan, #4 = UNKNOWN."
        ),
    )
    ap.add_argument("identity", help="PRIMARY account: DOMAIN/USER:PASS@TARGET")
    ap.add_argument("--probe", metavar="USER2:PASS2", default=None,
                    help="enable the #4 test with a 2nd account DIFFERENT from the primary (privilege irrelevant)")
    adv = ap.add_argument_group("advanced auth (optional)")
    adv.add_argument("-H", "--hashes", default=None, metavar="LM:NT", help="NTLM hashes of the primary account")
    adv.add_argument("-k", action="store_true", help="Kerberos via ccache (KRB5CCNAME)")
    adv.add_argument("--dc-ip", default=None, metavar="IP", help="KDC IP (required with -k)")
    a = ap.parse_args()

    try:
        domain, username, password, target = parse_identity(a.identity)
    except ValueError:
        sys.exit("[-] expected format: DOMAIN/USER:PASS@TARGET")

    # --- up-front check: the two accounts must differ (otherwise the #4 test is meaningless) ---
    probe_user = probe_pass = None
    if a.probe:
        probe_user, _, probe_pass = a.probe.partition(":")
        if probe_user.lower() == username.lower():
            sys.exit(
                "[-] --probe account must be DIFFERENT from the primary account "
                f"(both are '{username}').\n"
                "    Patch #4 only blocks CROSS-user re-auth; same-user re-auth is always allowed,\n"
                "    so reusing the primary account would test nothing. Use any second account\n"
                "    (privilege level does not matter)."
            )

    lm = nt = ""
    if a.hashes:
        lm, _, nt = a.hashes.partition(":")

    smb = SMBConnection(target, target)
    try:
        if a.k:
            smb.kerberosLogin(username, password, domain, lm, nt, kdcHost=a.dc_ip)
        else:
            smb.login(username, password, domain, lm, nt)
    except Exception as e:
        sys.exit(f"[-] login failed: {e}")

    major, minor, build = smb.getServerOSMajor(), smb.getServerOSMinor(), smb.getServerOSBuild()
    signing = signing_required(smb)
    name = smb.getServerName()
    key = (major, minor, build)
    dc = is_dc(target)

    trigger_winreg(smb)
    ubr = None
    try:
        ubr = read_ubr(smb)
    except Exception:
        pass
    try:
        smb.close()
    except Exception:
        pass

    order = [tag for tag, _, _ in PATCHES]
    st = {tag: (state(table, key, ubr) if ubr else "UNKNOWN") for tag, _, table in PATCHES}

    # Cumulative rule: patches ship in order, so a later one can't be present if an earlier one is
    # absent (and vice-versa). Fill UNKNOWNs by inference and flag them with '*'.
    inferred = set()
    seen_missing = False
    for tag in order:
        if st[tag] == "MISSING":
            seen_missing = True
        elif st[tag] == "UNKNOWN" and seen_missing:
            st[tag] = "MISSING"; inferred.add(tag)
    seen_patched = False
    for tag in reversed(order):
        if st[tag] == "PATCHED":
            seen_patched = True
        elif st[tag] == "UNKNOWN" and seen_patched:
            st[tag] = "PATCHED"; inferred.add(tag)

    build_s = f"{major}.{minor}.{build}." + (str(ubr) if ubr else "?")
    print()
    print("[*] " + "   ".join([
        col("1", f"{target}:445"),
        col("1", name or "?"),
        "build " + build_s,
        "signing:" + str(signing),
        "role:" + (col("36", "DC") if dc else "member"),
    ]))
    if not ubr:
        print("    " + col("33", "UBR unreadable (valid account needed, non-admin is enough); patch state is inference-only"))

    if a.probe:
        try:
            code = probe_reauth(target, domain, username, password, nt, probe_user, probe_pass, "")
            res = {0x00000000: "MISSING", 0xC0000022: "PATCHED"}.get(code)
            if res:
                st["#4"] = res
                inferred.discard("#4")   # actively tested -> no longer inferred
            print(f"    probe #4  {username} -> {probe_user}   {sname(code)}")
        except Exception as e:
            print(f"    probe #4  failed: {e}")

    print()
    width = max(len(LABEL[t]) for t in order)
    for tag in order:
        star = col("2", "*") if tag in inferred else ""
        print(f"    {col('1', tag)}  {LABEL[tag].ljust(width)}   {fmt_status(st[tag])}{star}")
    if inferred:
        print("    " + col("2", "* inferred: a later patch cannot be present if an earlier one is absent"))

    label, impact, hints = recommend(st, signing, dc)
    print()
    print(f"[+] {fmt_impact(impact)}   {label}")
    kw = max((len(k) for k, _ in hints), default=0)
    for k, v in hints:
        print(f"    {col('2', k.ljust(kw))}   {v}")
    print()


if __name__ == "__main__":
    main()
