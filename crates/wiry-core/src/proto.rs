use crate::field::{self, FieldDesc, FieldKind};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::OnceLock;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[repr(transparent)]
pub struct ProtoId(pub u16);

/// Built-in ids are the first `BUILTIN_COUNT` values and never move: the
/// numbering separates the static table from the registry.
#[allow(non_upper_case_globals)]
impl ProtoId {
    pub const Raw: ProtoId = ProtoId(0);
    pub const Padding: ProtoId = ProtoId(1);
    pub const Ether: ProtoId = ProtoId(2);
    pub const Dot1Q: ProtoId = ProtoId(3);
    pub const Arp: ProtoId = ProtoId(4);
    pub const Ipv4: ProtoId = ProtoId(5);
    pub const Ipv6: ProtoId = ProtoId(6);
    pub const Tcp: ProtoId = ProtoId(7);
    pub const Udp: ProtoId = ProtoId(8);
    pub const Icmp: ProtoId = ProtoId(9);
    pub const Icmpv6: ProtoId = ProtoId(10);
    pub const Dns: ProtoId = ProtoId(11);
    pub const Bootp: ProtoId = ProtoId(12);
    pub const Dhcp: ProtoId = ProtoId(13);
    pub const Null: ProtoId = ProtoId(14);
    pub const LinuxSll: ProtoId = ProtoId(15);
    pub const LinuxSll2: ProtoId = ProtoId(16);
    pub const HopByHop: ProtoId = ProtoId(17);
    pub const Routing: ProtoId = ProtoId(18);
    pub const Fragment: ProtoId = ProtoId(19);
    pub const DestOpt: ProtoId = ProtoId(20);
    pub const Gre: ProtoId = ProtoId(21);
    pub const Vxlan: ProtoId = ProtoId(22);
    pub const Geneve: ProtoId = ProtoId(23);
    pub const Mpls: ProtoId = ProtoId(24);
    pub const PppoeDisc: ProtoId = ProtoId(25);
    pub const Pppoe: ProtoId = ProtoId(26);
    pub const Ppp: ProtoId = ProtoId(27);
    pub const GtpU: ProtoId = ProtoId(28);
    pub const ErspanII: ProtoId = ProtoId(29);
    pub const ErspanIII: ProtoId = ProtoId(30);
    // protogen:ids begin
    pub const Llc: ProtoId = ProtoId(32);
    pub const Snap: ProtoId = ProtoId(33);
    pub const Stp: ProtoId = ProtoId(34);
    pub const Lldp: ProtoId = ProtoId(35);
    pub const Cdp: ProtoId = ProtoId(36);
    pub const RadioTap: ProtoId = ProtoId(37);
    pub const Dot11: ProtoId = ProtoId(38);
    pub const Dot11Beacon: ProtoId = ProtoId(39);
    pub const Dot11ProbeReq: ProtoId = ProtoId(40);
    pub const Dot11ProbeResp: ProtoId = ProtoId(41);
    pub const Dot11Auth: ProtoId = ProtoId(42);
    pub const Dot11AssoReq: ProtoId = ProtoId(43);
    pub const Dot11AssoResp: ProtoId = ProtoId(44);
    pub const Sctp: ProtoId = ProtoId(45);
    pub const Igmp: ProtoId = ProtoId(46);
    pub const Icmpv6NdRs: ProtoId = ProtoId(48);
    pub const Icmpv6NdRa: ProtoId = ProtoId(49);
    pub const Icmpv6NdNs: ProtoId = ProtoId(50);
    pub const Icmpv6NdNa: ProtoId = ProtoId(51);
    pub const Icmpv6NdRedirect: ProtoId = ProtoId(52);
    pub const Icmpv6MlQuery: ProtoId = ProtoId(53);
    pub const Icmpv6MlReport: ProtoId = ProtoId(54);
    pub const Icmpv6MlDone: ProtoId = ProtoId(55);
    pub const Icmpv6MlReport2: ProtoId = ProtoId(56);
    pub const Esp: ProtoId = ProtoId(57);
    pub const Ah: ProtoId = ProtoId(58);
    pub const Ospf: ProtoId = ProtoId(59);
    pub const Rip: ProtoId = ProtoId(60);
    pub const Bgp: ProtoId = ProtoId(61);
    pub const Vrrp: ProtoId = ProtoId(62);
    pub const Hsrp: ProtoId = ProtoId(63);
    pub const Bfd: ProtoId = ProtoId(64);
    pub const Ntp: ProtoId = ProtoId(65);
    pub const Dhcp6: ProtoId = ProtoId(66);
    pub const Snmp: ProtoId = ProtoId(67);
    pub const Tftp: ProtoId = ProtoId(68);
    pub const Syslog: ProtoId = ProtoId(69);
    pub const Nbns: ProtoId = ProtoId(70);
    pub const NbtSession: ProtoId = ProtoId(71);
    pub const Radius: ProtoId = ProtoId(72);
    pub const Rtp: ProtoId = ProtoId(73);
    pub const Rtcp: ProtoId = ProtoId(74);
    pub const NetflowV5: ProtoId = ProtoId(75);
    pub const NetflowV9: ProtoId = ProtoId(76);
    pub const Ipfix: ProtoId = ProtoId(77);
    pub const SFlow: ProtoId = ProtoId(78);
    pub const Quic: ProtoId = ProtoId(79);
    pub const WireGuard: ProtoId = ProtoId(80);
    pub const Tls: ProtoId = ProtoId(81);
    pub const Http: ProtoId = ProtoId(82);
    pub const Ssh: ProtoId = ProtoId(83);
    pub const Mqtt: ProtoId = ProtoId(84);
    pub const Modbus: ProtoId = ProtoId(85);
    pub const Smb2: ProtoId = ProtoId(86);
    pub const Ldap: ProtoId = ProtoId(87);
    pub const Sip: ProtoId = ProtoId(88);
    pub const Ftp: ProtoId = ProtoId(89);
    pub const Smtp: ProtoId = ProtoId(90);
    pub const Imap: ProtoId = ProtoId(91);
    pub const Telnet: ProtoId = ProtoId(92);
    pub const OspfHello: ProtoId = ProtoId(93);
    pub const OspfDbDesc: ProtoId = ProtoId(94);
    pub const OspfLsReq: ProtoId = ProtoId(95);
    pub const OspfLsUpd: ProtoId = ProtoId(96);
    pub const OspfLsAck: ProtoId = ProtoId(97);
    pub const BgpOpen: ProtoId = ProtoId(98);
    pub const BgpUpdate: ProtoId = ProtoId(99);
    pub const BgpNotification: ProtoId = ProtoId(100);
    pub const BgpRouteRefresh: ProtoId = ProtoId(101);
    pub const NTPSystemStatusPacket: ProtoId = ProtoId(1005);
    pub const NTPPeerStatusPacket: ProtoId = ProtoId(1006);
    pub const NTPClockStatusPacket: ProtoId = ProtoId(1007);
    pub const NTPErrorStatusPacket: ProtoId = ProtoId(1008);
    pub const NTPInfoPeerList: ProtoId = ProtoId(1011);
    pub const NTPInfoPeerStats: ProtoId = ProtoId(1014);
    pub const NTPInfoSysStats: ProtoId = ProtoId(1017);
    pub const NTPInfoIOStats: ProtoId = ProtoId(1019);
    pub const NTPInfoTimerStats: ProtoId = ProtoId(1020);
    pub const NTPConfPeer: ProtoId = ProtoId(1021);
    pub const NTPConfUnpeer: ProtoId = ProtoId(1022);
    pub const NTPConfRestrict: ProtoId = ProtoId(1023);
    pub const NTPInfoKernel: ProtoId = ProtoId(1024);
    pub const NTPInfoIfStatsIPv4: ProtoId = ProtoId(1025);
    pub const NTPInfoIfStatsIPv6: ProtoId = ProtoId(1026);
    pub const NTPInfoMonitor1: ProtoId = ProtoId(1027);
    pub const NTPInfoAuth: ProtoId = ProtoId(1028);
    pub const NTPConfTrap: ProtoId = ProtoId(1029);
    pub const NTPInfoControl: ProtoId = ProtoId(1030);
    pub const NTPPrivateReqPacket: ProtoId = ProtoId(1031);
    pub const PPPoETag: ProtoId = ProtoId(1102);
    pub const PPPoEDTags: ProtoId = ProtoId(1103);
    pub const HDLC: ProtoId = ProtoId(1104);
    pub const DIRPPP: ProtoId = ProtoId(1105);
    pub const PPPECPOptionOUI: ProtoId = ProtoId(1115);
    pub const PPPLCPMRUOption: ProtoId = ProtoId(1119);
    pub const PPPLCPACCMOption: ProtoId = ProtoId(1120);
    pub const PPPLCPQualityProtocolOption: ProtoId = ProtoId(1122);
    pub const PPPLCPMagicNumberOption: ProtoId = ProtoId(1123);
    pub const PPPLCPCallbackOption: ProtoId = ProtoId(1124);
    pub const PPPLCPTerminate: ProtoId = ProtoId(1126);
    pub const PPPLCPDiscardRequest: ProtoId = ProtoId(1129);
    pub const PPPLCPEcho: ProtoId = ProtoId(1130);
    pub const HCIPHDRHdr: ProtoId = ProtoId(5000);
    pub const HCIHdr: ProtoId = ProtoId(5001);
    pub const HCIACLHdr: ProtoId = ProtoId(5002);
    pub const L2CAPHdr: ProtoId = ProtoId(5003);
    pub const L2CAPCmdHdr: ProtoId = ProtoId(5004);
    pub const L2CAPConnReq: ProtoId = ProtoId(5005);
    pub const L2CAPConnResp: ProtoId = ProtoId(5006);
    pub const L2CAPCmdRej: ProtoId = ProtoId(5007);
    pub const L2CAPConfReq: ProtoId = ProtoId(5008);
    pub const L2CAPConfResp: ProtoId = ProtoId(5009);
    pub const L2CAPDisconnReq: ProtoId = ProtoId(5010);
    pub const L2CAPDisconnResp: ProtoId = ProtoId(5011);
    pub const L2CAPEchoReq: ProtoId = ProtoId(5012);
    pub const L2CAPEchoResp: ProtoId = ProtoId(5013);
    pub const L2CAPInfoReq: ProtoId = ProtoId(5014);
    pub const L2CAPInfoResp: ProtoId = ProtoId(5015);
    pub const L2CAPCreateChannelRequest: ProtoId = ProtoId(5016);
    pub const L2CAPCreateChannelResponse: ProtoId = ProtoId(5017);
    pub const L2CAPMoveChannelRequest: ProtoId = ProtoId(5018);
    pub const L2CAPMoveChannelResponse: ProtoId = ProtoId(5019);
    pub const L2CAPMoveChannelConfirmationRequest: ProtoId = ProtoId(5020);
    pub const L2CAPMoveChannelConfirmationResponse: ProtoId = ProtoId(5021);
    pub const L2CAPConnectionParameterUpdateRequest: ProtoId = ProtoId(5022);
    pub const L2CAPConnectionParameterUpdateResponse: ProtoId = ProtoId(5023);
    pub const L2CAPLECreditBasedConnectionRequest: ProtoId = ProtoId(5024);
    pub const L2CAPLECreditBasedConnectionResponse: ProtoId = ProtoId(5025);
    pub const L2CAPFlowControlCreditInd: ProtoId = ProtoId(5026);
    pub const L2CAPCreditBasedConnectionRequest: ProtoId = ProtoId(5027);
    pub const L2CAPCreditBasedConnectionResponse: ProtoId = ProtoId(5028);
    pub const L2CAPCreditBasedReconfigureRequest: ProtoId = ProtoId(5029);
    pub const L2CAPCreditBasedReconfigureResponse: ProtoId = ProtoId(5030);
    pub const ATTHdr: ProtoId = ProtoId(5031);
    pub const ATTHandle: ProtoId = ProtoId(5032);
    pub const ATTErrorResponse: ProtoId = ProtoId(5034);
    pub const ATTExchangeMTURequest: ProtoId = ProtoId(5035);
    pub const ATTExchangeMTUResponse: ProtoId = ProtoId(5036);
    pub const ATTFindInformationRequest: ProtoId = ProtoId(5037);
    pub const ATTFindByTypeValueRequest: ProtoId = ProtoId(5039);
    pub const ATTFindByTypeValueResponse: ProtoId = ProtoId(5040);
    pub const ATTReadByTypeRequest: ProtoId = ProtoId(5042);
    pub const ATTReadRequest: ProtoId = ProtoId(5045);
    pub const ATTReadResponse: ProtoId = ProtoId(5046);
    pub const ATTReadMultipleRequest: ProtoId = ProtoId(5047);
    pub const ATTReadMultipleResponse: ProtoId = ProtoId(5048);
    pub const ATTReadByGroupTypeRequest: ProtoId = ProtoId(5049);
    pub const ATTWriteRequest: ProtoId = ProtoId(5052);
    pub const ATTWriteCommand: ProtoId = ProtoId(5053);
    pub const ATTWriteResponse: ProtoId = ProtoId(5054);
    pub const ATTPrepareWriteRequest: ProtoId = ProtoId(5055);
    pub const ATTPrepareWriteResponse: ProtoId = ProtoId(5056);
    pub const ATTHandleValueNotification: ProtoId = ProtoId(5057);
    pub const ATTExecuteWriteRequest: ProtoId = ProtoId(5058);
    pub const ATTExecuteWriteResponse: ProtoId = ProtoId(5059);
    pub const ATTReadMultipleVariableRequest: ProtoId = ProtoId(5060);
    pub const ATTLengthValueTuple: ProtoId = ProtoId(5061);
    pub const ATTHandleLengthValueTuple: ProtoId = ProtoId(5063);
    pub const ATTReadBlobRequest: ProtoId = ProtoId(5065);
    pub const ATTReadBlobResponse: ProtoId = ProtoId(5066);
    pub const ATTHandleValueIndication: ProtoId = ProtoId(5067);
    pub const ATTHandleValueConfirmation: ProtoId = ProtoId(5068);
    pub const SMHdr: ProtoId = ProtoId(5070);
    pub const SMPairingRequest: ProtoId = ProtoId(5071);
    pub const SMPairingResponse: ProtoId = ProtoId(5072);
    pub const SMConfirm: ProtoId = ProtoId(5073);
    pub const SMRandom: ProtoId = ProtoId(5074);
    pub const SMFailed: ProtoId = ProtoId(5075);
    pub const SMEncryptionInformation: ProtoId = ProtoId(5076);
    pub const SMMasterIdentification: ProtoId = ProtoId(5077);
    pub const SMIdentityInformation: ProtoId = ProtoId(5078);
    pub const SMIdentityAddressInformation: ProtoId = ProtoId(5079);
    pub const SMSigningInformation: ProtoId = ProtoId(5080);
    pub const SMSecurityRequest: ProtoId = ProtoId(5081);
    pub const SMPublicKey: ProtoId = ProtoId(5082);
    pub const SMDHKeyCheck: ProtoId = ProtoId(5083);
    pub const SMKeypressNotification: ProtoId = ProtoId(5084);
    pub const EIRFlags: ProtoId = ProtoId(5088);
    pub const EIRClassOfDevice: ProtoId = ProtoId(5098);
    pub const EIRSecurityManagerOOBFlags: ProtoId = ProtoId(5101);
    pub const EIRPeripheralConnectionIntervalRange: ProtoId = ProtoId(5102);
    pub const EIRDeviceID: ProtoId = ProtoId(5104);
    pub const EIRPublicTargetAddress: ProtoId = ProtoId(5108);
    pub const EIRRandomTargetAddress: ProtoId = ProtoId(5109);
    pub const EIRLEBluetoothDeviceAddress: ProtoId = ProtoId(5111);
    pub const EIRLERole: ProtoId = ProtoId(5112);
    pub const EIR3DInformation: ProtoId = ProtoId(5114);
    pub const EIRAppearance: ProtoId = ProtoId(5115);
    pub const HCICommandHdr: ProtoId = ProtoId(5119);
    pub const HCICmdInquiry: ProtoId = ProtoId(5121);
    pub const HCICmdInquiryCancel: ProtoId = ProtoId(5122);
    pub const HCICmdPeriodicInquiryMode: ProtoId = ProtoId(5123);
    pub const HCICmdExitPeiodicInquiryMode: ProtoId = ProtoId(5124);
    pub const HCICmdCreateConnection: ProtoId = ProtoId(5125);
    pub const HCICmdDisconnect: ProtoId = ProtoId(5126);
    pub const HCICmdCreateConnectionCancel: ProtoId = ProtoId(5127);
    pub const HCICmdAcceptConnectionRequest: ProtoId = ProtoId(5128);
    pub const HCICmdRejectConnectionResponse: ProtoId = ProtoId(5129);
    pub const HCICmdLinkKeyRequestNegativeReply: ProtoId = ProtoId(5131);
    pub const HCICmdPINCodeRequestNegativeReply: ProtoId = ProtoId(5133);
    pub const HCICmdChangeConnectionPacketType: ProtoId = ProtoId(5134);
    pub const HCICmdAuthenticationRequested: ProtoId = ProtoId(5135);
    pub const HCICmdSetConnectionEncryption: ProtoId = ProtoId(5136);
    pub const HCICmdChangeConnectionLinkKey: ProtoId = ProtoId(5137);
    pub const HCICmdLinkKeySelection: ProtoId = ProtoId(5138);
    pub const HCICmdRemoteNameRequest: ProtoId = ProtoId(5139);
    pub const HCICmdRemoteNameRequestCancel: ProtoId = ProtoId(5140);
    pub const HCICmdReadRemoteSupportedFeatures: ProtoId = ProtoId(5141);
    pub const HCICmdReadRemoteExtendedFeatures: ProtoId = ProtoId(5142);
    pub const HCICmdIOCapabilityRequestReply: ProtoId = ProtoId(5143);
    pub const HCICmdUserConfirmationRequestReply: ProtoId = ProtoId(5144);
    pub const HCICmdUserConfirmationRequestNegativeReply: ProtoId = ProtoId(5145);
    pub const HCICmdUserPasskeyRequestReply: ProtoId = ProtoId(5146);
    pub const HCICmdUserPasskeyRequestNegativeReply: ProtoId = ProtoId(5147);
    pub const HCICmdRemoteOOBDataRequestNegativeReply: ProtoId = ProtoId(5149);
    pub const HCICmdHoldMode: ProtoId = ProtoId(5150);
    pub const HCICmdSetEventMask: ProtoId = ProtoId(5151);
    pub const HCICmdReset: ProtoId = ProtoId(5152);
    pub const HCICmdSetEventFilter: ProtoId = ProtoId(5153);
    pub const HCICmdWriteLocalName: ProtoId = ProtoId(5154);
    pub const HCICmdReadLocalName: ProtoId = ProtoId(5155);
    pub const HCICmdWriteConnectAcceptTimeout: ProtoId = ProtoId(5156);
    pub const HCICmdReadLEHostSupport: ProtoId = ProtoId(5158);
    pub const HCICmdWriteLEHostSupport: ProtoId = ProtoId(5159);
    pub const HCICmdReadLocalVersionInformation: ProtoId = ProtoId(5160);
    pub const HCICmdReadLocalExtendedFeatures: ProtoId = ProtoId(5161);
    pub const HCICmdReadBDAddr: ProtoId = ProtoId(5162);
    pub const HCICmdReadLinkQuality: ProtoId = ProtoId(5163);
    pub const HCICmdReadRSSI: ProtoId = ProtoId(5164);
    pub const HCICmdReadLoopbackMode: ProtoId = ProtoId(5165);
    pub const HCICmdWriteLoopbackMode: ProtoId = ProtoId(5166);
    pub const HCICmdLESetEventMask: ProtoId = ProtoId(5167);
    pub const HCICmdLEReadBufferSizeV1: ProtoId = ProtoId(5168);
    pub const HCICmdLEReadBufferSizeV2: ProtoId = ProtoId(5169);
    pub const HCICmdLEReadLocalSupportedFeatures: ProtoId = ProtoId(5170);
    pub const HCICmdLESetRandomAddress: ProtoId = ProtoId(5171);
    pub const HCICmdLESetAdvertisingParameters: ProtoId = ProtoId(5172);
    pub const HCICmdLESetAdvertisingSetRandomAddress: ProtoId = ProtoId(5174);
    pub const HCICmdLESetScanResponseData: ProtoId = ProtoId(5177);
    pub const HCICmdLESetAdvertiseEnable: ProtoId = ProtoId(5178);
    pub const ExtendedAdvertiseSet: ProtoId = ProtoId(5179);
    pub const HCICmdLESetExtendedAdvertiseEnable: ProtoId = ProtoId(5180);
    pub const HCICmdLESetScanParameters: ProtoId = ProtoId(5181);
    pub const HCICmdLESetScanEnable: ProtoId = ProtoId(5183);
    pub const HCICmdLESetExtendedScanEnable: ProtoId = ProtoId(5184);
    pub const HCICmdLECreateConnection: ProtoId = ProtoId(5185);
    pub const HCICmdLECreateConnectionCancel: ProtoId = ProtoId(5187);
    pub const HCICmdLEReadFilterAcceptListSize: ProtoId = ProtoId(5188);
    pub const HCICmdLEClearFilterAcceptList: ProtoId = ProtoId(5189);
    pub const HCICmdLEAddDeviceToFilterAcceptList: ProtoId = ProtoId(5190);
    pub const HCICmdLERemoveDeviceFromFilterAcceptList: ProtoId = ProtoId(5191);
    pub const HCICmdLEConnectionUpdate: ProtoId = ProtoId(5192);
    pub const HCICmdLEReadRemoteFeatures: ProtoId = ProtoId(5193);
    pub const HCICmdLEEnableEncryption: ProtoId = ProtoId(5194);
    pub const HCICmdLELongTermKeyRequestReply: ProtoId = ProtoId(5195);
    pub const HCICmdLELongTermKeyRequestNegativeReply: ProtoId = ProtoId(5196);
    pub const HCIEventHdr: ProtoId = ProtoId(5197);
    pub const HCIEventInquiryComplete: ProtoId = ProtoId(5198);
    pub const HCIEventConnectionComplete: ProtoId = ProtoId(5200);
    pub const HCIEventConnectionRequest: ProtoId = ProtoId(5201);
    pub const HCIEventDisconnectionComplete: ProtoId = ProtoId(5202);
    pub const HCIEventRemoteNameRequestComplete: ProtoId = ProtoId(5203);
    pub const HCIEventEncryptionChange: ProtoId = ProtoId(5204);
    pub const HCIEventReadRemoteSupportedFeaturesComplete: ProtoId = ProtoId(5205);
    pub const HCIEventRemoteHostSupportedFeaturesNotification: ProtoId = ProtoId(5206);
    pub const HCIEventReadRemoteVersionInformationComplete: ProtoId = ProtoId(5207);
    pub const HCIEventCommandComplete: ProtoId = ProtoId(5208);
    pub const HCIEventCommandStatus: ProtoId = ProtoId(5209);
    pub const HCIEventLinkKeyRequest: ProtoId = ProtoId(5211);
    pub const HCIEventReadRemoteExtendedFeaturesComplete: ProtoId = ProtoId(5213);
    pub const HCIEventIOCapabilityResponse: ProtoId = ProtoId(5215);
    pub const HCIEventLEMeta: ProtoId = ProtoId(5217);
    pub const HCICmdCompleteReadLocalName: ProtoId = ProtoId(5218);
    pub const HCICmdCompleteReadLocalVersionInformation: ProtoId = ProtoId(5219);
    pub const HCICmdCompleteReadLocalExtendedFeatures: ProtoId = ProtoId(5220);
    pub const HCICmdCompleteReadBDAddr: ProtoId = ProtoId(5221);
    pub const HCICmdCompleteLEReadWhiteListSize: ProtoId = ProtoId(5222);
    pub const HCILEMetaConnectionComplete: ProtoId = ProtoId(5223);
    pub const HCILEMetaEnhancedConnectionComplete: ProtoId = ProtoId(5224);
    pub const HCILEMetaConnectionUpdateComplete: ProtoId = ProtoId(5225);
    pub const HCILEMetaLEReadRemoteFeaturesComplete: ProtoId = ProtoId(5226);
    pub const HCILEMetaLongTermKeyRequest: ProtoId = ProtoId(5229);
    pub const HCIMonHdr: ProtoId = ProtoId(5232);
    pub const HCIMonPcapHdr: ProtoId = ProtoId(5233);
    pub const HCIMonNewIndex: ProtoId = ProtoId(5234);
    pub const HCIMonIndexInfo: ProtoId = ProtoId(5235);
    pub const BTLEDATA: ProtoId = ProtoId(5241);
    pub const BTLEADVDIRECTIND: ProtoId = ProtoId(5243);
    pub const BTLESCANREQ: ProtoId = ProtoId(5246);
    pub const BTLECONNECTREQ: ProtoId = ProtoId(5248);
    pub const BTLEEMPTYPDU: ProtoId = ProtoId(5249);
    pub const BTLECTRL: ProtoId = ProtoId(5250);
    pub const LLCONNECTIONUPDATEIND: ProtoId = ProtoId(5251);
    pub const LLCHANNELMAPIND: ProtoId = ProtoId(5252);
    pub const LLTERMINATEIND: ProtoId = ProtoId(5253);
    pub const LLENCREQ: ProtoId = ProtoId(5254);
    pub const LLENCRSP: ProtoId = ProtoId(5255);
    pub const LLSTARTENCREQ: ProtoId = ProtoId(5256);
    pub const LLSTARTENCRSP: ProtoId = ProtoId(5257);
    pub const LLUNKNOWNRSP: ProtoId = ProtoId(5258);
    pub const LLFEATUREREQ: ProtoId = ProtoId(5259);
    pub const LLFEATURERSP: ProtoId = ProtoId(5260);
    pub const LLPAUSEENCREQ: ProtoId = ProtoId(5261);
    pub const LLPAUSEENCRSP: ProtoId = ProtoId(5262);
    pub const LLVERSIONIND: ProtoId = ProtoId(5263);
    pub const LLREJECTIND: ProtoId = ProtoId(5264);
    pub const LLSLAVEFEATUREREQ: ProtoId = ProtoId(5265);
    pub const LLCONNECTIONPARAMREQ: ProtoId = ProtoId(5266);
    pub const LLCONNECTIONPARAMRSP: ProtoId = ProtoId(5267);
    pub const LLREJECTEXTIND: ProtoId = ProtoId(5268);
    pub const LLPINGREQ: ProtoId = ProtoId(5269);
    pub const LLPINGRSP: ProtoId = ProtoId(5270);
    pub const LLLENGTHREQ: ProtoId = ProtoId(5271);
    pub const LLLENGTHRSP: ProtoId = ProtoId(5272);
    pub const LLPHYREQ: ProtoId = ProtoId(5273);
    pub const LLPHYRSP: ProtoId = ProtoId(5274);
    pub const LLPHYUPDATEIND: ProtoId = ProtoId(5275);
    pub const LLMINUSEDCHANNELSIND: ProtoId = ProtoId(5276);
    pub const LLCTEREQ: ProtoId = ProtoId(5277);
    pub const LLCTERSP: ProtoId = ProtoId(5278);
    pub const LLCLOCKACCURACYREQ: ProtoId = ProtoId(5280);
    pub const LLCLOCKACCURACYRSP: ProtoId = ProtoId(5281);
    pub const LLCISREQ: ProtoId = ProtoId(5282);
    pub const LLCISRSP: ProtoId = ProtoId(5283);
    pub const LLCISIND: ProtoId = ProtoId(5284);
    pub const LLCISTERMINATEIND: ProtoId = ProtoId(5285);
    pub const LLSUBRATEREQ: ProtoId = ProtoId(5289);
    pub const LLSUBRATEIND: ProtoId = ProtoId(5290);
    pub const LLCHANNELREPORTINGIND: ProtoId = ProtoId(5291);
    // protogen:ids end

    pub fn name(self) -> &'static str {
        desc(self).name
    }

    pub fn is_registered(self) -> bool {
        self.0 >= BUILTIN_COUNT
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Next {
    Proto(ProtoId),
    Raw,
    End,
}

/// Shared rather than redefined per module: sixty generated layers want one of
/// these three, and sixty copies of a one-line hook bury the field table that
/// is the only part of a generated file worth reading.
pub fn next_raw(_: &[u8]) -> Next {
    Next::Raw
}

pub fn next_end(_: &[u8]) -> Next {
    Next::End
}

pub fn header_len_rest(hdr: &[u8]) -> usize {
    hdr.len()
}

pub type OptionParser = fn(&[u8]) -> Vec<crate::options::Item>;

pub struct ProtoDesc {
    pub id: ProtoId,
    pub name: &'static str,
    pub fields: &'static [FieldDesc],
    /// Shorter input dissects as `Raw`.
    pub min_len: usize,
    pub header_len: fn(&[u8]) -> usize,
    pub next: fn(&[u8]) -> Next,
    pub build_len: usize,
    pub parse_options: Option<OptionParser>,
    /// The one table this protocol's options are named by, in both directions.
    pub opt_table: Option<&'static crate::options::OptTable>,
    /// Written after option bytes are appended (IPv4 ihl, TCP data offset).
    pub set_hlen: Option<fn(&mut [u8], usize)>,
    pub bind_next: Option<fn(&mut [u8], ProtoId)>,
    /// Bytes appended when `next` is stacked. BOOTP's magic cookie starts the
    /// option area rather than DHCP itself: RFC 2131 §3.
    pub bind_next_bytes: Option<fn(ProtoId) -> &'static [u8]>,
    /// Total bytes this header's own length field claims, itself included.
    /// `None` means the content runs to the end of what encloses it.
    pub content_len: Option<fn(&[u8]) -> usize>,
}

/// Room for every scapy layer class converted by `dev/protogen/scapy2spec.py`,
/// with the registry's ids above it still inside a `u16`.
pub const BUILTIN_COUNT: u16 = 8192;

const _: () = assert!(BUILTIN_COUNT as usize + MAX_REGISTERED <= u16::MAX as usize + 1);

const BUILTINS: &[ProtoId] = &[
    ProtoId::Ether,
    ProtoId::Dot1Q,
    ProtoId::Arp,
    ProtoId::Ipv4,
    ProtoId::Ipv6,
    ProtoId::Tcp,
    ProtoId::Udp,
    ProtoId::Icmp,
    ProtoId::Icmpv6,
    ProtoId::Dns,
    ProtoId::Bootp,
    ProtoId::Dhcp,
    ProtoId::Null,
    ProtoId::LinuxSll,
    ProtoId::LinuxSll2,
    ProtoId::Raw,
    ProtoId::Padding,
    ProtoId::HopByHop,
    ProtoId::Routing,
    ProtoId::Fragment,
    ProtoId::DestOpt,
    ProtoId::Gre,
    ProtoId::Vxlan,
    ProtoId::Geneve,
    ProtoId::Mpls,
    ProtoId::PppoeDisc,
    ProtoId::Pppoe,
    ProtoId::Ppp,
    ProtoId::GtpU,
    ProtoId::ErspanII,
    ProtoId::ErspanIII,
    // protogen:builtins begin
    ProtoId::Llc,
    ProtoId::Snap,
    ProtoId::Stp,
    ProtoId::Lldp,
    ProtoId::Cdp,
    ProtoId::RadioTap,
    ProtoId::Dot11,
    ProtoId::Dot11Beacon,
    ProtoId::Dot11ProbeReq,
    ProtoId::Dot11ProbeResp,
    ProtoId::Dot11Auth,
    ProtoId::Dot11AssoReq,
    ProtoId::Dot11AssoResp,
    ProtoId::Sctp,
    ProtoId::Igmp,
    ProtoId::Icmpv6NdRs,
    ProtoId::Icmpv6NdRa,
    ProtoId::Icmpv6NdNs,
    ProtoId::Icmpv6NdNa,
    ProtoId::Icmpv6NdRedirect,
    ProtoId::Icmpv6MlQuery,
    ProtoId::Icmpv6MlReport,
    ProtoId::Icmpv6MlDone,
    ProtoId::Icmpv6MlReport2,
    ProtoId::Esp,
    ProtoId::Ah,
    ProtoId::Ospf,
    ProtoId::Rip,
    ProtoId::Bgp,
    ProtoId::Vrrp,
    ProtoId::Hsrp,
    ProtoId::Bfd,
    ProtoId::Ntp,
    ProtoId::Dhcp6,
    ProtoId::Snmp,
    ProtoId::Tftp,
    ProtoId::Syslog,
    ProtoId::Nbns,
    ProtoId::NbtSession,
    ProtoId::Radius,
    ProtoId::Rtp,
    ProtoId::Rtcp,
    ProtoId::NetflowV5,
    ProtoId::NetflowV9,
    ProtoId::Ipfix,
    ProtoId::SFlow,
    ProtoId::Quic,
    ProtoId::WireGuard,
    ProtoId::Tls,
    ProtoId::Http,
    ProtoId::Ssh,
    ProtoId::Mqtt,
    ProtoId::Modbus,
    ProtoId::Smb2,
    ProtoId::Ldap,
    ProtoId::Sip,
    ProtoId::Ftp,
    ProtoId::Smtp,
    ProtoId::Imap,
    ProtoId::Telnet,
    ProtoId::OspfHello,
    ProtoId::OspfDbDesc,
    ProtoId::OspfLsReq,
    ProtoId::OspfLsUpd,
    ProtoId::OspfLsAck,
    ProtoId::BgpOpen,
    ProtoId::BgpUpdate,
    ProtoId::BgpNotification,
    ProtoId::BgpRouteRefresh,
    ProtoId::NTPSystemStatusPacket,
    ProtoId::NTPPeerStatusPacket,
    ProtoId::NTPClockStatusPacket,
    ProtoId::NTPErrorStatusPacket,
    ProtoId::NTPInfoPeerList,
    ProtoId::NTPInfoPeerStats,
    ProtoId::NTPInfoSysStats,
    ProtoId::NTPInfoIOStats,
    ProtoId::NTPInfoTimerStats,
    ProtoId::NTPConfPeer,
    ProtoId::NTPConfUnpeer,
    ProtoId::NTPConfRestrict,
    ProtoId::NTPInfoKernel,
    ProtoId::NTPInfoIfStatsIPv4,
    ProtoId::NTPInfoIfStatsIPv6,
    ProtoId::NTPInfoMonitor1,
    ProtoId::NTPInfoAuth,
    ProtoId::NTPConfTrap,
    ProtoId::NTPInfoControl,
    ProtoId::NTPPrivateReqPacket,
    ProtoId::PPPoETag,
    ProtoId::PPPoEDTags,
    ProtoId::HDLC,
    ProtoId::DIRPPP,
    ProtoId::PPPECPOptionOUI,
    ProtoId::PPPLCPMRUOption,
    ProtoId::PPPLCPACCMOption,
    ProtoId::PPPLCPQualityProtocolOption,
    ProtoId::PPPLCPMagicNumberOption,
    ProtoId::PPPLCPCallbackOption,
    ProtoId::PPPLCPTerminate,
    ProtoId::PPPLCPDiscardRequest,
    ProtoId::PPPLCPEcho,
    ProtoId::HCIPHDRHdr,
    ProtoId::HCIHdr,
    ProtoId::HCIACLHdr,
    ProtoId::L2CAPHdr,
    ProtoId::L2CAPCmdHdr,
    ProtoId::L2CAPConnReq,
    ProtoId::L2CAPConnResp,
    ProtoId::L2CAPCmdRej,
    ProtoId::L2CAPConfReq,
    ProtoId::L2CAPConfResp,
    ProtoId::L2CAPDisconnReq,
    ProtoId::L2CAPDisconnResp,
    ProtoId::L2CAPEchoReq,
    ProtoId::L2CAPEchoResp,
    ProtoId::L2CAPInfoReq,
    ProtoId::L2CAPInfoResp,
    ProtoId::L2CAPCreateChannelRequest,
    ProtoId::L2CAPCreateChannelResponse,
    ProtoId::L2CAPMoveChannelRequest,
    ProtoId::L2CAPMoveChannelResponse,
    ProtoId::L2CAPMoveChannelConfirmationRequest,
    ProtoId::L2CAPMoveChannelConfirmationResponse,
    ProtoId::L2CAPConnectionParameterUpdateRequest,
    ProtoId::L2CAPConnectionParameterUpdateResponse,
    ProtoId::L2CAPLECreditBasedConnectionRequest,
    ProtoId::L2CAPLECreditBasedConnectionResponse,
    ProtoId::L2CAPFlowControlCreditInd,
    ProtoId::L2CAPCreditBasedConnectionRequest,
    ProtoId::L2CAPCreditBasedConnectionResponse,
    ProtoId::L2CAPCreditBasedReconfigureRequest,
    ProtoId::L2CAPCreditBasedReconfigureResponse,
    ProtoId::ATTHdr,
    ProtoId::ATTHandle,
    ProtoId::ATTErrorResponse,
    ProtoId::ATTExchangeMTURequest,
    ProtoId::ATTExchangeMTUResponse,
    ProtoId::ATTFindInformationRequest,
    ProtoId::ATTFindByTypeValueRequest,
    ProtoId::ATTFindByTypeValueResponse,
    ProtoId::ATTReadByTypeRequest,
    ProtoId::ATTReadRequest,
    ProtoId::ATTReadResponse,
    ProtoId::ATTReadMultipleRequest,
    ProtoId::ATTReadMultipleResponse,
    ProtoId::ATTReadByGroupTypeRequest,
    ProtoId::ATTWriteRequest,
    ProtoId::ATTWriteCommand,
    ProtoId::ATTWriteResponse,
    ProtoId::ATTPrepareWriteRequest,
    ProtoId::ATTPrepareWriteResponse,
    ProtoId::ATTHandleValueNotification,
    ProtoId::ATTExecuteWriteRequest,
    ProtoId::ATTExecuteWriteResponse,
    ProtoId::ATTReadMultipleVariableRequest,
    ProtoId::ATTLengthValueTuple,
    ProtoId::ATTHandleLengthValueTuple,
    ProtoId::ATTReadBlobRequest,
    ProtoId::ATTReadBlobResponse,
    ProtoId::ATTHandleValueIndication,
    ProtoId::ATTHandleValueConfirmation,
    ProtoId::SMHdr,
    ProtoId::SMPairingRequest,
    ProtoId::SMPairingResponse,
    ProtoId::SMConfirm,
    ProtoId::SMRandom,
    ProtoId::SMFailed,
    ProtoId::SMEncryptionInformation,
    ProtoId::SMMasterIdentification,
    ProtoId::SMIdentityInformation,
    ProtoId::SMIdentityAddressInformation,
    ProtoId::SMSigningInformation,
    ProtoId::SMSecurityRequest,
    ProtoId::SMPublicKey,
    ProtoId::SMDHKeyCheck,
    ProtoId::SMKeypressNotification,
    ProtoId::EIRFlags,
    ProtoId::EIRClassOfDevice,
    ProtoId::EIRSecurityManagerOOBFlags,
    ProtoId::EIRPeripheralConnectionIntervalRange,
    ProtoId::EIRDeviceID,
    ProtoId::EIRPublicTargetAddress,
    ProtoId::EIRRandomTargetAddress,
    ProtoId::EIRLEBluetoothDeviceAddress,
    ProtoId::EIRLERole,
    ProtoId::EIR3DInformation,
    ProtoId::EIRAppearance,
    ProtoId::HCICommandHdr,
    ProtoId::HCICmdInquiry,
    ProtoId::HCICmdInquiryCancel,
    ProtoId::HCICmdPeriodicInquiryMode,
    ProtoId::HCICmdExitPeiodicInquiryMode,
    ProtoId::HCICmdCreateConnection,
    ProtoId::HCICmdDisconnect,
    ProtoId::HCICmdCreateConnectionCancel,
    ProtoId::HCICmdAcceptConnectionRequest,
    ProtoId::HCICmdRejectConnectionResponse,
    ProtoId::HCICmdLinkKeyRequestNegativeReply,
    ProtoId::HCICmdPINCodeRequestNegativeReply,
    ProtoId::HCICmdChangeConnectionPacketType,
    ProtoId::HCICmdAuthenticationRequested,
    ProtoId::HCICmdSetConnectionEncryption,
    ProtoId::HCICmdChangeConnectionLinkKey,
    ProtoId::HCICmdLinkKeySelection,
    ProtoId::HCICmdRemoteNameRequest,
    ProtoId::HCICmdRemoteNameRequestCancel,
    ProtoId::HCICmdReadRemoteSupportedFeatures,
    ProtoId::HCICmdReadRemoteExtendedFeatures,
    ProtoId::HCICmdIOCapabilityRequestReply,
    ProtoId::HCICmdUserConfirmationRequestReply,
    ProtoId::HCICmdUserConfirmationRequestNegativeReply,
    ProtoId::HCICmdUserPasskeyRequestReply,
    ProtoId::HCICmdUserPasskeyRequestNegativeReply,
    ProtoId::HCICmdRemoteOOBDataRequestNegativeReply,
    ProtoId::HCICmdHoldMode,
    ProtoId::HCICmdSetEventMask,
    ProtoId::HCICmdReset,
    ProtoId::HCICmdSetEventFilter,
    ProtoId::HCICmdWriteLocalName,
    ProtoId::HCICmdReadLocalName,
    ProtoId::HCICmdWriteConnectAcceptTimeout,
    ProtoId::HCICmdReadLEHostSupport,
    ProtoId::HCICmdWriteLEHostSupport,
    ProtoId::HCICmdReadLocalVersionInformation,
    ProtoId::HCICmdReadLocalExtendedFeatures,
    ProtoId::HCICmdReadBDAddr,
    ProtoId::HCICmdReadLinkQuality,
    ProtoId::HCICmdReadRSSI,
    ProtoId::HCICmdReadLoopbackMode,
    ProtoId::HCICmdWriteLoopbackMode,
    ProtoId::HCICmdLESetEventMask,
    ProtoId::HCICmdLEReadBufferSizeV1,
    ProtoId::HCICmdLEReadBufferSizeV2,
    ProtoId::HCICmdLEReadLocalSupportedFeatures,
    ProtoId::HCICmdLESetRandomAddress,
    ProtoId::HCICmdLESetAdvertisingParameters,
    ProtoId::HCICmdLESetAdvertisingSetRandomAddress,
    ProtoId::HCICmdLESetScanResponseData,
    ProtoId::HCICmdLESetAdvertiseEnable,
    ProtoId::ExtendedAdvertiseSet,
    ProtoId::HCICmdLESetExtendedAdvertiseEnable,
    ProtoId::HCICmdLESetScanParameters,
    ProtoId::HCICmdLESetScanEnable,
    ProtoId::HCICmdLESetExtendedScanEnable,
    ProtoId::HCICmdLECreateConnection,
    ProtoId::HCICmdLECreateConnectionCancel,
    ProtoId::HCICmdLEReadFilterAcceptListSize,
    ProtoId::HCICmdLEClearFilterAcceptList,
    ProtoId::HCICmdLEAddDeviceToFilterAcceptList,
    ProtoId::HCICmdLERemoveDeviceFromFilterAcceptList,
    ProtoId::HCICmdLEConnectionUpdate,
    ProtoId::HCICmdLEReadRemoteFeatures,
    ProtoId::HCICmdLEEnableEncryption,
    ProtoId::HCICmdLELongTermKeyRequestReply,
    ProtoId::HCICmdLELongTermKeyRequestNegativeReply,
    ProtoId::HCIEventHdr,
    ProtoId::HCIEventInquiryComplete,
    ProtoId::HCIEventConnectionComplete,
    ProtoId::HCIEventConnectionRequest,
    ProtoId::HCIEventDisconnectionComplete,
    ProtoId::HCIEventRemoteNameRequestComplete,
    ProtoId::HCIEventEncryptionChange,
    ProtoId::HCIEventReadRemoteSupportedFeaturesComplete,
    ProtoId::HCIEventRemoteHostSupportedFeaturesNotification,
    ProtoId::HCIEventReadRemoteVersionInformationComplete,
    ProtoId::HCIEventCommandComplete,
    ProtoId::HCIEventCommandStatus,
    ProtoId::HCIEventLinkKeyRequest,
    ProtoId::HCIEventReadRemoteExtendedFeaturesComplete,
    ProtoId::HCIEventIOCapabilityResponse,
    ProtoId::HCIEventLEMeta,
    ProtoId::HCICmdCompleteReadLocalName,
    ProtoId::HCICmdCompleteReadLocalVersionInformation,
    ProtoId::HCICmdCompleteReadLocalExtendedFeatures,
    ProtoId::HCICmdCompleteReadBDAddr,
    ProtoId::HCICmdCompleteLEReadWhiteListSize,
    ProtoId::HCILEMetaConnectionComplete,
    ProtoId::HCILEMetaEnhancedConnectionComplete,
    ProtoId::HCILEMetaConnectionUpdateComplete,
    ProtoId::HCILEMetaLEReadRemoteFeaturesComplete,
    ProtoId::HCILEMetaLongTermKeyRequest,
    ProtoId::HCIMonHdr,
    ProtoId::HCIMonPcapHdr,
    ProtoId::HCIMonNewIndex,
    ProtoId::HCIMonIndexInfo,
    ProtoId::BTLEDATA,
    ProtoId::BTLEADVDIRECTIND,
    ProtoId::BTLESCANREQ,
    ProtoId::BTLECONNECTREQ,
    ProtoId::BTLEEMPTYPDU,
    ProtoId::BTLECTRL,
    ProtoId::LLCONNECTIONUPDATEIND,
    ProtoId::LLCHANNELMAPIND,
    ProtoId::LLTERMINATEIND,
    ProtoId::LLENCREQ,
    ProtoId::LLENCRSP,
    ProtoId::LLSTARTENCREQ,
    ProtoId::LLSTARTENCRSP,
    ProtoId::LLUNKNOWNRSP,
    ProtoId::LLFEATUREREQ,
    ProtoId::LLFEATURERSP,
    ProtoId::LLPAUSEENCREQ,
    ProtoId::LLPAUSEENCRSP,
    ProtoId::LLVERSIONIND,
    ProtoId::LLREJECTIND,
    ProtoId::LLSLAVEFEATUREREQ,
    ProtoId::LLCONNECTIONPARAMREQ,
    ProtoId::LLCONNECTIONPARAMRSP,
    ProtoId::LLREJECTEXTIND,
    ProtoId::LLPINGREQ,
    ProtoId::LLPINGRSP,
    ProtoId::LLLENGTHREQ,
    ProtoId::LLLENGTHRSP,
    ProtoId::LLPHYREQ,
    ProtoId::LLPHYRSP,
    ProtoId::LLPHYUPDATEIND,
    ProtoId::LLMINUSEDCHANNELSIND,
    ProtoId::LLCTEREQ,
    ProtoId::LLCTERSP,
    ProtoId::LLCLOCKACCURACYREQ,
    ProtoId::LLCLOCKACCURACYRSP,
    ProtoId::LLCISREQ,
    ProtoId::LLCISRSP,
    ProtoId::LLCISIND,
    ProtoId::LLCISTERMINATEIND,
    ProtoId::LLSUBRATEREQ,
    ProtoId::LLSUBRATEIND,
    ProtoId::LLCHANNELREPORTINGIND,
    // protogen:builtins end
];

/// Every built-in id, so the fuzz and robustness suites cannot fall behind the
/// layer list by being a second copy of it.
pub fn builtins() -> impl Iterator<Item = ProtoId> {
    BUILTINS.iter().copied()
}

#[inline]
pub fn desc(id: ProtoId) -> &'static ProtoDesc {
    if id.0 < BUILTIN_COUNT {
        BUILTIN_DESCS[id.0 as usize]
    } else {
        registered_desc(id)
    }
}

/// A match over every registered id is too large for the inliner to take into
/// the dissection walk, which asks for a descriptor once per layer per packet.
/// An id the build does not register reads `Raw`, as the match's `_` arm did.
static BUILTIN_DESCS: [&ProtoDesc; BUILTIN_COUNT as usize] = {
    use crate::layers::*;
    let mut t = [&raw::DESC; BUILTIN_COUNT as usize];
    t[ProtoId::Padding.0 as usize] = &raw::PADDING_DESC;
    t[ProtoId::Ether.0 as usize] = &ether::DESC;
    t[ProtoId::Dot1Q.0 as usize] = &dot1q::DESC;
    t[ProtoId::Arp.0 as usize] = &arp::DESC;
    t[ProtoId::Ipv4.0 as usize] = &ipv4::DESC;
    t[ProtoId::Ipv6.0 as usize] = &ipv6::DESC;
    t[ProtoId::Tcp.0 as usize] = &tcp::DESC;
    t[ProtoId::Udp.0 as usize] = &udp::DESC;
    t[ProtoId::Icmp.0 as usize] = &icmp::DESC;
    t[ProtoId::Icmpv6.0 as usize] = &icmpv6::DESC;
    t[ProtoId::Dns.0 as usize] = &dns::DESC;
    t[ProtoId::Bootp.0 as usize] = &bootp::DESC;
    t[ProtoId::Dhcp.0 as usize] = &bootp::DHCP_DESC;
    t[ProtoId::Null.0 as usize] = &null::DESC;
    t[ProtoId::LinuxSll.0 as usize] = &linux_sll::DESC;
    t[ProtoId::LinuxSll2.0 as usize] = &linux_sll::DESC_V2;
    t[ProtoId::HopByHop.0 as usize] = &ipv6_ext::HOP_BY_HOP_DESC;
    t[ProtoId::Routing.0 as usize] = &ipv6_ext::ROUTING_DESC;
    t[ProtoId::Fragment.0 as usize] = &ipv6_ext::FRAGMENT_DESC;
    t[ProtoId::DestOpt.0 as usize] = &ipv6_ext::DEST_OPT_DESC;
    t[ProtoId::Gre.0 as usize] = &gre::DESC;
    t[ProtoId::Vxlan.0 as usize] = &vxlan::DESC;
    t[ProtoId::Geneve.0 as usize] = &geneve::DESC;
    t[ProtoId::Mpls.0 as usize] = &mpls::DESC;
    t[ProtoId::PppoeDisc.0 as usize] = &pppoe::DISC_DESC;
    t[ProtoId::Pppoe.0 as usize] = &pppoe::DESC;
    t[ProtoId::Ppp.0 as usize] = &pppoe::PPP_DESC;
    t[ProtoId::GtpU.0 as usize] = &gtp::DESC;
    t[ProtoId::ErspanII.0 as usize] = &erspan::DESC_II;
    t[ProtoId::ErspanIII.0 as usize] = &erspan::DESC_III;
    // protogen:desc begin
    t[ProtoId::Llc.0 as usize] = &llc::DESC;
    t[ProtoId::Snap.0 as usize] = &snap::DESC;
    t[ProtoId::Stp.0 as usize] = &stp::DESC;
    t[ProtoId::Lldp.0 as usize] = &lldp::DESC;
    t[ProtoId::Cdp.0 as usize] = &cdp::DESC;
    t[ProtoId::RadioTap.0 as usize] = &radiotap::DESC;
    t[ProtoId::Dot11.0 as usize] = &dot11::DESC;
    t[ProtoId::Dot11Beacon.0 as usize] = &dot11beacon::DESC;
    t[ProtoId::Dot11ProbeReq.0 as usize] = &dot11probereq::DESC;
    t[ProtoId::Dot11ProbeResp.0 as usize] = &dot11proberesp::DESC;
    t[ProtoId::Dot11Auth.0 as usize] = &dot11auth::DESC;
    t[ProtoId::Dot11AssoReq.0 as usize] = &dot11assoreq::DESC;
    t[ProtoId::Dot11AssoResp.0 as usize] = &dot11assoresp::DESC;
    t[ProtoId::Sctp.0 as usize] = &sctp::DESC;
    t[ProtoId::Igmp.0 as usize] = &igmp::DESC;
    t[ProtoId::Icmpv6NdRs.0 as usize] = &icmpv6_rs::DESC;
    t[ProtoId::Icmpv6NdRa.0 as usize] = &icmpv6_ra::DESC;
    t[ProtoId::Icmpv6NdNs.0 as usize] = &icmpv6_ns::DESC;
    t[ProtoId::Icmpv6NdNa.0 as usize] = &icmpv6_na::DESC;
    t[ProtoId::Icmpv6NdRedirect.0 as usize] = &icmpv6_redirect::DESC;
    t[ProtoId::Icmpv6MlQuery.0 as usize] = &mld_query::DESC;
    t[ProtoId::Icmpv6MlReport.0 as usize] = &mld_report::DESC;
    t[ProtoId::Icmpv6MlDone.0 as usize] = &mld_done::DESC;
    t[ProtoId::Icmpv6MlReport2.0 as usize] = &mld_report2::DESC;
    t[ProtoId::Esp.0 as usize] = &esp::DESC;
    t[ProtoId::Ah.0 as usize] = &ah::DESC;
    t[ProtoId::Ospf.0 as usize] = &ospf::DESC;
    t[ProtoId::Rip.0 as usize] = &rip::DESC;
    t[ProtoId::Bgp.0 as usize] = &bgp::DESC;
    t[ProtoId::Vrrp.0 as usize] = &vrrp::DESC;
    t[ProtoId::Hsrp.0 as usize] = &hsrp::DESC;
    t[ProtoId::Bfd.0 as usize] = &bfd::DESC;
    t[ProtoId::Ntp.0 as usize] = &ntp::DESC;
    t[ProtoId::Dhcp6.0 as usize] = &dhcp6::DESC;
    t[ProtoId::Snmp.0 as usize] = &snmp::DESC;
    t[ProtoId::Tftp.0 as usize] = &tftp::DESC;
    t[ProtoId::Syslog.0 as usize] = &syslog::DESC;
    t[ProtoId::Nbns.0 as usize] = &nbns::DESC;
    t[ProtoId::NbtSession.0 as usize] = &nbtsession::DESC;
    t[ProtoId::Radius.0 as usize] = &radius::DESC;
    t[ProtoId::Rtp.0 as usize] = &rtp::DESC;
    t[ProtoId::Rtcp.0 as usize] = &rtcp::DESC;
    t[ProtoId::NetflowV5.0 as usize] = &netflow5::DESC;
    t[ProtoId::NetflowV9.0 as usize] = &netflow9::DESC;
    t[ProtoId::Ipfix.0 as usize] = &ipfix::DESC;
    t[ProtoId::SFlow.0 as usize] = &sflow::DESC;
    t[ProtoId::Quic.0 as usize] = &quic::DESC;
    t[ProtoId::WireGuard.0 as usize] = &wireguard::DESC;
    t[ProtoId::Tls.0 as usize] = &tls::DESC;
    t[ProtoId::Http.0 as usize] = &http::DESC;
    t[ProtoId::Ssh.0 as usize] = &ssh::DESC;
    t[ProtoId::Mqtt.0 as usize] = &mqtt::DESC;
    t[ProtoId::Modbus.0 as usize] = &modbus::DESC;
    t[ProtoId::Smb2.0 as usize] = &smb2::DESC;
    t[ProtoId::Ldap.0 as usize] = &ldap::DESC;
    t[ProtoId::Sip.0 as usize] = &sip::DESC;
    t[ProtoId::Ftp.0 as usize] = &ftp::DESC;
    t[ProtoId::Smtp.0 as usize] = &smtp::DESC;
    t[ProtoId::Imap.0 as usize] = &imap::DESC;
    t[ProtoId::Telnet.0 as usize] = &telnet::DESC;
    t[ProtoId::OspfHello.0 as usize] = &ospf_hello::DESC;
    t[ProtoId::OspfDbDesc.0 as usize] = &ospf_dbdesc::DESC;
    t[ProtoId::OspfLsReq.0 as usize] = &ospf_lsreq::DESC;
    t[ProtoId::OspfLsUpd.0 as usize] = &ospf_lsupd::DESC;
    t[ProtoId::OspfLsAck.0 as usize] = &ospf_lsack::DESC;
    t[ProtoId::BgpOpen.0 as usize] = &bgp_open::DESC;
    t[ProtoId::BgpUpdate.0 as usize] = &bgp_update::DESC;
    t[ProtoId::BgpNotification.0 as usize] = &bgp_notification::DESC;
    t[ProtoId::BgpRouteRefresh.0 as usize] = &bgp_route_refresh::DESC;
    t[ProtoId::NTPSystemStatusPacket.0 as usize] = &ntp_ntpsystemstatuspacket::DESC;
    t[ProtoId::NTPPeerStatusPacket.0 as usize] = &ntp_ntppeerstatuspacket::DESC;
    t[ProtoId::NTPClockStatusPacket.0 as usize] = &ntp_ntpclockstatuspacket::DESC;
    t[ProtoId::NTPErrorStatusPacket.0 as usize] = &ntp_ntperrorstatuspacket::DESC;
    t[ProtoId::NTPInfoPeerList.0 as usize] = &ntp_ntpinfopeerlist::DESC;
    t[ProtoId::NTPInfoPeerStats.0 as usize] = &ntp_ntpinfopeerstats::DESC;
    t[ProtoId::NTPInfoSysStats.0 as usize] = &ntp_ntpinfosysstats::DESC;
    t[ProtoId::NTPInfoIOStats.0 as usize] = &ntp_ntpinfoiostats::DESC;
    t[ProtoId::NTPInfoTimerStats.0 as usize] = &ntp_ntpinfotimerstats::DESC;
    t[ProtoId::NTPConfPeer.0 as usize] = &ntp_ntpconfpeer::DESC;
    t[ProtoId::NTPConfUnpeer.0 as usize] = &ntp_ntpconfunpeer::DESC;
    t[ProtoId::NTPConfRestrict.0 as usize] = &ntp_ntpconfrestrict::DESC;
    t[ProtoId::NTPInfoKernel.0 as usize] = &ntp_ntpinfokernel::DESC;
    t[ProtoId::NTPInfoIfStatsIPv4.0 as usize] = &ntp_ntpinfoifstatsipv4::DESC;
    t[ProtoId::NTPInfoIfStatsIPv6.0 as usize] = &ntp_ntpinfoifstatsipv6::DESC;
    t[ProtoId::NTPInfoMonitor1.0 as usize] = &ntp_ntpinfomonitor1::DESC;
    t[ProtoId::NTPInfoAuth.0 as usize] = &ntp_ntpinfoauth::DESC;
    t[ProtoId::NTPConfTrap.0 as usize] = &ntp_ntpconftrap::DESC;
    t[ProtoId::NTPInfoControl.0 as usize] = &ntp_ntpinfocontrol::DESC;
    t[ProtoId::NTPPrivateReqPacket.0 as usize] = &ntp_ntpprivatereqpacket::DESC;
    t[ProtoId::PPPoETag.0 as usize] = &ppp_pppoetag::DESC;
    t[ProtoId::PPPoEDTags.0 as usize] = &ppp_pppoed_tags::DESC;
    t[ProtoId::HDLC.0 as usize] = &ppp_hdlc::DESC;
    t[ProtoId::DIRPPP.0 as usize] = &ppp_dir_ppp::DESC;
    t[ProtoId::PPPECPOptionOUI.0 as usize] = &ppp_ppp_ecp_option_oui::DESC;
    t[ProtoId::PPPLCPMRUOption.0 as usize] = &ppp_ppp_lcp_mru_option::DESC;
    t[ProtoId::PPPLCPACCMOption.0 as usize] = &ppp_ppp_lcp_accm_option::DESC;
    t[ProtoId::PPPLCPQualityProtocolOption.0 as usize] = &ppp_ppp_lcp_quality_protocol_option::DESC;
    t[ProtoId::PPPLCPMagicNumberOption.0 as usize] = &ppp_ppp_lcp_magic_number_option::DESC;
    t[ProtoId::PPPLCPCallbackOption.0 as usize] = &ppp_ppp_lcp_callback_option::DESC;
    t[ProtoId::PPPLCPTerminate.0 as usize] = &ppp_ppp_lcp_terminate::DESC;
    t[ProtoId::PPPLCPDiscardRequest.0 as usize] = &ppp_ppp_lcp_discard_request::DESC;
    t[ProtoId::PPPLCPEcho.0 as usize] = &ppp_ppp_lcp_echo::DESC;
    t[ProtoId::HCIPHDRHdr.0 as usize] = &bluetooth_hci_phdr_hdr::DESC;
    t[ProtoId::HCIHdr.0 as usize] = &bluetooth_hci_hdr::DESC;
    t[ProtoId::HCIACLHdr.0 as usize] = &bluetooth_hci_acl_hdr::DESC;
    t[ProtoId::L2CAPHdr.0 as usize] = &bluetooth_l2cap_hdr::DESC;
    t[ProtoId::L2CAPCmdHdr.0 as usize] = &bluetooth_l2cap_cmdhdr::DESC;
    t[ProtoId::L2CAPConnReq.0 as usize] = &bluetooth_l2cap_connreq::DESC;
    t[ProtoId::L2CAPConnResp.0 as usize] = &bluetooth_l2cap_connresp::DESC;
    t[ProtoId::L2CAPCmdRej.0 as usize] = &bluetooth_l2cap_cmdrej::DESC;
    t[ProtoId::L2CAPConfReq.0 as usize] = &bluetooth_l2cap_confreq::DESC;
    t[ProtoId::L2CAPConfResp.0 as usize] = &bluetooth_l2cap_confresp::DESC;
    t[ProtoId::L2CAPDisconnReq.0 as usize] = &bluetooth_l2cap_disconnreq::DESC;
    t[ProtoId::L2CAPDisconnResp.0 as usize] = &bluetooth_l2cap_disconnresp::DESC;
    t[ProtoId::L2CAPEchoReq.0 as usize] = &bluetooth_l2cap_echoreq::DESC;
    t[ProtoId::L2CAPEchoResp.0 as usize] = &bluetooth_l2cap_echoresp::DESC;
    t[ProtoId::L2CAPInfoReq.0 as usize] = &bluetooth_l2cap_inforeq::DESC;
    t[ProtoId::L2CAPInfoResp.0 as usize] = &bluetooth_l2cap_inforesp::DESC;
    t[ProtoId::L2CAPCreateChannelRequest.0 as usize] =
        &bluetooth_l2cap_create_channel_request::DESC;
    t[ProtoId::L2CAPCreateChannelResponse.0 as usize] =
        &bluetooth_l2cap_create_channel_response::DESC;
    t[ProtoId::L2CAPMoveChannelRequest.0 as usize] = &bluetooth_l2cap_move_channel_request::DESC;
    t[ProtoId::L2CAPMoveChannelResponse.0 as usize] = &bluetooth_l2cap_move_channel_response::DESC;
    t[ProtoId::L2CAPMoveChannelConfirmationRequest.0 as usize] =
        &bluetooth_l2cap_move_channel_confirmation_request::DESC;
    t[ProtoId::L2CAPMoveChannelConfirmationResponse.0 as usize] =
        &bluetooth_l2cap_move_channel_confirmation_response::DESC;
    t[ProtoId::L2CAPConnectionParameterUpdateRequest.0 as usize] =
        &bluetooth_l2cap_connection_parameter_update_request::DESC;
    t[ProtoId::L2CAPConnectionParameterUpdateResponse.0 as usize] =
        &bluetooth_l2cap_connection_parameter_update_response::DESC;
    t[ProtoId::L2CAPLECreditBasedConnectionRequest.0 as usize] =
        &bluetooth_l2cap_le_credit_based_connection_request::DESC;
    t[ProtoId::L2CAPLECreditBasedConnectionResponse.0 as usize] =
        &bluetooth_l2cap_le_credit_based_connection_response::DESC;
    t[ProtoId::L2CAPFlowControlCreditInd.0 as usize] =
        &bluetooth_l2cap_flow_control_credit_ind::DESC;
    t[ProtoId::L2CAPCreditBasedConnectionRequest.0 as usize] =
        &bluetooth_l2cap_credit_based_connection_request::DESC;
    t[ProtoId::L2CAPCreditBasedConnectionResponse.0 as usize] =
        &bluetooth_l2cap_credit_based_connection_response::DESC;
    t[ProtoId::L2CAPCreditBasedReconfigureRequest.0 as usize] =
        &bluetooth_l2cap_credit_based_reconfigure_request::DESC;
    t[ProtoId::L2CAPCreditBasedReconfigureResponse.0 as usize] =
        &bluetooth_l2cap_credit_based_reconfigure_response::DESC;
    t[ProtoId::ATTHdr.0 as usize] = &bluetooth_att_hdr::DESC;
    t[ProtoId::ATTHandle.0 as usize] = &bluetooth_att_handle::DESC;
    t[ProtoId::ATTErrorResponse.0 as usize] = &bluetooth_att_error_response::DESC;
    t[ProtoId::ATTExchangeMTURequest.0 as usize] = &bluetooth_att_exchange_mtu_request::DESC;
    t[ProtoId::ATTExchangeMTUResponse.0 as usize] = &bluetooth_att_exchange_mtu_response::DESC;
    t[ProtoId::ATTFindInformationRequest.0 as usize] =
        &bluetooth_att_find_information_request::DESC;
    t[ProtoId::ATTFindByTypeValueRequest.0 as usize] =
        &bluetooth_att_find_by_type_value_request::DESC;
    t[ProtoId::ATTFindByTypeValueResponse.0 as usize] =
        &bluetooth_att_find_by_type_value_response::DESC;
    t[ProtoId::ATTReadByTypeRequest.0 as usize] = &bluetooth_att_read_by_type_request::DESC;
    t[ProtoId::ATTReadRequest.0 as usize] = &bluetooth_att_read_request::DESC;
    t[ProtoId::ATTReadResponse.0 as usize] = &bluetooth_att_read_response::DESC;
    t[ProtoId::ATTReadMultipleRequest.0 as usize] = &bluetooth_att_read_multiple_request::DESC;
    t[ProtoId::ATTReadMultipleResponse.0 as usize] = &bluetooth_att_read_multiple_response::DESC;
    t[ProtoId::ATTReadByGroupTypeRequest.0 as usize] =
        &bluetooth_att_read_by_group_type_request::DESC;
    t[ProtoId::ATTWriteRequest.0 as usize] = &bluetooth_att_write_request::DESC;
    t[ProtoId::ATTWriteCommand.0 as usize] = &bluetooth_att_write_command::DESC;
    t[ProtoId::ATTWriteResponse.0 as usize] = &bluetooth_att_write_response::DESC;
    t[ProtoId::ATTPrepareWriteRequest.0 as usize] = &bluetooth_att_prepare_write_request::DESC;
    t[ProtoId::ATTPrepareWriteResponse.0 as usize] = &bluetooth_att_prepare_write_response::DESC;
    t[ProtoId::ATTHandleValueNotification.0 as usize] =
        &bluetooth_att_handle_value_notification::DESC;
    t[ProtoId::ATTExecuteWriteRequest.0 as usize] = &bluetooth_att_execute_write_request::DESC;
    t[ProtoId::ATTExecuteWriteResponse.0 as usize] = &bluetooth_att_execute_write_response::DESC;
    t[ProtoId::ATTReadMultipleVariableRequest.0 as usize] =
        &bluetooth_att_read_multiple_variable_request::DESC;
    t[ProtoId::ATTLengthValueTuple.0 as usize] = &bluetooth_att_length_value_tuple::DESC;
    t[ProtoId::ATTHandleLengthValueTuple.0 as usize] =
        &bluetooth_att_handle_length_value_tuple::DESC;
    t[ProtoId::ATTReadBlobRequest.0 as usize] = &bluetooth_att_read_blob_request::DESC;
    t[ProtoId::ATTReadBlobResponse.0 as usize] = &bluetooth_att_read_blob_response::DESC;
    t[ProtoId::ATTHandleValueIndication.0 as usize] = &bluetooth_att_handle_value_indication::DESC;
    t[ProtoId::ATTHandleValueConfirmation.0 as usize] =
        &bluetooth_att_handle_value_confirmation::DESC;
    t[ProtoId::SMHdr.0 as usize] = &bluetooth_sm_hdr::DESC;
    t[ProtoId::SMPairingRequest.0 as usize] = &bluetooth_sm_pairing_request::DESC;
    t[ProtoId::SMPairingResponse.0 as usize] = &bluetooth_sm_pairing_response::DESC;
    t[ProtoId::SMConfirm.0 as usize] = &bluetooth_sm_confirm::DESC;
    t[ProtoId::SMRandom.0 as usize] = &bluetooth_sm_random::DESC;
    t[ProtoId::SMFailed.0 as usize] = &bluetooth_sm_failed::DESC;
    t[ProtoId::SMEncryptionInformation.0 as usize] = &bluetooth_sm_encryption_information::DESC;
    t[ProtoId::SMMasterIdentification.0 as usize] = &bluetooth_sm_master_identification::DESC;
    t[ProtoId::SMIdentityInformation.0 as usize] = &bluetooth_sm_identity_information::DESC;
    t[ProtoId::SMIdentityAddressInformation.0 as usize] =
        &bluetooth_sm_identity_address_information::DESC;
    t[ProtoId::SMSigningInformation.0 as usize] = &bluetooth_sm_signing_information::DESC;
    t[ProtoId::SMSecurityRequest.0 as usize] = &bluetooth_sm_security_request::DESC;
    t[ProtoId::SMPublicKey.0 as usize] = &bluetooth_sm_public_key::DESC;
    t[ProtoId::SMDHKeyCheck.0 as usize] = &bluetooth_sm_dhkey_check::DESC;
    t[ProtoId::SMKeypressNotification.0 as usize] = &bluetooth_sm_keypress_notification::DESC;
    t[ProtoId::EIRFlags.0 as usize] = &bluetooth_eir_flags::DESC;
    t[ProtoId::EIRClassOfDevice.0 as usize] = &bluetooth_eir_classofdevice::DESC;
    t[ProtoId::EIRSecurityManagerOOBFlags.0 as usize] =
        &bluetooth_eir_securitymanageroobflags::DESC;
    t[ProtoId::EIRPeripheralConnectionIntervalRange.0 as usize] =
        &bluetooth_eir_peripheralconnectionintervalrange::DESC;
    t[ProtoId::EIRDeviceID.0 as usize] = &bluetooth_eir_device_id::DESC;
    t[ProtoId::EIRPublicTargetAddress.0 as usize] = &bluetooth_eir_publictargetaddress::DESC;
    t[ProtoId::EIRRandomTargetAddress.0 as usize] = &bluetooth_eir_randomtargetaddress::DESC;
    t[ProtoId::EIRLEBluetoothDeviceAddress.0 as usize] =
        &bluetooth_eir_lebluetoothdeviceaddress::DESC;
    t[ProtoId::EIRLERole.0 as usize] = &bluetooth_eir_lerole::DESC;
    t[ProtoId::EIR3DInformation.0 as usize] = &bluetooth_eir_3dinformation::DESC;
    t[ProtoId::EIRAppearance.0 as usize] = &bluetooth_eir_appearance::DESC;
    t[ProtoId::HCICommandHdr.0 as usize] = &bluetooth_hci_command_hdr::DESC;
    t[ProtoId::HCICmdInquiry.0 as usize] = &bluetooth_hci_cmd_inquiry::DESC;
    t[ProtoId::HCICmdInquiryCancel.0 as usize] = &bluetooth_hci_cmd_inquiry_cancel::DESC;
    t[ProtoId::HCICmdPeriodicInquiryMode.0 as usize] =
        &bluetooth_hci_cmd_periodic_inquiry_mode::DESC;
    t[ProtoId::HCICmdExitPeiodicInquiryMode.0 as usize] =
        &bluetooth_hci_cmd_exit_peiodic_inquiry_mode::DESC;
    t[ProtoId::HCICmdCreateConnection.0 as usize] = &bluetooth_hci_cmd_create_connection::DESC;
    t[ProtoId::HCICmdDisconnect.0 as usize] = &bluetooth_hci_cmd_disconnect::DESC;
    t[ProtoId::HCICmdCreateConnectionCancel.0 as usize] =
        &bluetooth_hci_cmd_create_connection_cancel::DESC;
    t[ProtoId::HCICmdAcceptConnectionRequest.0 as usize] =
        &bluetooth_hci_cmd_accept_connection_request::DESC;
    t[ProtoId::HCICmdRejectConnectionResponse.0 as usize] =
        &bluetooth_hci_cmd_reject_connection_response::DESC;
    t[ProtoId::HCICmdLinkKeyRequestNegativeReply.0 as usize] =
        &bluetooth_hci_cmd_link_key_request_negative_reply::DESC;
    t[ProtoId::HCICmdPINCodeRequestNegativeReply.0 as usize] =
        &bluetooth_hci_cmd_pin_code_request_negative_reply::DESC;
    t[ProtoId::HCICmdChangeConnectionPacketType.0 as usize] =
        &bluetooth_hci_cmd_change_connection_packet_type::DESC;
    t[ProtoId::HCICmdAuthenticationRequested.0 as usize] =
        &bluetooth_hci_cmd_authentication_requested::DESC;
    t[ProtoId::HCICmdSetConnectionEncryption.0 as usize] =
        &bluetooth_hci_cmd_set_connection_encryption::DESC;
    t[ProtoId::HCICmdChangeConnectionLinkKey.0 as usize] =
        &bluetooth_hci_cmd_change_connection_link_key::DESC;
    t[ProtoId::HCICmdLinkKeySelection.0 as usize] = &bluetooth_hci_cmd_link_key_selection::DESC;
    t[ProtoId::HCICmdRemoteNameRequest.0 as usize] = &bluetooth_hci_cmd_remote_name_request::DESC;
    t[ProtoId::HCICmdRemoteNameRequestCancel.0 as usize] =
        &bluetooth_hci_cmd_remote_name_request_cancel::DESC;
    t[ProtoId::HCICmdReadRemoteSupportedFeatures.0 as usize] =
        &bluetooth_hci_cmd_read_remote_supported_features::DESC;
    t[ProtoId::HCICmdReadRemoteExtendedFeatures.0 as usize] =
        &bluetooth_hci_cmd_read_remote_extended_features::DESC;
    t[ProtoId::HCICmdIOCapabilityRequestReply.0 as usize] =
        &bluetooth_hci_cmd_io_capability_request_reply::DESC;
    t[ProtoId::HCICmdUserConfirmationRequestReply.0 as usize] =
        &bluetooth_hci_cmd_user_confirmation_request_reply::DESC;
    t[ProtoId::HCICmdUserConfirmationRequestNegativeReply.0 as usize] =
        &bluetooth_hci_cmd_user_confirmation_request_negative_reply::DESC;
    t[ProtoId::HCICmdUserPasskeyRequestReply.0 as usize] =
        &bluetooth_hci_cmd_user_passkey_request_reply::DESC;
    t[ProtoId::HCICmdUserPasskeyRequestNegativeReply.0 as usize] =
        &bluetooth_hci_cmd_user_passkey_request_negative_reply::DESC;
    t[ProtoId::HCICmdRemoteOOBDataRequestNegativeReply.0 as usize] =
        &bluetooth_hci_cmd_remote_oob_data_request_negative_reply::DESC;
    t[ProtoId::HCICmdHoldMode.0 as usize] = &bluetooth_hci_cmd_hold_mode::DESC;
    t[ProtoId::HCICmdSetEventMask.0 as usize] = &bluetooth_hci_cmd_set_event_mask::DESC;
    t[ProtoId::HCICmdReset.0 as usize] = &bluetooth_hci_cmd_reset::DESC;
    t[ProtoId::HCICmdSetEventFilter.0 as usize] = &bluetooth_hci_cmd_set_event_filter::DESC;
    t[ProtoId::HCICmdWriteLocalName.0 as usize] = &bluetooth_hci_cmd_write_local_name::DESC;
    t[ProtoId::HCICmdReadLocalName.0 as usize] = &bluetooth_hci_cmd_read_local_name::DESC;
    t[ProtoId::HCICmdWriteConnectAcceptTimeout.0 as usize] =
        &bluetooth_hci_cmd_write_connect_accept_timeout::DESC;
    t[ProtoId::HCICmdReadLEHostSupport.0 as usize] = &bluetooth_hci_cmd_read_le_host_support::DESC;
    t[ProtoId::HCICmdWriteLEHostSupport.0 as usize] =
        &bluetooth_hci_cmd_write_le_host_support::DESC;
    t[ProtoId::HCICmdReadLocalVersionInformation.0 as usize] =
        &bluetooth_hci_cmd_read_local_version_information::DESC;
    t[ProtoId::HCICmdReadLocalExtendedFeatures.0 as usize] =
        &bluetooth_hci_cmd_read_local_extended_features::DESC;
    t[ProtoId::HCICmdReadBDAddr.0 as usize] = &bluetooth_hci_cmd_read_bd_addr::DESC;
    t[ProtoId::HCICmdReadLinkQuality.0 as usize] = &bluetooth_hci_cmd_read_link_quality::DESC;
    t[ProtoId::HCICmdReadRSSI.0 as usize] = &bluetooth_hci_cmd_read_rssi::DESC;
    t[ProtoId::HCICmdReadLoopbackMode.0 as usize] = &bluetooth_hci_cmd_read_loopback_mode::DESC;
    t[ProtoId::HCICmdWriteLoopbackMode.0 as usize] = &bluetooth_hci_cmd_write_loopback_mode::DESC;
    t[ProtoId::HCICmdLESetEventMask.0 as usize] = &bluetooth_hci_cmd_le_set_event_mask::DESC;
    t[ProtoId::HCICmdLEReadBufferSizeV1.0 as usize] =
        &bluetooth_hci_cmd_le_read_buffer_size_v1::DESC;
    t[ProtoId::HCICmdLEReadBufferSizeV2.0 as usize] =
        &bluetooth_hci_cmd_le_read_buffer_size_v2::DESC;
    t[ProtoId::HCICmdLEReadLocalSupportedFeatures.0 as usize] =
        &bluetooth_hci_cmd_le_read_local_supported_features::DESC;
    t[ProtoId::HCICmdLESetRandomAddress.0 as usize] =
        &bluetooth_hci_cmd_le_set_random_address::DESC;
    t[ProtoId::HCICmdLESetAdvertisingParameters.0 as usize] =
        &bluetooth_hci_cmd_le_set_advertising_parameters::DESC;
    t[ProtoId::HCICmdLESetAdvertisingSetRandomAddress.0 as usize] =
        &bluetooth_hci_cmd_le_set_advertising_set_random_address::DESC;
    t[ProtoId::HCICmdLESetScanResponseData.0 as usize] =
        &bluetooth_hci_cmd_le_set_scan_response_data::DESC;
    t[ProtoId::HCICmdLESetAdvertiseEnable.0 as usize] =
        &bluetooth_hci_cmd_le_set_advertise_enable::DESC;
    t[ProtoId::ExtendedAdvertiseSet.0 as usize] = &bluetooth_extended_advertise_set::DESC;
    t[ProtoId::HCICmdLESetExtendedAdvertiseEnable.0 as usize] =
        &bluetooth_hci_cmd_le_set_extended_advertise_enable::DESC;
    t[ProtoId::HCICmdLESetScanParameters.0 as usize] =
        &bluetooth_hci_cmd_le_set_scan_parameters::DESC;
    t[ProtoId::HCICmdLESetScanEnable.0 as usize] = &bluetooth_hci_cmd_le_set_scan_enable::DESC;
    t[ProtoId::HCICmdLESetExtendedScanEnable.0 as usize] =
        &bluetooth_hci_cmd_le_set_extended_scan_enable::DESC;
    t[ProtoId::HCICmdLECreateConnection.0 as usize] = &bluetooth_hci_cmd_le_create_connection::DESC;
    t[ProtoId::HCICmdLECreateConnectionCancel.0 as usize] =
        &bluetooth_hci_cmd_le_create_connection_cancel::DESC;
    t[ProtoId::HCICmdLEReadFilterAcceptListSize.0 as usize] =
        &bluetooth_hci_cmd_le_read_filter_accept_list_size::DESC;
    t[ProtoId::HCICmdLEClearFilterAcceptList.0 as usize] =
        &bluetooth_hci_cmd_le_clear_filter_accept_list::DESC;
    t[ProtoId::HCICmdLEAddDeviceToFilterAcceptList.0 as usize] =
        &bluetooth_hci_cmd_le_add_device_to_filter_accept_list::DESC;
    t[ProtoId::HCICmdLERemoveDeviceFromFilterAcceptList.0 as usize] =
        &bluetooth_hci_cmd_le_remove_device_from_filter_accept_list::DESC;
    t[ProtoId::HCICmdLEConnectionUpdate.0 as usize] = &bluetooth_hci_cmd_le_connection_update::DESC;
    t[ProtoId::HCICmdLEReadRemoteFeatures.0 as usize] =
        &bluetooth_hci_cmd_le_read_remote_features::DESC;
    t[ProtoId::HCICmdLEEnableEncryption.0 as usize] = &bluetooth_hci_cmd_le_enable_encryption::DESC;
    t[ProtoId::HCICmdLELongTermKeyRequestReply.0 as usize] =
        &bluetooth_hci_cmd_le_long_term_key_request_reply::DESC;
    t[ProtoId::HCICmdLELongTermKeyRequestNegativeReply.0 as usize] =
        &bluetooth_hci_cmd_le_long_term_key_request_negative_reply::DESC;
    t[ProtoId::HCIEventHdr.0 as usize] = &bluetooth_hci_event_hdr::DESC;
    t[ProtoId::HCIEventInquiryComplete.0 as usize] = &bluetooth_hci_event_inquiry_complete::DESC;
    t[ProtoId::HCIEventConnectionComplete.0 as usize] =
        &bluetooth_hci_event_connection_complete::DESC;
    t[ProtoId::HCIEventConnectionRequest.0 as usize] =
        &bluetooth_hci_event_connection_request::DESC;
    t[ProtoId::HCIEventDisconnectionComplete.0 as usize] =
        &bluetooth_hci_event_disconnection_complete::DESC;
    t[ProtoId::HCIEventRemoteNameRequestComplete.0 as usize] =
        &bluetooth_hci_event_remote_name_request_complete::DESC;
    t[ProtoId::HCIEventEncryptionChange.0 as usize] = &bluetooth_hci_event_encryption_change::DESC;
    t[ProtoId::HCIEventReadRemoteSupportedFeaturesComplete.0 as usize] =
        &bluetooth_hci_event_read_remote_supported_features_complete::DESC;
    t[ProtoId::HCIEventRemoteHostSupportedFeaturesNotification.0 as usize] =
        &bluetooth_hci_event_remote_host_supported_features_notification::DESC;
    t[ProtoId::HCIEventReadRemoteVersionInformationComplete.0 as usize] =
        &bluetooth_hci_event_read_remote_version_information_complete::DESC;
    t[ProtoId::HCIEventCommandComplete.0 as usize] = &bluetooth_hci_event_command_complete::DESC;
    t[ProtoId::HCIEventCommandStatus.0 as usize] = &bluetooth_hci_event_command_status::DESC;
    t[ProtoId::HCIEventLinkKeyRequest.0 as usize] = &bluetooth_hci_event_link_key_request::DESC;
    t[ProtoId::HCIEventReadRemoteExtendedFeaturesComplete.0 as usize] =
        &bluetooth_hci_event_read_remote_extended_features_complete::DESC;
    t[ProtoId::HCIEventIOCapabilityResponse.0 as usize] =
        &bluetooth_hci_event_io_capability_response::DESC;
    t[ProtoId::HCIEventLEMeta.0 as usize] = &bluetooth_hci_event_le_meta::DESC;
    t[ProtoId::HCICmdCompleteReadLocalName.0 as usize] =
        &bluetooth_hci_cmd_complete_read_local_name::DESC;
    t[ProtoId::HCICmdCompleteReadLocalVersionInformation.0 as usize] =
        &bluetooth_hci_cmd_complete_read_local_version_information::DESC;
    t[ProtoId::HCICmdCompleteReadLocalExtendedFeatures.0 as usize] =
        &bluetooth_hci_cmd_complete_read_local_extended_features::DESC;
    t[ProtoId::HCICmdCompleteReadBDAddr.0 as usize] =
        &bluetooth_hci_cmd_complete_read_bd_addr::DESC;
    t[ProtoId::HCICmdCompleteLEReadWhiteListSize.0 as usize] =
        &bluetooth_hci_cmd_complete_le_read_white_list_size::DESC;
    t[ProtoId::HCILEMetaConnectionComplete.0 as usize] =
        &bluetooth_hci_le_meta_connection_complete::DESC;
    t[ProtoId::HCILEMetaEnhancedConnectionComplete.0 as usize] =
        &bluetooth_hci_le_meta_enhanced_connection_complete::DESC;
    t[ProtoId::HCILEMetaConnectionUpdateComplete.0 as usize] =
        &bluetooth_hci_le_meta_connection_update_complete::DESC;
    t[ProtoId::HCILEMetaLEReadRemoteFeaturesComplete.0 as usize] =
        &bluetooth_hci_le_meta_le_read_remote_features_complete::DESC;
    t[ProtoId::HCILEMetaLongTermKeyRequest.0 as usize] =
        &bluetooth_hci_le_meta_long_term_key_request::DESC;
    t[ProtoId::HCIMonHdr.0 as usize] = &bluetooth_hci_mon_hdr::DESC;
    t[ProtoId::HCIMonPcapHdr.0 as usize] = &bluetooth_hci_mon_pcap_hdr::DESC;
    t[ProtoId::HCIMonNewIndex.0 as usize] = &bluetooth_hci_mon_new_index::DESC;
    t[ProtoId::HCIMonIndexInfo.0 as usize] = &bluetooth_hci_mon_index_info::DESC;
    t[ProtoId::BTLEDATA.0 as usize] = &bluetooth4le_btle_data::DESC;
    t[ProtoId::BTLEADVDIRECTIND.0 as usize] = &bluetooth4le_btle_adv_direct_ind::DESC;
    t[ProtoId::BTLESCANREQ.0 as usize] = &bluetooth4le_btle_scan_req::DESC;
    t[ProtoId::BTLECONNECTREQ.0 as usize] = &bluetooth4le_btle_connect_req::DESC;
    t[ProtoId::BTLEEMPTYPDU.0 as usize] = &bluetooth4le_btle_empty_pdu::DESC;
    t[ProtoId::BTLECTRL.0 as usize] = &bluetooth4le_btle_ctrl::DESC;
    t[ProtoId::LLCONNECTIONUPDATEIND.0 as usize] = &bluetooth4le_ll_connection_update_ind::DESC;
    t[ProtoId::LLCHANNELMAPIND.0 as usize] = &bluetooth4le_ll_channel_map_ind::DESC;
    t[ProtoId::LLTERMINATEIND.0 as usize] = &bluetooth4le_ll_terminate_ind::DESC;
    t[ProtoId::LLENCREQ.0 as usize] = &bluetooth4le_ll_enc_req::DESC;
    t[ProtoId::LLENCRSP.0 as usize] = &bluetooth4le_ll_enc_rsp::DESC;
    t[ProtoId::LLSTARTENCREQ.0 as usize] = &bluetooth4le_ll_start_enc_req::DESC;
    t[ProtoId::LLSTARTENCRSP.0 as usize] = &bluetooth4le_ll_start_enc_rsp::DESC;
    t[ProtoId::LLUNKNOWNRSP.0 as usize] = &bluetooth4le_ll_unknown_rsp::DESC;
    t[ProtoId::LLFEATUREREQ.0 as usize] = &bluetooth4le_ll_feature_req::DESC;
    t[ProtoId::LLFEATURERSP.0 as usize] = &bluetooth4le_ll_feature_rsp::DESC;
    t[ProtoId::LLPAUSEENCREQ.0 as usize] = &bluetooth4le_ll_pause_enc_req::DESC;
    t[ProtoId::LLPAUSEENCRSP.0 as usize] = &bluetooth4le_ll_pause_enc_rsp::DESC;
    t[ProtoId::LLVERSIONIND.0 as usize] = &bluetooth4le_ll_version_ind::DESC;
    t[ProtoId::LLREJECTIND.0 as usize] = &bluetooth4le_ll_reject_ind::DESC;
    t[ProtoId::LLSLAVEFEATUREREQ.0 as usize] = &bluetooth4le_ll_slave_feature_req::DESC;
    t[ProtoId::LLCONNECTIONPARAMREQ.0 as usize] = &bluetooth4le_ll_connection_param_req::DESC;
    t[ProtoId::LLCONNECTIONPARAMRSP.0 as usize] = &bluetooth4le_ll_connection_param_rsp::DESC;
    t[ProtoId::LLREJECTEXTIND.0 as usize] = &bluetooth4le_ll_reject_ext_ind::DESC;
    t[ProtoId::LLPINGREQ.0 as usize] = &bluetooth4le_ll_ping_req::DESC;
    t[ProtoId::LLPINGRSP.0 as usize] = &bluetooth4le_ll_ping_rsp::DESC;
    t[ProtoId::LLLENGTHREQ.0 as usize] = &bluetooth4le_ll_length_req::DESC;
    t[ProtoId::LLLENGTHRSP.0 as usize] = &bluetooth4le_ll_length_rsp::DESC;
    t[ProtoId::LLPHYREQ.0 as usize] = &bluetooth4le_ll_phy_req::DESC;
    t[ProtoId::LLPHYRSP.0 as usize] = &bluetooth4le_ll_phy_rsp::DESC;
    t[ProtoId::LLPHYUPDATEIND.0 as usize] = &bluetooth4le_ll_phy_update_ind::DESC;
    t[ProtoId::LLMINUSEDCHANNELSIND.0 as usize] = &bluetooth4le_ll_min_used_channels_ind::DESC;
    t[ProtoId::LLCTEREQ.0 as usize] = &bluetooth4le_ll_cte_req::DESC;
    t[ProtoId::LLCTERSP.0 as usize] = &bluetooth4le_ll_cte_rsp::DESC;
    t[ProtoId::LLCLOCKACCURACYREQ.0 as usize] = &bluetooth4le_ll_clock_accuracy_req::DESC;
    t[ProtoId::LLCLOCKACCURACYRSP.0 as usize] = &bluetooth4le_ll_clock_accuracy_rsp::DESC;
    t[ProtoId::LLCISREQ.0 as usize] = &bluetooth4le_ll_cis_req::DESC;
    t[ProtoId::LLCISRSP.0 as usize] = &bluetooth4le_ll_cis_rsp::DESC;
    t[ProtoId::LLCISIND.0 as usize] = &bluetooth4le_ll_cis_ind::DESC;
    t[ProtoId::LLCISTERMINATEIND.0 as usize] = &bluetooth4le_ll_cis_terminate_ind::DESC;
    t[ProtoId::LLSUBRATEREQ.0 as usize] = &bluetooth4le_ll_subrate_req::DESC;
    t[ProtoId::LLSUBRATEIND.0 as usize] = &bluetooth4le_ll_subrate_ind::DESC;
    t[ProtoId::LLCHANNELREPORTINGIND.0 as usize] = &bluetooth4le_ll_channel_reporting_ind::DESC;
    // protogen:desc end
    t
};

/// Sorted once, so a lookup over thousands of built-in layers is a binary
/// search rather than a scan; constructing a packet asks once per layer.
fn builtin_names() -> &'static [(&'static str, ProtoId)] {
    static INDEX: OnceLock<Vec<(&'static str, ProtoId)>> = OnceLock::new();
    INDEX.get_or_init(|| {
        let mut v: Vec<_> = BUILTINS.iter().map(|p| (desc(*p).name, *p)).collect();
        v.sort_by(|a, b| a.0.cmp(b.0));
        v
    })
}

pub fn by_name(name: &str) -> Option<ProtoId> {
    let idx = builtin_names();
    if let Ok(i) = idx.binary_search_by(|(n, _)| (*n).cmp(name)) {
        return Some(idx[i].1);
    }
    // Newest first, so redefining a layer shadows the earlier one.
    registered().rev().find(|d| d.name == name).map(|d| d.id)
}

pub fn known_layers() -> Vec<&'static str> {
    let mut out: Vec<&'static str> = BUILTINS.iter().map(|p| desc(*p).name).collect();
    out.extend(registered().map(|d| d.name));
    out
}

/// Octets of framing a `child` carries when it sits directly under `parent`.
/// RFC 1035 §4.2.2 prefixes a DNS message with its own length over a stream;
/// those two octets belong to neither header alone, so the pair decides. The
/// dissector counts them into the child's header, ahead of every field.
#[inline]
pub fn framing_octets(parent: ProtoId, child: ProtoId) -> usize {
    match (parent, child) {
        (ProtoId::Tcp, ProtoId::Dns) => 2,
        _ => 0,
    }
}

/// Framing moves every field, which a condition cannot express, so it is a
/// second table rather than a second set of conditions.
#[inline]
pub fn fields_of(id: ProtoId, framed: bool) -> &'static [FieldDesc] {
    match (id, framed) {
        (ProtoId::Dns, true) => crate::layers::dns::TCP_FIELDS,
        _ => desc(id).fields,
    }
}

/// Empty for a layer that takes the same layout either way, so the callers below
/// do not walk one table twice.
fn framed_only(id: ProtoId) -> &'static [FieldDesc] {
    let framed = fields_of(id, true);
    if std::ptr::eq(framed, desc(id).fields) {
        &[]
    } else {
        framed
    }
}

/// Ignores conditions and framing, so it sees every field the protocol can ever
/// carry. The descriptor answers questions about the *name* — its kind, width,
/// flags, whether it is computed or conditional. It must not be decoded through:
/// where a layer has two layouts the offsets are only right for one of them, so
/// a read goes via `Packet::active_field`, which knows which layout this packet
/// took.
pub fn field_of(id: ProtoId, name: &str) -> Option<&'static FieldDesc> {
    desc(id)
        .fields
        .iter()
        .chain(framed_only(id))
        .find(|f| f.name == name)
}

pub fn all_field_names(id: ProtoId) -> Vec<&'static str> {
    let mut out: Vec<&'static str> = desc(id).fields.iter().map(|f| f.name).collect();
    for f in framed_only(id) {
        if !out.contains(&f.name) {
            out.push(f.name);
        }
    }
    out
}

pub fn active_fields(
    id: ProtoId,
    framed: bool,
    hdr: &[u8],
) -> impl Iterator<Item = &'static FieldDesc> + '_ {
    fields_of(id, framed)
        .iter()
        .filter(move |f| f.is_active(hdr))
}

/// Two fields may share a name when their conditions are disjoint; the header
/// bytes pick between them.
pub fn active_field_of(
    id: ProtoId,
    framed: bool,
    hdr: &[u8],
    name: &str,
) -> Option<&'static FieldDesc> {
    active_fields(id, framed, hdr).find(|f| f.name == name)
}

/// Names served by a parser rather than by the flat field table.
pub fn accessor_names(id: ProtoId) -> &'static [&'static str] {
    match id {
        // RFC 1035 §4.1
        ProtoId::Dns => &["qd", "an", "ns", "ar"],
        // protogen:accessors begin
        // protogen:accessors end
        _ => &[],
    }
}

/// The repeating group a protocol's payload is, where its payload is one. A
/// generated match rather than a `ProtoDesc` field, since ninety layers carry
/// no group.
#[inline]
// The arms are generated, so a spec set that declares no group at all still
// has to compile.
#[allow(clippy::match_single_binding)]
pub fn group_of(id: ProtoId) -> Option<&'static crate::repeat::GroupDesc> {
    match id {
        // protogen:groups begin
        ProtoId::Igmp => Some(&crate::layers::igmp::GROUP),
        ProtoId::Icmpv6MlQuery => Some(&crate::layers::mld_query::GROUP),
        ProtoId::Icmpv6MlReport2 => Some(&crate::layers::mld_report2::GROUP),
        ProtoId::Rip => Some(&crate::layers::rip::GROUP),
        ProtoId::Vrrp => Some(&crate::layers::vrrp::GROUP),
        ProtoId::Rtp => Some(&crate::layers::rtp::GROUP),
        ProtoId::NetflowV5 => Some(&crate::layers::netflow5::GROUP),
        ProtoId::NetflowV9 => Some(&crate::layers::netflow9::GROUP),
        ProtoId::Ipfix => Some(&crate::layers::ipfix::GROUP),
        ProtoId::SFlow => Some(&crate::layers::sflow::GROUP),
        ProtoId::OspfHello => Some(&crate::layers::ospf_hello::GROUP),
        ProtoId::OspfDbDesc => Some(&crate::layers::ospf_dbdesc::GROUP),
        ProtoId::OspfLsReq => Some(&crate::layers::ospf_lsreq::GROUP),
        ProtoId::OspfLsUpd => Some(&crate::layers::ospf_lsupd::GROUP),
        ProtoId::OspfLsAck => Some(&crate::layers::ospf_lsack::GROUP),
        ProtoId::BgpOpen => Some(&crate::layers::bgp_open::GROUP),
        ProtoId::PPPoEDTags => Some(&crate::layers::ppp_pppoed_tags::GROUP),
        ProtoId::ATTFindByTypeValueResponse => {
            Some(&crate::layers::bluetooth_att_find_by_type_value_response::GROUP)
        }
        ProtoId::ATTReadMultipleRequest => {
            Some(&crate::layers::bluetooth_att_read_multiple_request::GROUP)
        }
        ProtoId::ATTReadMultipleVariableRequest => {
            Some(&crate::layers::bluetooth_att_read_multiple_variable_request::GROUP)
        }
        ProtoId::HCICmdLESetExtendedAdvertiseEnable => {
            Some(&crate::layers::bluetooth_hci_cmd_le_set_extended_advertise_enable::GROUP)
        }
        // protogen:groups end
        _ => None,
    }
}

/// The header field a group's extent reads, by name, so a caller can tell a
/// count the user wrote from one the region should supply. `None` where the
/// elements simply run to the end.
pub fn group_extent_field(id: ProtoId) -> Option<&'static str> {
    use crate::repeat::Extent;
    let (off, len) = match group_of(id)?.extent {
        Extent::Count { bit_off, bit_len } => (bit_off, bit_len),
        Extent::Length {
            bit_off, bit_len, ..
        } => (bit_off, bit_len),
        Extent::Rest => return None,
    };
    desc(id)
        .fields
        .iter()
        .find(|f| f.bit_off == off && f.bit_len == len)
        .map(|f| f.name)
}

/// Whether a layer answers its parsed field with an item list at all, by either
/// route: an option region or a repeating group.
#[inline]
pub fn has_parsed_items(id: ProtoId) -> bool {
    desc(id).parse_options.is_some() || group_of(id).is_some()
}

/// A field that holds the octets after its own header plus a constant, which
/// is what scapy's `LenField` and most of its length-writing `post_build`s
/// compute. Recomputed on build unless the user assigned it.
#[inline]
#[allow(clippy::match_single_binding)]
pub fn payload_len_of(id: ProtoId) -> Option<(&'static str, i64)> {
    match id {
        // protogen:payload_len begin
        ProtoId::HCIACLHdr => Some(("len", 0)),
        ProtoId::L2CAPHdr => Some(("len", 0)),
        ProtoId::L2CAPCmdHdr => Some(("len", 0)),
        ProtoId::HCICommandHdr => Some(("len", 0)),
        ProtoId::HCIEventHdr => Some(("len", 0)),
        ProtoId::BTLEDATA => Some(("len", 0)),
        // protogen:payload_len end
        _ => None,
    }
}

/// The field a protocol's `parse_options` answers for. Line-oriented and
/// BER-encoded layers reuse the same parsed-item shape under their own name,
/// so `pkt[HTTP].headers` reads as `pkt[TCP].options` does.
pub fn parsed_field_name(id: ProtoId) -> &'static str {
    match id {
        // protogen:parsed begin
        ProtoId::Lldp => "options",
        ProtoId::Cdp => "msg",
        ProtoId::Igmp => "records",
        ProtoId::Icmpv6MlQuery => "sources",
        ProtoId::Icmpv6MlReport2 => "records",
        ProtoId::Rip => "entries",
        ProtoId::Vrrp => "addrlist",
        ProtoId::Snmp => "vars",
        ProtoId::Syslog => "headers",
        ProtoId::Rtp => "sync",
        ProtoId::NetflowV5 => "records",
        ProtoId::NetflowV9 => "flowsets",
        ProtoId::Ipfix => "sets",
        ProtoId::SFlow => "samples",
        ProtoId::Http => "headers",
        ProtoId::Ldap => "vars",
        ProtoId::Sip => "headers",
        ProtoId::Ftp => "lines",
        ProtoId::Smtp => "lines",
        ProtoId::Imap => "lines",
        ProtoId::Telnet => "lines",
        ProtoId::OspfHello => "neighbors",
        ProtoId::OspfDbDesc => "lsaheaders",
        ProtoId::OspfLsReq => "requests",
        ProtoId::OspfLsUpd => "lsalist",
        ProtoId::OspfLsAck => "lsaheaders",
        ProtoId::BgpOpen => "opt_params",
        ProtoId::BgpUpdate => "body",
        ProtoId::PPPoEDTags => "tag_list",
        ProtoId::ATTFindByTypeValueResponse => "handles",
        ProtoId::ATTReadMultipleRequest => "handles",
        ProtoId::ATTReadMultipleVariableRequest => "handles",
        ProtoId::HCICmdLESetExtendedAdvertiseEnable => "sets",
        // protogen:parsed end
        _ => "options",
    }
}

/// Registration happens once per Python class definition and is never undone,
/// so the owned data is leaked for the `'static` lifetimes `ProtoDesc` wants.
const MAX_REGISTERED: usize = 1024;

#[allow(clippy::declare_interior_mutable_const)]
const NO_DESC: OnceLock<&'static ProtoDesc> = OnceLock::new();
static REGISTRY: [OnceLock<&'static ProtoDesc>; MAX_REGISTERED] = [NO_DESC; MAX_REGISTERED];
static REGISTERED: AtomicUsize = AtomicUsize::new(0);

fn registered_desc(id: ProtoId) -> &'static ProtoDesc {
    REGISTRY
        .get((id.0 - BUILTIN_COUNT) as usize)
        .and_then(|slot| slot.get())
        .copied()
        .unwrap_or(&crate::layers::raw::DESC)
}

fn registered() -> impl DoubleEndedIterator<Item = &'static ProtoDesc> {
    let n = REGISTERED.load(Ordering::Acquire).min(MAX_REGISTERED);
    REGISTRY[..n].iter().filter_map(|slot| slot.get().copied())
}

/// `dissect_spans` raises this to `min_len`, so a header of one fixed width
/// needs no function of its own.
pub fn fixed_len(_: &[u8]) -> usize {
    0
}

/// A trailing `VarBytes` field runs to the end of the packet.
fn rest_len(hdr: &[u8]) -> usize {
    hdr.len()
}

pub fn raw_next(_: &[u8]) -> Next {
    Next::Raw
}

/// A tunnel whose payload is a whole frame, whatever its own header said.
pub fn frame_next(_: &[u8]) -> Next {
    Next::Proto(ProtoId::Ether)
}

/// `build_len` is the width of the fixed part in bytes.
pub fn register(
    name: String,
    mut fields: Vec<FieldDesc>,
    build_len: usize,
) -> Result<ProtoId, String> {
    if name.is_empty() {
        return Err("layer name must not be empty".into());
    }
    if BUILTINS.iter().any(|p| desc(*p).name == name) {
        return Err(format!(
            "{name} is a built-in layer and cannot be redefined"
        ));
    }
    let slot = REGISTERED.fetch_add(1, Ordering::AcqRel);
    if slot >= MAX_REGISTERED {
        REGISTERED.store(MAX_REGISTERED, Ordering::Release);
        return Err(format!(
            "no room for more than {MAX_REGISTERED} custom layers"
        ));
    }
    let var_tail = fields.last().is_some_and(|f| f.kind == FieldKind::VarBytes);
    if var_tail {
        fields.last_mut().unwrap().to_end = true;
    }
    let d: &'static ProtoDesc = Box::leak(Box::new(ProtoDesc {
        id: ProtoId(BUILTIN_COUNT + slot as u16),
        name: Box::leak(name.into_boxed_str()),
        fields: Box::leak(fields.into_boxed_slice()),
        min_len: build_len,
        header_len: if var_tail { rest_len } else { fixed_len },
        next: raw_next,
        build_len,
        parse_options: None,
        opt_table: None,
        set_hlen: None,
        bind_next: None,
        bind_next_bytes: None,
        content_len: None,
    }));
    let _ = REGISTRY[slot].set(d);
    Ok(d.id)
}

/// When every condition holds in the parent's header, `child` follows it.
struct Bind {
    parent: ProtoId,
    child: ProtoId,
    conds: &'static [(&'static FieldDesc, u64)],
}

const MAX_BINDS: usize = 1024;

#[allow(clippy::declare_interior_mutable_const)]
const NO_BIND: OnceLock<Bind> = OnceLock::new();
static BINDS: [OnceLock<Bind>; MAX_BINDS] = [NO_BIND; MAX_BINDS];
static BOUND: AtomicUsize = AtomicUsize::new(0);
/// Which protocols appear as a parent, so a layer nobody bound under skips the
/// search. Ids past 64 share a bit: a fruitless search, never a missed binding.
static BOUND_PARENTS: AtomicU64 = AtomicU64::new(0);

#[inline]
fn parent_bit(p: ProtoId) -> u64 {
    1u64 << (p.0 % 64)
}

pub fn bind(
    parent: ProtoId,
    child: ProtoId,
    conds: Vec<(&'static FieldDesc, u64)>,
) -> Result<(), String> {
    let slot = BOUND.fetch_add(1, Ordering::AcqRel);
    if slot >= MAX_BINDS {
        BOUND.store(MAX_BINDS, Ordering::Release);
        return Err(format!("no room for more than {MAX_BINDS} layer bindings"));
    }
    let _ = BINDS[slot].set(Bind {
        parent,
        child,
        conds: Box::leak(conds.into_boxed_slice()),
    });
    BOUND_PARENTS.fetch_or(parent_bit(parent), Ordering::Release);
    Ok(())
}

fn binds() -> impl Iterator<Item = &'static Bind> {
    let n = BOUND.load(Ordering::Acquire).min(MAX_BINDS);
    BINDS[..n].iter().filter_map(|slot| slot.get())
}

/// The search is kept out of line, so a layer nothing was bound under pays one
/// relaxed load and a branch.
#[inline]
pub fn bound_next(parent: ProtoId, hdr: &[u8]) -> Option<ProtoId> {
    if BOUND_PARENTS.load(Ordering::Relaxed) & parent_bit(parent) == 0 {
        return None;
    }
    search_binds(parent, hdr)
}

#[inline(never)]
fn search_binds(parent: ProtoId, hdr: &[u8]) -> Option<ProtoId> {
    binds()
        .find(|b| b.parent == parent && b.conds.iter().all(|(f, v)| field::read_uint(hdr, f) == *v))
        .map(|b| b.child)
}

/// The reverse of `bound_next`: writes back the values that make dissection
/// find `child` again.
#[inline]
pub fn apply_bind(hdr: &mut [u8], parent: ProtoId, child: ProtoId) {
    if BOUND_PARENTS.load(Ordering::Relaxed) & parent_bit(parent) == 0 {
        return;
    }
    write_bind(hdr, parent, child);
}

#[inline(never)]
fn write_bind(hdr: &mut [u8], parent: ProtoId, child: ProtoId) {
    if let Some(b) = binds().find(|b| b.parent == parent && b.child == child) {
        for (f, v) in b.conds {
            field::write_uint(hdr, f, *v);
        }
    }
}

/// IANA "ETHER TYPES" registry.
pub mod ethertype {
    pub const IPV4: u16 = 0x0800;
    pub const ARP: u16 = 0x0806;
    pub const DOT1Q: u16 = 0x8100;
    pub const IPV6: u16 = 0x86DD;
    /// Loopback; carries no payload, so it is the default for a frame with
    /// nothing stacked under it.
    pub const LOOP: u16 = 0x9000;
    /// RFC 1701 §3: Transparent Ethernet Bridging, how a tunnel says its
    /// payload is a whole frame rather than a datagram.
    pub const TEB: u16 = 0x6558;
    pub const PPP_LINK: u16 = 0x880B;
    pub const MPLS_UNICAST: u16 = 0x8847;
    pub const MPLS_MULTICAST: u16 = 0x8848;
    pub const PPPOE_DISCOVERY: u16 = 0x8863;
    pub const PPPOE_SESSION: u16 = 0x8864;
    pub const ERSPAN_II: u16 = 0x88BE;
    pub const ERSPAN_III: u16 = 0x22EB;
}

/// IANA "Protocol Numbers" registry.
pub mod ipproto {
    pub const ICMP: u8 = 1;
    pub const TCP: u8 = 6;
    pub const UDP: u8 = 17;
    pub const IPV6_ICMP: u8 = 58;
    /// RFC 8200 §4: the extension headers this build walks.
    pub const HOPOPT: u8 = 0;
    pub const IPV6_ROUTE: u8 = 43;
    pub const IPV6_FRAG: u8 = 44;
    pub const IPV6_OPTS: u8 = 60;
    /// RFC 2003 §3 and RFC 4213 §3: an IP datagram as the payload of another.
    pub const IPV4: u8 = 4;
    pub const IPV6: u8 = 41;
    pub const GRE: u8 = 47;
}

pub mod ports {
    pub const DNS: u16 = 53;
    /// RFC 6762 §18.
    pub const MDNS: u16 = 5353;
    /// RFC 4795 §2.
    pub const LLMNR: u16 = 5355;
    pub const BOOTPS: u16 = 67;
    pub const BOOTPC: u16 = 68;
    pub const GTP_U: u16 = 2152;
    pub const VXLAN: u16 = 4789;
    pub const GENEVE: u16 = 6081;
    /// RFC 8086 §3: GRE over UDP.
    pub const GRE_UDP: u16 = 4754;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn uint(name: &'static str, off: u16, len: u16) -> FieldDesc {
        FieldDesc::uint(name, off, len, 0)
    }

    #[test]
    fn builtin_ids_keep_their_numbering() {
        assert_eq!(ProtoId::Raw.0, 0);
        assert_eq!(ProtoId::Tcp.0, 7);
        assert_eq!(desc(ProtoId::Tcp).name, "TCP");
        // The numbering is append-only and may have gaps; what has to hold is
        // that every built-in stays below the count that separates the static
        // table from the registry.
        assert!(BUILTINS.iter().all(|p| p.0 < BUILTIN_COUNT));
        assert!(BUILTINS.iter().all(|p| !p.is_registered()));
    }

    /// The id list, `BUILTINS` and the dispatch match are three hand-kept
    /// tables: an id missing from any of them fails silently, as `Raw` or as a
    /// layer `by_name` cannot see.
    #[test]
    fn every_builtin_id_is_listed_and_dispatched() {
        for id in builtins() {
            let d = desc(id);
            assert_eq!(d.id, id, "{} dispatches to {}", id.0, d.name);
            assert!(BUILTINS.contains(&id), "{} missing from BUILTINS", d.name);
            assert_eq!(by_name(d.name), Some(id), "{} not found by name", d.name);
        }
        assert!(BUILTINS.len() <= BUILTIN_COUNT as usize);
    }

    /// `BUILTIN_DESCS` is indexed by id, so the numbering's gaps are slots no
    /// spec fills. They have to read what the match's `_` arm gave them, and an
    /// id past the count still has to reach the registry rather than the array.
    #[test]
    fn an_unfilled_id_reads_raw_and_one_past_the_count_reaches_the_registry() {
        for id in (0..BUILTIN_COUNT).map(ProtoId) {
            if BUILTINS.contains(&id) {
                continue;
            }
            assert_eq!(desc(id).name, "Raw", "id {} is a gap that is not Raw", id.0);
        }
        // Not BUILTIN_COUNT itself: that is the first registry slot, and the
        // registry is process-global and append-only, so another test's
        // registration owns it in a whole-suite run but not a filtered one.
        for n in [BUILTIN_COUNT + 500, u16::MAX] {
            assert_eq!(desc(ProtoId(n)).name, "Raw", "id {n}");
        }
        let id = register("GapDemo".into(), vec![uint("a", 0, 8)], 1).unwrap();
        assert!(id.is_registered());
        assert_eq!(desc(id).name, "GapDemo");
    }

    #[test]
    fn registration_round_trips_through_name_and_desc() {
        let id = register("RegDemo".into(), vec![uint("a", 0, 8), uint("b", 8, 16)], 3).unwrap();
        assert!(id.is_registered());
        assert_eq!(desc(id).name, "RegDemo");
        assert_eq!(desc(id).build_len, 3);
        assert_eq!(desc(id).min_len, 3);
        assert_eq!(by_name("RegDemo"), Some(id));
        assert!(known_layers().contains(&"RegDemo"));
        assert_eq!(field_of(id, "b").unwrap().bit_len, 16);
    }

    #[test]
    fn a_builtin_name_cannot_be_redefined() {
        assert!(register("TCP".into(), vec![], 0).is_err());
        assert!(register(String::new(), vec![], 0).is_err());
    }

    #[test]
    fn an_unknown_id_falls_back_to_raw_rather_than_panicking() {
        assert_eq!(desc(ProtoId(60000)).name, "Raw");
    }

    #[test]
    fn a_trailing_var_field_makes_the_header_run_to_the_end() {
        let id = register(
            "RegVar".into(),
            vec![uint("a", 0, 8), FieldDesc::var_bytes("data", 8)],
            1,
        )
        .unwrap();
        assert_eq!((desc(id).header_len)(&[1, 2, 3, 4]), 4);
        let plain = register("RegPlain".into(), vec![uint("a", 0, 8)], 1).unwrap();
        assert_eq!((desc(plain).header_len)(&[1, 2, 3, 4]), 0);
    }

    #[test]
    fn a_binding_matches_only_when_every_condition_holds() {
        let id = register("RegBound".into(), vec![uint("a", 0, 8)], 1).unwrap();
        let sport = field_of(ProtoId::Udp, "sport").unwrap();
        let dport = field_of(ProtoId::Udp, "dport").unwrap();
        bind(ProtoId::Udp, id, vec![(sport, 1111), (dport, 2222)]).unwrap();

        let mut hdr = [0u8; 8];
        assert_eq!(bound_next(ProtoId::Udp, &hdr), None);
        hdr[0..2].copy_from_slice(&1111u16.to_be_bytes());
        assert_eq!(bound_next(ProtoId::Udp, &hdr), None);
        hdr[2..4].copy_from_slice(&2222u16.to_be_bytes());
        assert_eq!(bound_next(ProtoId::Udp, &hdr), Some(id));
        assert_eq!(bound_next(ProtoId::Tcp, &hdr), None);

        let mut back = [0u8; 8];
        apply_bind(&mut back, ProtoId::Udp, id);
        assert_eq!(&back[..4], &hdr[..4]);
    }

    /// Every pair that contributes framing, and every layer that therefore has
    /// a second field table. A layer added without an entry here takes the same
    /// layout under every parent, which is what makes framing invisible to an
    /// author who does not want it — and adding one has to be deliberate.
    const FRAMED: &[(ProtoId, ProtoId)] = &[(ProtoId::Tcp, ProtoId::Dns)];

    #[test]
    fn only_a_declared_pair_carries_framing() {
        for p in (0..BUILTIN_COUNT).map(ProtoId) {
            for c in (0..BUILTIN_COUNT).map(ProtoId) {
                let n = framing_octets(p, c);
                assert_eq!(
                    n > 0,
                    FRAMED.contains(&(p, c)),
                    "{}/{} framing is {n}, which the list does not declare",
                    p.name(),
                    c.name()
                );
            }
        }
        for id in (0..BUILTIN_COUNT).map(ProtoId) {
            let framed = FRAMED.iter().any(|(_, c)| *c == id);
            assert_eq!(
                framed,
                !framed_only(id).is_empty(),
                "{} has a second field table without a pair that reaches it, or the reverse",
                id.name()
            );
        }
    }

    /// A second table shifts the first, so it must still name everything the
    /// first does: a name readable under one parent and missing under another
    /// would be a layout that silently lost a field.
    #[test]
    fn a_framed_table_names_everything_the_plain_one_does() {
        for id in (0..BUILTIN_COUNT).map(ProtoId) {
            let extra = framed_only(id);
            if extra.is_empty() {
                continue;
            }
            for f in desc(id).fields {
                assert!(
                    extra.iter().any(|g| g.name == f.name),
                    "{}.{} is missing from the framed table",
                    id.name(),
                    f.name
                );
            }
        }
    }

    /// A condition is a closure over raw header offsets, and the header a framed
    /// layer is read from starts at the framing, not at the first field. Shifting
    /// the offsets in a second table therefore does not shift its conditions, so
    /// the two cannot be combined until a condition is told where the fields
    /// begin.
    #[test]
    fn no_framed_table_declares_a_conditional_field() {
        for id in (0..BUILTIN_COUNT).map(ProtoId) {
            for f in framed_only(id) {
                assert!(
                    f.cond.is_none(),
                    "{}.{} is conditional in a framed table, where its predicate \
                     would read the framing octets as the first header bytes",
                    id.name(),
                    f.name
                );
            }
        }
    }
}
