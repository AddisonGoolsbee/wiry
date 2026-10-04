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
    pub const HCIPHDRHdr: ProtoId = ProtoId(1000);
    pub const HCIHdr: ProtoId = ProtoId(1001);
    pub const L2CAPConnReq: ProtoId = ProtoId(1005);
    pub const L2CAPConnResp: ProtoId = ProtoId(1006);
    pub const L2CAPCmdRej: ProtoId = ProtoId(1007);
    pub const L2CAPConfReq: ProtoId = ProtoId(1008);
    pub const L2CAPConfResp: ProtoId = ProtoId(1009);
    pub const L2CAPDisconnReq: ProtoId = ProtoId(1010);
    pub const L2CAPDisconnResp: ProtoId = ProtoId(1011);
    pub const L2CAPEchoReq: ProtoId = ProtoId(1012);
    pub const L2CAPEchoResp: ProtoId = ProtoId(1013);
    pub const L2CAPInfoReq: ProtoId = ProtoId(1014);
    pub const L2CAPInfoResp: ProtoId = ProtoId(1015);
    pub const L2CAPCreateChannelRequest: ProtoId = ProtoId(1016);
    pub const L2CAPCreateChannelResponse: ProtoId = ProtoId(1017);
    pub const L2CAPMoveChannelRequest: ProtoId = ProtoId(1018);
    pub const L2CAPMoveChannelResponse: ProtoId = ProtoId(1019);
    pub const L2CAPMoveChannelConfirmationRequest: ProtoId = ProtoId(1020);
    pub const L2CAPMoveChannelConfirmationResponse: ProtoId = ProtoId(1021);
    pub const L2CAPConnectionParameterUpdateRequest: ProtoId = ProtoId(1022);
    pub const L2CAPConnectionParameterUpdateResponse: ProtoId = ProtoId(1023);
    pub const L2CAPLECreditBasedConnectionRequest: ProtoId = ProtoId(1024);
    pub const L2CAPLECreditBasedConnectionResponse: ProtoId = ProtoId(1025);
    pub const L2CAPFlowControlCreditInd: ProtoId = ProtoId(1026);
    pub const L2CAPCreditBasedConnectionRequest: ProtoId = ProtoId(1027);
    pub const L2CAPCreditBasedConnectionResponse: ProtoId = ProtoId(1028);
    pub const L2CAPCreditBasedReconfigureRequest: ProtoId = ProtoId(1029);
    pub const L2CAPCreditBasedReconfigureResponse: ProtoId = ProtoId(1030);
    pub const ATTHdr: ProtoId = ProtoId(1031);
    pub const ATTHandle: ProtoId = ProtoId(1032);
    pub const ATTErrorResponse: ProtoId = ProtoId(1034);
    pub const ATTExchangeMTURequest: ProtoId = ProtoId(1035);
    pub const ATTExchangeMTUResponse: ProtoId = ProtoId(1036);
    pub const ATTFindInformationRequest: ProtoId = ProtoId(1037);
    pub const ATTFindByTypeValueRequest: ProtoId = ProtoId(1039);
    pub const ATTFindByTypeValueResponse: ProtoId = ProtoId(1040);
    pub const ATTReadByTypeRequest: ProtoId = ProtoId(1042);
    pub const ATTReadRequest: ProtoId = ProtoId(1045);
    pub const ATTReadResponse: ProtoId = ProtoId(1046);
    pub const ATTReadMultipleRequest: ProtoId = ProtoId(1047);
    pub const ATTReadMultipleResponse: ProtoId = ProtoId(1048);
    pub const ATTReadByGroupTypeRequest: ProtoId = ProtoId(1049);
    pub const ATTReadByGroupTypeResponse: ProtoId = ProtoId(1050);
    pub const ATTWriteRequest: ProtoId = ProtoId(1051);
    pub const ATTWriteCommand: ProtoId = ProtoId(1052);
    pub const ATTPrepareWriteRequest: ProtoId = ProtoId(1054);
    pub const ATTPrepareWriteResponse: ProtoId = ProtoId(1055);
    pub const ATTHandleValueNotification: ProtoId = ProtoId(1056);
    pub const ATTExecuteWriteRequest: ProtoId = ProtoId(1057);
    pub const ATTReadBlobRequest: ProtoId = ProtoId(1059);
    pub const ATTReadBlobResponse: ProtoId = ProtoId(1060);
    pub const ATTHandleValueIndication: ProtoId = ProtoId(1061);
    pub const SMHdr: ProtoId = ProtoId(1062);
    pub const SMPairingRequest: ProtoId = ProtoId(1063);
    pub const SMPairingResponse: ProtoId = ProtoId(1064);
    pub const SMConfirm: ProtoId = ProtoId(1065);
    pub const SMRandom: ProtoId = ProtoId(1066);
    pub const SMFailed: ProtoId = ProtoId(1067);
    pub const SMEncryptionInformation: ProtoId = ProtoId(1068);
    pub const SMMasterIdentification: ProtoId = ProtoId(1069);
    pub const SMIdentityInformation: ProtoId = ProtoId(1070);
    pub const SMSigningInformation: ProtoId = ProtoId(1072);
    pub const SMSecurityRequest: ProtoId = ProtoId(1073);
    pub const SMPublicKey: ProtoId = ProtoId(1074);
    pub const SMDHKeyCheck: ProtoId = ProtoId(1075);
    pub const EIRFlags: ProtoId = ProtoId(1079);
    pub const EIRSecurityManagerOOBFlags: ProtoId = ProtoId(1092);
    pub const EIRPeripheralConnectionIntervalRange: ProtoId = ProtoId(1093);
    pub const EIRDeviceID: ProtoId = ProtoId(1095);
    pub const HCICmdInquiry: ProtoId = ProtoId(1108);
    pub const HCICmdPeriodicInquiryMode: ProtoId = ProtoId(1110);
    pub const HCICmdDisconnect: ProtoId = ProtoId(1113);
    pub const HCICmdChangeConnectionPacketType: ProtoId = ProtoId(1121);
    pub const HCICmdAuthenticationRequested: ProtoId = ProtoId(1122);
    pub const HCICmdSetConnectionEncryption: ProtoId = ProtoId(1123);
    pub const HCICmdChangeConnectionLinkKey: ProtoId = ProtoId(1124);
    pub const HCICmdLinkKeySelection: ProtoId = ProtoId(1125);
    pub const HCICmdReadRemoteSupportedFeatures: ProtoId = ProtoId(1128);
    pub const HCICmdReadRemoteExtendedFeatures: ProtoId = ProtoId(1129);
    pub const HCICmdHoldMode: ProtoId = ProtoId(1137);
    pub const HCICmdSetEventMask: ProtoId = ProtoId(1138);
    pub const HCICmdSetEventFilter: ProtoId = ProtoId(1140);
    pub const HCICmdWriteLocalName: ProtoId = ProtoId(1141);
    pub const HCICmdWriteConnectAcceptTimeout: ProtoId = ProtoId(1143);
    pub const HCICmdWriteLEHostSupport: ProtoId = ProtoId(1146);
    pub const HCICmdReadLocalExtendedFeatures: ProtoId = ProtoId(1148);
    pub const HCICmdReadLinkQuality: ProtoId = ProtoId(1150);
    pub const HCICmdReadRSSI: ProtoId = ProtoId(1151);
    pub const HCICmdWriteLoopbackMode: ProtoId = ProtoId(1153);
    pub const HCICmdLESetScanResponseData: ProtoId = ProtoId(1160);
    pub const HCICmdLESetAdvertiseEnable: ProtoId = ProtoId(1161);
    pub const HCICmdLESetScanParameters: ProtoId = ProtoId(1162);
    pub const HCICmdLESetScanEnable: ProtoId = ProtoId(1163);
    pub const HCICmdLEConnectionUpdate: ProtoId = ProtoId(1170);
    pub const HCICmdLEReadRemoteFeatures: ProtoId = ProtoId(1171);
    pub const HCICmdLEEnableEncryption: ProtoId = ProtoId(1172);
    pub const HCICmdLELongTermKeyRequestReply: ProtoId = ProtoId(1173);
    pub const HCICmdLELongTermKeyRequestNegativeReply: ProtoId = ProtoId(1174);
    pub const HCIEventInquiryComplete: ProtoId = ProtoId(1176);
    pub const HCIEventDisconnectionComplete: ProtoId = ProtoId(1179);
    pub const HCIEventEncryptionChange: ProtoId = ProtoId(1181);
    pub const HCIEventReadRemoteVersionInformationComplete: ProtoId = ProtoId(1183);
    pub const HCIEventCommandComplete: ProtoId = ProtoId(1184);
    pub const HCIEventCommandStatus: ProtoId = ProtoId(1185);
    pub const HCIEventReadRemoteExtendedFeaturesComplete: ProtoId = ProtoId(1189);
    pub const HCIEventLEMeta: ProtoId = ProtoId(1192);
    pub const HCICmdCompleteReadLocalName: ProtoId = ProtoId(1193);
    pub const HCICmdCompleteReadLocalVersionInformation: ProtoId = ProtoId(1194);
    pub const HCICmdCompleteReadLocalExtendedFeatures: ProtoId = ProtoId(1195);
    pub const HCICmdCompleteLEReadWhiteListSize: ProtoId = ProtoId(1197);
    pub const HCILEMetaConnectionUpdateComplete: ProtoId = ProtoId(1199);
    pub const HCILEMetaLongTermKeyRequest: ProtoId = ProtoId(1202);
    pub const HCIMonHdr: ProtoId = ProtoId(1205);
    pub const HCIMonPcapHdr: ProtoId = ProtoId(1206);
    pub const BTLECTRL: ProtoId = ProtoId(1223);
    pub const LLCONNECTIONUPDATEIND: ProtoId = ProtoId(1224);
    pub const LLTERMINATEIND: ProtoId = ProtoId(1226);
    pub const LLENCREQ: ProtoId = ProtoId(1227);
    pub const LLENCRSP: ProtoId = ProtoId(1228);
    pub const LLUNKNOWNRSP: ProtoId = ProtoId(1231);
    pub const LLVERSIONIND: ProtoId = ProtoId(1236);
    pub const LLREJECTIND: ProtoId = ProtoId(1237);
    pub const LLCONNECTIONPARAMREQ: ProtoId = ProtoId(1239);
    pub const LLCONNECTIONPARAMRSP: ProtoId = ProtoId(1240);
    pub const LLREJECTEXTIND: ProtoId = ProtoId(1241);
    pub const LLLENGTHREQ: ProtoId = ProtoId(1244);
    pub const LLLENGTHRSP: ProtoId = ProtoId(1245);
    pub const LLCLOCKACCURACYREQ: ProtoId = ProtoId(1253);
    pub const LLCLOCKACCURACYRSP: ProtoId = ProtoId(1254);
    pub const LLCISRSP: ProtoId = ProtoId(1256);
    pub const LLCISIND: ProtoId = ProtoId(1257);
    pub const LLCISTERMINATEIND: ProtoId = ProtoId(1258);
    pub const LLSUBRATEREQ: ProtoId = ProtoId(1262);
    pub const LLSUBRATEIND: ProtoId = ProtoId(1263);
    pub const LLCHANNELREPORTINGIND: ProtoId = ProtoId(1264);
    pub const DceRpcSecVTBitmask: ProtoId = ProtoId(1278);
    pub const DceRpcSecVTHeader2: ProtoId = ProtoId(1280);
    pub const DceRpc5Version: ProtoId = ProtoId(1290);
    pub const DceRpc5Auth3: ProtoId = ProtoId(1294);
    pub const NDRSerialization1Header: ProtoId = ProtoId(1307);
    pub const DUIDEN: ProtoId = ProtoId(1313);
    pub const DHCP6OptGeoConfElement: ProtoId = ProtoId(1354);
    pub const DHCP6NTPSubOptSrvAddr: ProtoId = ProtoId(1364);
    pub const DHCP6NTPSubOptMCAddr: ProtoId = ProtoId(1365);
    pub const EDNS0DAU: ProtoId = ProtoId(1400);
    pub const EDNS0DHU: ProtoId = ProtoId(1401);
    pub const EDNS0N3U: ProtoId = ProtoId(1402);
    pub const EDNS0COOKIE: ProtoId = ProtoId(1404);
    pub const EDNS0ExtendedDNSError: ProtoId = ProtoId(1405);
    pub const RSNCipherSuite: ProtoId = ProtoId(1438);
    pub const AKMSuite: ProtoId = ProtoId(1439);
    pub const Dot11EltCountryConstraintTriplet: ProtoId = ProtoId(1442);
    pub const Dot11VHTOperationInfo: ProtoId = ProtoId(1450);
    pub const Dot11Disas: ProtoId = ProtoId(1454);
    pub const Dot11ReassoReq: ProtoId = ProtoId(1457);
    pub const Dot11ReassoResp: ProtoId = ProtoId(1458);
    pub const Dot11Deauth: ProtoId = ProtoId(1462);
    pub const Dot11Action: ProtoId = ProtoId(1464);
    pub const Dot11WNM: ProtoId = ProtoId(1465);
    pub const SubelemTLV: ProtoId = ProtoId(1466);
    pub const BSSTerminationDuration: ProtoId = ProtoId(1467);
    pub const Dot11SpectrumManagement: ProtoId = ProtoId(1471);
    pub const Dot11S1GBeacon: ProtoId = ProtoId(1473);
    pub const Dot11CCMP: ProtoId = ProtoId(1477);
    pub const Dot15d4CmdCoordRealignPage: ProtoId = ProtoId(1486);
    pub const Dot15d4CmdAssocReq: ProtoId = ProtoId(1487);
    pub const Dot15d4CmdAssocResp: ProtoId = ProtoId(1488);
    pub const Dot15d4CmdDisassociation: ProtoId = ProtoId(1489);
    pub const Dot15d4CmdGTSReq: ProtoId = ProtoId(1490);
    pub const MKAPeerListTuple: ProtoId = ProtoId(1503);
    pub const MKASAKUseParamSet: ProtoId = ProtoId(1506);
    pub const MKADistributedCAKParamSet: ProtoId = ProtoId(1508);
    pub const MKAICVSet: ProtoId = ProtoId(1509);
    pub const GssBufferDesc: ProtoId = ProtoId(1514);
    pub const IPOptionHDR: ProtoId = ProtoId(1522);
    pub const IPOptionEOL: ProtoId = ProtoId(1524);
    pub const IPOptionNOP: ProtoId = ProtoId(1525);
    pub const IPOptionSecurity: ProtoId = ProtoId(1526);
    pub const IPOptionRR: ProtoId = ProtoId(1527);
    pub const IPOptionLSRR: ProtoId = ProtoId(1528);
    pub const IPOptionSSRR: ProtoId = ProtoId(1529);
    pub const IPOptionStreamId: ProtoId = ProtoId(1530);
    pub const IPOptionMTUProbe: ProtoId = ProtoId(1531);
    pub const IPOptionMTUReply: ProtoId = ProtoId(1532);
    pub const IPOptionTraceroute: ProtoId = ProtoId(1533);
    pub const IPOptionAddressExtension: ProtoId = ProtoId(1535);
    pub const IPOptionRouterAlert: ProtoId = ProtoId(1536);
    pub const IPOptionSDBM: ProtoId = ProtoId(1537);
    pub const PseudoIPv6: ProtoId = ProtoId(1553);
    pub const IPv6ExtHdrSegmentRoutingTLVIngressNode: ProtoId = ProtoId(1566);
    pub const IPv6ExtHdrSegmentRoutingTLVEgressNode: ProtoId = ProtoId(1567);
    pub const IPv6ExtHdrSegmentRoutingTLVPad1: ProtoId = ProtoId(1568);
    pub const IPv6ExtHdrSegmentRoutingTLVHMAC: ProtoId = ProtoId(1570);
    pub const MIP6OptBRAdvice: ProtoId = ProtoId(1636);
    pub const MIP6OptAltCoA: ProtoId = ProtoId(1637);
    pub const MIP6OptNonceIndices: ProtoId = ProtoId(1638);
    pub const MIP6OptMobNetPrefix: ProtoId = ProtoId(1640);
    pub const MIP6OptLLAddr: ProtoId = ProtoId(1641);
    pub const MIP6OptMNID: ProtoId = ProtoId(1642);
    pub const MIP6OptCGAParamsReq: ProtoId = ProtoId(1645);
    pub const MIP6OptCGAParams: ProtoId = ProtoId(1646);
    pub const MIP6OptSignature: ProtoId = ProtoId(1647);
    pub const MIP6OptHomeKeygenToken: ProtoId = ProtoId(1648);
    pub const MIP6OptCareOfTestInit: ProtoId = ProtoId(1649);
    pub const NONESP: ProtoId = ProtoId(1664);
    pub const NATKEEPALIVE: ProtoId = ProtoId(1665);
    pub const IrLAPHead: ProtoId = ProtoId(1667);
    pub const IrLAPCommand: ProtoId = ProtoId(1668);
    pub const IrLMP: ProtoId = ProtoId(1669);
    pub const KPasswdRepData: ProtoId = ProtoId(1780);
    pub const GRErouting: ProtoId = ProtoId(1794);
    pub const LoopbackOpenBSD: ProtoId = ProtoId(1798);
    pub const Dot1AH: ProtoId = ProtoId(1800);
    pub const LLTDHello: ProtoId = ProtoId(1853);
    pub const LLTDDiscover: ProtoId = ProtoId(1854);
    pub const LLTDEmiteeDesc: ProtoId = ProtoId(1855);
    pub const LLTDEmit: ProtoId = ProtoId(1856);
    pub const LLTDRecveeDesc: ProtoId = ProtoId(1857);
    pub const LLTDQueryLargeTlv: ProtoId = ProtoId(1859);
    pub const LLTDAttributeEOP: ProtoId = ProtoId(1862);
    pub const LLTDAttributeHostID: ProtoId = ProtoId(1863);
    pub const LLTDAttributeCharacteristics: ProtoId = ProtoId(1864);
    pub const LLTDAttributePhysicalMedium: ProtoId = ProtoId(1865);
    pub const LLTDAttributeIPv4Address: ProtoId = ProtoId(1866);
    pub const LLTDAttributeIPv6Address: ProtoId = ProtoId(1867);
    pub const LLTDAttribute80211MaxRate: ProtoId = ProtoId(1868);
    pub const LLTDAttributePerformanceCounterFrequency: ProtoId = ProtoId(1869);
    pub const LLTDAttributeLinkSpeed: ProtoId = ProtoId(1870);
    pub const LLTDAttributeLargeTLV: ProtoId = ProtoId(1871);
    pub const LLTDAttributeQOSCharacteristics: ProtoId = ProtoId(1874);
    pub const LLTDAttribute80211PhysicalMedium: ProtoId = ProtoId(1875);
    pub const LLTDAttributeSeesList: ProtoId = ProtoId(1876);
    pub const MobileIP: ProtoId = ProtoId(1878);
    pub const MobileIPRRQ: ProtoId = ProtoId(1879);
    pub const MobileIPRRP: ProtoId = ProtoId(1880);
    pub const MobileIPTunnelData: ProtoId = ProtoId(1881);
    pub const NRTPEndHeader: ProtoId = ProtoId(1884);
    pub const NRTPStatusCodeHeader: ProtoId = ProtoId(1886);
    pub const NRTPCloseConnectionHeader: ProtoId = ProtoId(1889);
    pub const ArrayInfo: ProtoId = ProtoId(1910);
    pub const NRBFArraySingleObject: ProtoId = ProtoId(1911);
    pub const NRBFMemberReference: ProtoId = ProtoId(1914);
    pub const NRBFObjectNull: ProtoId = ProtoId(1915);
    pub const NRBFMessageEnd: ProtoId = ProtoId(1919);
    pub const OctetStringT: ProtoId = ProtoId(1921);
    pub const PACINFOBUFFER: ProtoId = ProtoId(1951);
    pub const PACCREDENTIALINFO: ProtoId = ProtoId(1961);
    pub const NBNSHeader: ProtoId = ProtoId(2328);
    pub const NBNSADDENTRY: ProtoId = ProtoId(2330);
    pub const NBNSNodeStatusResponseService: ProtoId = ProtoId(2333);
    pub const NetflowHeader: ProtoId = ProtoId(2339);
    pub const NetflowRecordV1: ProtoId = ProtoId(2341);
    pub const NetflowRecordV5: ProtoId = ProtoId(2343);
    pub const NetflowRecordV9: ProtoId = ProtoId(2349);
    pub const NetflowOptionsRecordScopeV9: ProtoId = ProtoId(2351);
    pub const NetflowOptionsRecordOptionV9: ProtoId = ProtoId(2352);
    pub const NetflowOptionsFlowsetScopeV9: ProtoId = ProtoId(2354);
    pub const NTLMVersion: ProtoId = ProtoId(2360);
    pub const LMRESPONSE: ProtoId = ProtoId(2365);
    pub const LMv2RESPONSE: ProtoId = ProtoId(2366);
    pub const NTLMRESPONSE: ProtoId = ProtoId(2367);
    pub const NTLMSSPMESSAGESIGNATURE: ProtoId = ProtoId(2374);
    pub const NTPSystemStatusPacketX: ProtoId = ProtoId(2380);
    pub const NTPPeerStatusPacketX: ProtoId = ProtoId(2381);
    pub const NTPClockStatusPacketX: ProtoId = ProtoId(2382);
    pub const NTPErrorStatusPacketX: ProtoId = ProtoId(2383);
    pub const NTPInfoPeerListX: ProtoId = ProtoId(2386);
    pub const NTPInfoPeerStatsX: ProtoId = ProtoId(2389);
    pub const NTPInfoSysStatsX: ProtoId = ProtoId(2392);
    pub const NTPInfoIOStatsX: ProtoId = ProtoId(2394);
    pub const NTPInfoTimerStatsX: ProtoId = ProtoId(2395);
    pub const NTPConfPeerX: ProtoId = ProtoId(2396);
    pub const NTPConfUnpeerX: ProtoId = ProtoId(2397);
    pub const NTPConfRestrictX: ProtoId = ProtoId(2398);
    pub const NTPInfoKernelX: ProtoId = ProtoId(2399);
    pub const NTPInfoIfStatsIPv4X: ProtoId = ProtoId(2400);
    pub const NTPInfoIfStatsIPv6X: ProtoId = ProtoId(2401);
    pub const NTPInfoMonitor1X: ProtoId = ProtoId(2402);
    pub const NTPInfoAuthX: ProtoId = ProtoId(2403);
    pub const NTPConfTrapX: ProtoId = ProtoId(2404);
    pub const NTPInfoControlX: ProtoId = ProtoId(2405);
    pub const NTPPrivateReqPacketX: ProtoId = ProtoId(2406);
    pub const PPPoETagX: ProtoId = ProtoId(2415);
    pub const PPPoEDTagsX: ProtoId = ProtoId(2416);
    pub const HDLCX: ProtoId = ProtoId(2417);
    pub const DIRPPPX: ProtoId = ProtoId(2418);
    pub const PPPECPOptionOUIX: ProtoId = ProtoId(2428);
    pub const PPPLCPMRUOptionX: ProtoId = ProtoId(2432);
    pub const PPPLCPACCMOptionX: ProtoId = ProtoId(2433);
    pub const PPPLCPQualityProtocolOptionX: ProtoId = ProtoId(2435);
    pub const PPPLCPMagicNumberOptionX: ProtoId = ProtoId(2436);
    pub const PPPLCPCallbackOptionX: ProtoId = ProtoId(2437);
    pub const PPPLCPTerminateX: ProtoId = ProtoId(2439);
    pub const PPPLCPDiscardRequestX: ProtoId = ProtoId(2442);
    pub const PPPLCPEchoX: ProtoId = ProtoId(2443);
    pub const PPTPStartControlConnectionRequest: ProtoId = ProtoId(2450);
    pub const PPTPStartControlConnectionReply: ProtoId = ProtoId(2451);
    pub const PPTPStopControlConnectionRequest: ProtoId = ProtoId(2452);
    pub const PPTPStopControlConnectionReply: ProtoId = ProtoId(2453);
    pub const PPTPEchoRequest: ProtoId = ProtoId(2454);
    pub const PPTPEchoReply: ProtoId = ProtoId(2455);
    pub const PPTPOutgoingCallRequest: ProtoId = ProtoId(2456);
    pub const PPTPOutgoingCallReply: ProtoId = ProtoId(2457);
    pub const PPTPIncomingCallRequest: ProtoId = ProtoId(2458);
    pub const PPTPIncomingCallReply: ProtoId = ProtoId(2459);
    pub const PPTPIncomingCallConnected: ProtoId = ProtoId(2460);
    pub const PPTPCallClearRequest: ProtoId = ProtoId(2461);
    pub const PPTPCallDisconnectNotify: ProtoId = ProtoId(2462);
    pub const PPTPWANErrorNotify: ProtoId = ProtoId(2463);
    pub const PPTPSetLinkInfo: ProtoId = ProtoId(2464);
    pub const QUICPADDING: ProtoId = ProtoId(2472);
    pub const QUICPING: ProtoId = ProtoId(2473);
    pub const QUICACK: ProtoId = ProtoId(2474);
    pub const MSCHAP2Response: ProtoId = ProtoId(2540);
    pub const MSCHAP2Success: ProtoId = ProtoId(2541);
    pub const MSCHAPError: ProtoId = ProtoId(2542);
    pub const MSCHAPDomain: ProtoId = ProtoId(2543);
    pub const RTPExtension: ProtoId = ProtoId(2547);
    pub const SCTPChunkParamIPv4Addr: ProtoId = ProtoId(2552);
    pub const SCTPChunkParamIPv6Addr: ProtoId = ProtoId(2553);
    pub const SCTPChunkParamCookiePreservative: ProtoId = ProtoId(2556);
    pub const SCTPChunkParamSSNTSNResetReq: ProtoId = ProtoId(2561);
    pub const SCTPChunkParamReConfigRes: ProtoId = ProtoId(2562);
    pub const SCTPChunkParamAddOutgoingStreamReq: ProtoId = ProtoId(2563);
    pub const SCTPChunkParamAddIncomingStreamReq: ProtoId = ProtoId(2564);
    pub const SCTPChunkParamECNCapable: ProtoId = ProtoId(2565);
    pub const SCTPChunkParamFwdTSN: ProtoId = ProtoId(2570);
    pub const SCTPChunkParamSuccessIndication: ProtoId = ProtoId(2575);
    pub const SCTPChunkParamAdaptationLayer: ProtoId = ProtoId(2576);
    pub const SCTPForwardSkip: ProtoId = ProtoId(2579);
    pub const SCTPIForwardSkip: ProtoId = ProtoId(2581);
    pub const SCTPChunkShutdown: ProtoId = ProtoId(2589);
    pub const SCTPChunkShutdownAck: ProtoId = ProtoId(2590);
    pub const SCTPChunkCookieAck: ProtoId = ProtoId(2593);
    pub const SCTPChunkShutdownComplete: ProtoId = ProtoId(2594);
    pub const LoWPANUncompressedIPv6: ProtoId = ProtoId(2600);
    pub const LoWPANHC2UDP: ProtoId = ProtoId(2602);
    pub const LoWPANFragmentationFirst: ProtoId = ProtoId(2604);
    pub const LoWPANBroadcast: ProtoId = ProtoId(2606);
    pub const SixLoWPANESC: ProtoId = ProtoId(2612);
    pub const Skinny: ProtoId = ProtoId(2614);
    pub const SMBSessionNull: ProtoId = ProtoId(2627);
    pub const DcSockAddr: ProtoId = ProtoId(2636);
    pub const FileAlignmentInformation: ProtoId = ProtoId(2645);
    pub const FileEaInformation: ProtoId = ProtoId(2648);
    pub const FileInternalInformation: ProtoId = ProtoId(2656);
    pub const FilePositionInformation: ProtoId = ProtoId(2658);
    pub const FileStandardInformation: ProtoId = ProtoId(2660);
    pub const WINNTSIDIDENTIFIERAUTHORITY: ProtoId = ProtoId(2662);
    pub const FileFsSizeInformation: ProtoId = ProtoId(2687);
    pub const SMB2FILEID: ProtoId = ProtoId(2715);
    pub const SMB2CREATEDURABLEHANDLERESPONSE: ProtoId = ProtoId(2716);
    pub const SMB2CREATEQUERYONDISKID: ProtoId = ProtoId(2718);
    pub const SMB2CREATEDURABLEHANDLEREQUEST: ProtoId = ProtoId(2722);
    pub const SMB2CREATEQUERYMAXIMALACCESSREQUEST: ProtoId = ProtoId(2724);
    pub const SMB2CREATEALLOCATIONSIZE: ProtoId = ProtoId(2725);
    pub const SMB2CREATETIMEWARPTOKEN: ProtoId = ProtoId(2726);
    pub const SMB2CREATEAPPINSTANCEID: ProtoId = ProtoId(2731);
    pub const SMB2CREATEAPPINSTANCEVERSION: ProtoId = ProtoId(2732);
    pub const SMB2IOCTLOFFLOADREADRequest: ProtoId = ProtoId(2751);
    pub const SMB2TransformHeader: ProtoId = ProtoId(2765);
    pub const SMB2CompressionTransformHeader: ProtoId = ProtoId(2766);
    pub const NEGOEXEXTENSIONVECTOR: ProtoId = ProtoId(2794);
    pub const SSHNewKeys: ProtoId = ProtoId(2808);
    pub const SSHUnimplemented: ProtoId = ProtoId(2816);
    pub const SSHNewCompress: ProtoId = ProtoId(2819);
    pub const TFTPDATA: ProtoId = ProtoId(2827);
    pub const TFTPACK: ProtoId = ProtoId(2830);
    pub const UnEncryptedPreMasterSecret: ProtoId = ProtoId(2933);
    pub const ClientPSKIdentity: ProtoId = ProtoId(2935);
    pub const PSKBinderEntry: ProtoId = ProtoId(2942);
    pub const TLSEncryptedContent: ProtoId = ProtoId(2964);
    pub const TLSChangeCipherSpec: ProtoId = ProtoId(2966);
    pub const TLSAlert: ProtoId = ProtoId(2967);
    pub const TLSApplicationData: ProtoId = ProtoId(2968);
    pub const TLSPlaintext: ProtoId = ProtoId(2973);
    pub const TLSCompressed: ProtoId = ProtoId(2974);
    pub const TLSCiphertext: ProtoId = ProtoId(2975);
    pub const TPMSSCHEMESIGHASH: ProtoId = ProtoId(2977);
    pub const TPMSNULLPARMS: ProtoId = ProtoId(2983);
    pub const TPM2BPRIVATEKEYRSA: ProtoId = ProtoId(2986);
    pub const TPM2BDIGESTX: ProtoId = ProtoId(2987);
    pub const TPM2BNAME: ProtoId = ProtoId(2992);
    pub const TPM2BDATA: ProtoId = ProtoId(2993);
    pub const TPMALOCALITY: ProtoId = ProtoId(2994);
    pub const TPMSPCRSELECTION: ProtoId = ProtoId(2995);
    pub const TPMLPCRSELECTION: ProtoId = ProtoId(2996);
    pub const TPMSCLOCKINFO: ProtoId = ProtoId(2999);
    pub const TPM2BPUBLICKEYRSA: ProtoId = ProtoId(3004);
    pub const DarwinUtunPacketInfo: ProtoId = ProtoId(3017);
    pub const USBpcapTransferIsochronous: ProtoId = ProtoId(3019);
    pub const USBpcapTransferInterrupt: ProtoId = ProtoId(3020);
    pub const USBpcapTransferControl: ProtoId = ProtoId(3021);
    pub const LinkStatusEntry: ProtoId = ProtoId(3159);
    pub const ZDPActiveEPReq: ProtoId = ProtoId(3167);
    pub const ZCLGeneralReadAttributes: ProtoId = ProtoId(3176);
    pub const ZCLGeneralDefaultResponse: ProtoId = ProtoId(3183);
    pub const ZCLIASZoneZoneEnrollResponse: ProtoId = ProtoId(3184);
    pub const ZCLIASZoneZoneStatusChangeNotification: ProtoId = ProtoId(3185);
    pub const ZCLMeteringGetProfile: ProtoId = ProtoId(3187);
    pub const ZCLPriceGetCurrentPrice: ProtoId = ProtoId(3188);
    pub const ZCLPriceGetScheduledPrices: ProtoId = ProtoId(3189);
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
pub const BUILTIN_COUNT: u16 = 4096;

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
    ProtoId::HCIPHDRHdr,
    ProtoId::HCIHdr,
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
    ProtoId::ATTReadByGroupTypeResponse,
    ProtoId::ATTWriteRequest,
    ProtoId::ATTWriteCommand,
    ProtoId::ATTPrepareWriteRequest,
    ProtoId::ATTPrepareWriteResponse,
    ProtoId::ATTHandleValueNotification,
    ProtoId::ATTExecuteWriteRequest,
    ProtoId::ATTReadBlobRequest,
    ProtoId::ATTReadBlobResponse,
    ProtoId::ATTHandleValueIndication,
    ProtoId::SMHdr,
    ProtoId::SMPairingRequest,
    ProtoId::SMPairingResponse,
    ProtoId::SMConfirm,
    ProtoId::SMRandom,
    ProtoId::SMFailed,
    ProtoId::SMEncryptionInformation,
    ProtoId::SMMasterIdentification,
    ProtoId::SMIdentityInformation,
    ProtoId::SMSigningInformation,
    ProtoId::SMSecurityRequest,
    ProtoId::SMPublicKey,
    ProtoId::SMDHKeyCheck,
    ProtoId::EIRFlags,
    ProtoId::EIRSecurityManagerOOBFlags,
    ProtoId::EIRPeripheralConnectionIntervalRange,
    ProtoId::EIRDeviceID,
    ProtoId::HCICmdInquiry,
    ProtoId::HCICmdPeriodicInquiryMode,
    ProtoId::HCICmdDisconnect,
    ProtoId::HCICmdChangeConnectionPacketType,
    ProtoId::HCICmdAuthenticationRequested,
    ProtoId::HCICmdSetConnectionEncryption,
    ProtoId::HCICmdChangeConnectionLinkKey,
    ProtoId::HCICmdLinkKeySelection,
    ProtoId::HCICmdReadRemoteSupportedFeatures,
    ProtoId::HCICmdReadRemoteExtendedFeatures,
    ProtoId::HCICmdHoldMode,
    ProtoId::HCICmdSetEventMask,
    ProtoId::HCICmdSetEventFilter,
    ProtoId::HCICmdWriteLocalName,
    ProtoId::HCICmdWriteConnectAcceptTimeout,
    ProtoId::HCICmdWriteLEHostSupport,
    ProtoId::HCICmdReadLocalExtendedFeatures,
    ProtoId::HCICmdReadLinkQuality,
    ProtoId::HCICmdReadRSSI,
    ProtoId::HCICmdWriteLoopbackMode,
    ProtoId::HCICmdLESetScanResponseData,
    ProtoId::HCICmdLESetAdvertiseEnable,
    ProtoId::HCICmdLESetScanParameters,
    ProtoId::HCICmdLESetScanEnable,
    ProtoId::HCICmdLEConnectionUpdate,
    ProtoId::HCICmdLEReadRemoteFeatures,
    ProtoId::HCICmdLEEnableEncryption,
    ProtoId::HCICmdLELongTermKeyRequestReply,
    ProtoId::HCICmdLELongTermKeyRequestNegativeReply,
    ProtoId::HCIEventInquiryComplete,
    ProtoId::HCIEventDisconnectionComplete,
    ProtoId::HCIEventEncryptionChange,
    ProtoId::HCIEventReadRemoteVersionInformationComplete,
    ProtoId::HCIEventCommandComplete,
    ProtoId::HCIEventCommandStatus,
    ProtoId::HCIEventReadRemoteExtendedFeaturesComplete,
    ProtoId::HCIEventLEMeta,
    ProtoId::HCICmdCompleteReadLocalName,
    ProtoId::HCICmdCompleteReadLocalVersionInformation,
    ProtoId::HCICmdCompleteReadLocalExtendedFeatures,
    ProtoId::HCICmdCompleteLEReadWhiteListSize,
    ProtoId::HCILEMetaConnectionUpdateComplete,
    ProtoId::HCILEMetaLongTermKeyRequest,
    ProtoId::HCIMonHdr,
    ProtoId::HCIMonPcapHdr,
    ProtoId::BTLECTRL,
    ProtoId::LLCONNECTIONUPDATEIND,
    ProtoId::LLTERMINATEIND,
    ProtoId::LLENCREQ,
    ProtoId::LLENCRSP,
    ProtoId::LLUNKNOWNRSP,
    ProtoId::LLVERSIONIND,
    ProtoId::LLREJECTIND,
    ProtoId::LLCONNECTIONPARAMREQ,
    ProtoId::LLCONNECTIONPARAMRSP,
    ProtoId::LLREJECTEXTIND,
    ProtoId::LLLENGTHREQ,
    ProtoId::LLLENGTHRSP,
    ProtoId::LLCLOCKACCURACYREQ,
    ProtoId::LLCLOCKACCURACYRSP,
    ProtoId::LLCISRSP,
    ProtoId::LLCISIND,
    ProtoId::LLCISTERMINATEIND,
    ProtoId::LLSUBRATEREQ,
    ProtoId::LLSUBRATEIND,
    ProtoId::LLCHANNELREPORTINGIND,
    ProtoId::DceRpcSecVTBitmask,
    ProtoId::DceRpcSecVTHeader2,
    ProtoId::DceRpc5Version,
    ProtoId::DceRpc5Auth3,
    ProtoId::NDRSerialization1Header,
    ProtoId::DUIDEN,
    ProtoId::DHCP6OptGeoConfElement,
    ProtoId::DHCP6NTPSubOptSrvAddr,
    ProtoId::DHCP6NTPSubOptMCAddr,
    ProtoId::EDNS0DAU,
    ProtoId::EDNS0DHU,
    ProtoId::EDNS0N3U,
    ProtoId::EDNS0COOKIE,
    ProtoId::EDNS0ExtendedDNSError,
    ProtoId::RSNCipherSuite,
    ProtoId::AKMSuite,
    ProtoId::Dot11EltCountryConstraintTriplet,
    ProtoId::Dot11VHTOperationInfo,
    ProtoId::Dot11Disas,
    ProtoId::Dot11ReassoReq,
    ProtoId::Dot11ReassoResp,
    ProtoId::Dot11Deauth,
    ProtoId::Dot11Action,
    ProtoId::Dot11WNM,
    ProtoId::SubelemTLV,
    ProtoId::BSSTerminationDuration,
    ProtoId::Dot11SpectrumManagement,
    ProtoId::Dot11S1GBeacon,
    ProtoId::Dot11CCMP,
    ProtoId::Dot15d4CmdCoordRealignPage,
    ProtoId::Dot15d4CmdAssocReq,
    ProtoId::Dot15d4CmdAssocResp,
    ProtoId::Dot15d4CmdDisassociation,
    ProtoId::Dot15d4CmdGTSReq,
    ProtoId::MKAPeerListTuple,
    ProtoId::MKASAKUseParamSet,
    ProtoId::MKADistributedCAKParamSet,
    ProtoId::MKAICVSet,
    ProtoId::GssBufferDesc,
    ProtoId::IPOptionHDR,
    ProtoId::IPOptionEOL,
    ProtoId::IPOptionNOP,
    ProtoId::IPOptionSecurity,
    ProtoId::IPOptionRR,
    ProtoId::IPOptionLSRR,
    ProtoId::IPOptionSSRR,
    ProtoId::IPOptionStreamId,
    ProtoId::IPOptionMTUProbe,
    ProtoId::IPOptionMTUReply,
    ProtoId::IPOptionTraceroute,
    ProtoId::IPOptionAddressExtension,
    ProtoId::IPOptionRouterAlert,
    ProtoId::IPOptionSDBM,
    ProtoId::PseudoIPv6,
    ProtoId::IPv6ExtHdrSegmentRoutingTLVIngressNode,
    ProtoId::IPv6ExtHdrSegmentRoutingTLVEgressNode,
    ProtoId::IPv6ExtHdrSegmentRoutingTLVPad1,
    ProtoId::IPv6ExtHdrSegmentRoutingTLVHMAC,
    ProtoId::MIP6OptBRAdvice,
    ProtoId::MIP6OptAltCoA,
    ProtoId::MIP6OptNonceIndices,
    ProtoId::MIP6OptMobNetPrefix,
    ProtoId::MIP6OptLLAddr,
    ProtoId::MIP6OptMNID,
    ProtoId::MIP6OptCGAParamsReq,
    ProtoId::MIP6OptCGAParams,
    ProtoId::MIP6OptSignature,
    ProtoId::MIP6OptHomeKeygenToken,
    ProtoId::MIP6OptCareOfTestInit,
    ProtoId::NONESP,
    ProtoId::NATKEEPALIVE,
    ProtoId::IrLAPHead,
    ProtoId::IrLAPCommand,
    ProtoId::IrLMP,
    ProtoId::KPasswdRepData,
    ProtoId::GRErouting,
    ProtoId::LoopbackOpenBSD,
    ProtoId::Dot1AH,
    ProtoId::LLTDHello,
    ProtoId::LLTDDiscover,
    ProtoId::LLTDEmiteeDesc,
    ProtoId::LLTDEmit,
    ProtoId::LLTDRecveeDesc,
    ProtoId::LLTDQueryLargeTlv,
    ProtoId::LLTDAttributeEOP,
    ProtoId::LLTDAttributeHostID,
    ProtoId::LLTDAttributeCharacteristics,
    ProtoId::LLTDAttributePhysicalMedium,
    ProtoId::LLTDAttributeIPv4Address,
    ProtoId::LLTDAttributeIPv6Address,
    ProtoId::LLTDAttribute80211MaxRate,
    ProtoId::LLTDAttributePerformanceCounterFrequency,
    ProtoId::LLTDAttributeLinkSpeed,
    ProtoId::LLTDAttributeLargeTLV,
    ProtoId::LLTDAttributeQOSCharacteristics,
    ProtoId::LLTDAttribute80211PhysicalMedium,
    ProtoId::LLTDAttributeSeesList,
    ProtoId::MobileIP,
    ProtoId::MobileIPRRQ,
    ProtoId::MobileIPRRP,
    ProtoId::MobileIPTunnelData,
    ProtoId::NRTPEndHeader,
    ProtoId::NRTPStatusCodeHeader,
    ProtoId::NRTPCloseConnectionHeader,
    ProtoId::ArrayInfo,
    ProtoId::NRBFArraySingleObject,
    ProtoId::NRBFMemberReference,
    ProtoId::NRBFObjectNull,
    ProtoId::NRBFMessageEnd,
    ProtoId::OctetStringT,
    ProtoId::PACINFOBUFFER,
    ProtoId::PACCREDENTIALINFO,
    ProtoId::NBNSHeader,
    ProtoId::NBNSADDENTRY,
    ProtoId::NBNSNodeStatusResponseService,
    ProtoId::NetflowHeader,
    ProtoId::NetflowRecordV1,
    ProtoId::NetflowRecordV5,
    ProtoId::NetflowRecordV9,
    ProtoId::NetflowOptionsRecordScopeV9,
    ProtoId::NetflowOptionsRecordOptionV9,
    ProtoId::NetflowOptionsFlowsetScopeV9,
    ProtoId::NTLMVersion,
    ProtoId::LMRESPONSE,
    ProtoId::LMv2RESPONSE,
    ProtoId::NTLMRESPONSE,
    ProtoId::NTLMSSPMESSAGESIGNATURE,
    ProtoId::NTPSystemStatusPacketX,
    ProtoId::NTPPeerStatusPacketX,
    ProtoId::NTPClockStatusPacketX,
    ProtoId::NTPErrorStatusPacketX,
    ProtoId::NTPInfoPeerListX,
    ProtoId::NTPInfoPeerStatsX,
    ProtoId::NTPInfoSysStatsX,
    ProtoId::NTPInfoIOStatsX,
    ProtoId::NTPInfoTimerStatsX,
    ProtoId::NTPConfPeerX,
    ProtoId::NTPConfUnpeerX,
    ProtoId::NTPConfRestrictX,
    ProtoId::NTPInfoKernelX,
    ProtoId::NTPInfoIfStatsIPv4X,
    ProtoId::NTPInfoIfStatsIPv6X,
    ProtoId::NTPInfoMonitor1X,
    ProtoId::NTPInfoAuthX,
    ProtoId::NTPConfTrapX,
    ProtoId::NTPInfoControlX,
    ProtoId::NTPPrivateReqPacketX,
    ProtoId::PPPoETagX,
    ProtoId::PPPoEDTagsX,
    ProtoId::HDLCX,
    ProtoId::DIRPPPX,
    ProtoId::PPPECPOptionOUIX,
    ProtoId::PPPLCPMRUOptionX,
    ProtoId::PPPLCPACCMOptionX,
    ProtoId::PPPLCPQualityProtocolOptionX,
    ProtoId::PPPLCPMagicNumberOptionX,
    ProtoId::PPPLCPCallbackOptionX,
    ProtoId::PPPLCPTerminateX,
    ProtoId::PPPLCPDiscardRequestX,
    ProtoId::PPPLCPEchoX,
    ProtoId::PPTPStartControlConnectionRequest,
    ProtoId::PPTPStartControlConnectionReply,
    ProtoId::PPTPStopControlConnectionRequest,
    ProtoId::PPTPStopControlConnectionReply,
    ProtoId::PPTPEchoRequest,
    ProtoId::PPTPEchoReply,
    ProtoId::PPTPOutgoingCallRequest,
    ProtoId::PPTPOutgoingCallReply,
    ProtoId::PPTPIncomingCallRequest,
    ProtoId::PPTPIncomingCallReply,
    ProtoId::PPTPIncomingCallConnected,
    ProtoId::PPTPCallClearRequest,
    ProtoId::PPTPCallDisconnectNotify,
    ProtoId::PPTPWANErrorNotify,
    ProtoId::PPTPSetLinkInfo,
    ProtoId::QUICPADDING,
    ProtoId::QUICPING,
    ProtoId::QUICACK,
    ProtoId::MSCHAP2Response,
    ProtoId::MSCHAP2Success,
    ProtoId::MSCHAPError,
    ProtoId::MSCHAPDomain,
    ProtoId::RTPExtension,
    ProtoId::SCTPChunkParamIPv4Addr,
    ProtoId::SCTPChunkParamIPv6Addr,
    ProtoId::SCTPChunkParamCookiePreservative,
    ProtoId::SCTPChunkParamSSNTSNResetReq,
    ProtoId::SCTPChunkParamReConfigRes,
    ProtoId::SCTPChunkParamAddOutgoingStreamReq,
    ProtoId::SCTPChunkParamAddIncomingStreamReq,
    ProtoId::SCTPChunkParamECNCapable,
    ProtoId::SCTPChunkParamFwdTSN,
    ProtoId::SCTPChunkParamSuccessIndication,
    ProtoId::SCTPChunkParamAdaptationLayer,
    ProtoId::SCTPForwardSkip,
    ProtoId::SCTPIForwardSkip,
    ProtoId::SCTPChunkShutdown,
    ProtoId::SCTPChunkShutdownAck,
    ProtoId::SCTPChunkCookieAck,
    ProtoId::SCTPChunkShutdownComplete,
    ProtoId::LoWPANUncompressedIPv6,
    ProtoId::LoWPANHC2UDP,
    ProtoId::LoWPANFragmentationFirst,
    ProtoId::LoWPANBroadcast,
    ProtoId::SixLoWPANESC,
    ProtoId::Skinny,
    ProtoId::SMBSessionNull,
    ProtoId::DcSockAddr,
    ProtoId::FileAlignmentInformation,
    ProtoId::FileEaInformation,
    ProtoId::FileInternalInformation,
    ProtoId::FilePositionInformation,
    ProtoId::FileStandardInformation,
    ProtoId::WINNTSIDIDENTIFIERAUTHORITY,
    ProtoId::FileFsSizeInformation,
    ProtoId::SMB2FILEID,
    ProtoId::SMB2CREATEDURABLEHANDLERESPONSE,
    ProtoId::SMB2CREATEQUERYONDISKID,
    ProtoId::SMB2CREATEDURABLEHANDLEREQUEST,
    ProtoId::SMB2CREATEQUERYMAXIMALACCESSREQUEST,
    ProtoId::SMB2CREATEALLOCATIONSIZE,
    ProtoId::SMB2CREATETIMEWARPTOKEN,
    ProtoId::SMB2CREATEAPPINSTANCEID,
    ProtoId::SMB2CREATEAPPINSTANCEVERSION,
    ProtoId::SMB2IOCTLOFFLOADREADRequest,
    ProtoId::SMB2TransformHeader,
    ProtoId::SMB2CompressionTransformHeader,
    ProtoId::NEGOEXEXTENSIONVECTOR,
    ProtoId::SSHNewKeys,
    ProtoId::SSHUnimplemented,
    ProtoId::SSHNewCompress,
    ProtoId::TFTPDATA,
    ProtoId::TFTPACK,
    ProtoId::UnEncryptedPreMasterSecret,
    ProtoId::ClientPSKIdentity,
    ProtoId::PSKBinderEntry,
    ProtoId::TLSEncryptedContent,
    ProtoId::TLSChangeCipherSpec,
    ProtoId::TLSAlert,
    ProtoId::TLSApplicationData,
    ProtoId::TLSPlaintext,
    ProtoId::TLSCompressed,
    ProtoId::TLSCiphertext,
    ProtoId::TPMSSCHEMESIGHASH,
    ProtoId::TPMSNULLPARMS,
    ProtoId::TPM2BPRIVATEKEYRSA,
    ProtoId::TPM2BDIGESTX,
    ProtoId::TPM2BNAME,
    ProtoId::TPM2BDATA,
    ProtoId::TPMALOCALITY,
    ProtoId::TPMSPCRSELECTION,
    ProtoId::TPMLPCRSELECTION,
    ProtoId::TPMSCLOCKINFO,
    ProtoId::TPM2BPUBLICKEYRSA,
    ProtoId::DarwinUtunPacketInfo,
    ProtoId::USBpcapTransferIsochronous,
    ProtoId::USBpcapTransferInterrupt,
    ProtoId::USBpcapTransferControl,
    ProtoId::LinkStatusEntry,
    ProtoId::ZDPActiveEPReq,
    ProtoId::ZCLGeneralReadAttributes,
    ProtoId::ZCLGeneralDefaultResponse,
    ProtoId::ZCLIASZoneZoneEnrollResponse,
    ProtoId::ZCLIASZoneZoneStatusChangeNotification,
    ProtoId::ZCLMeteringGetProfile,
    ProtoId::ZCLPriceGetCurrentPrice,
    ProtoId::ZCLPriceGetScheduledPrices,
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
    t[ProtoId::HCIPHDRHdr.0 as usize] = &bluetooth_hci_phdr_hdr::DESC;
    t[ProtoId::HCIHdr.0 as usize] = &bluetooth_hci_hdr::DESC;
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
    t[ProtoId::ATTReadByGroupTypeResponse.0 as usize] =
        &bluetooth_att_read_by_group_type_response::DESC;
    t[ProtoId::ATTWriteRequest.0 as usize] = &bluetooth_att_write_request::DESC;
    t[ProtoId::ATTWriteCommand.0 as usize] = &bluetooth_att_write_command::DESC;
    t[ProtoId::ATTPrepareWriteRequest.0 as usize] = &bluetooth_att_prepare_write_request::DESC;
    t[ProtoId::ATTPrepareWriteResponse.0 as usize] = &bluetooth_att_prepare_write_response::DESC;
    t[ProtoId::ATTHandleValueNotification.0 as usize] =
        &bluetooth_att_handle_value_notification::DESC;
    t[ProtoId::ATTExecuteWriteRequest.0 as usize] = &bluetooth_att_execute_write_request::DESC;
    t[ProtoId::ATTReadBlobRequest.0 as usize] = &bluetooth_att_read_blob_request::DESC;
    t[ProtoId::ATTReadBlobResponse.0 as usize] = &bluetooth_att_read_blob_response::DESC;
    t[ProtoId::ATTHandleValueIndication.0 as usize] = &bluetooth_att_handle_value_indication::DESC;
    t[ProtoId::SMHdr.0 as usize] = &bluetooth_sm_hdr::DESC;
    t[ProtoId::SMPairingRequest.0 as usize] = &bluetooth_sm_pairing_request::DESC;
    t[ProtoId::SMPairingResponse.0 as usize] = &bluetooth_sm_pairing_response::DESC;
    t[ProtoId::SMConfirm.0 as usize] = &bluetooth_sm_confirm::DESC;
    t[ProtoId::SMRandom.0 as usize] = &bluetooth_sm_random::DESC;
    t[ProtoId::SMFailed.0 as usize] = &bluetooth_sm_failed::DESC;
    t[ProtoId::SMEncryptionInformation.0 as usize] = &bluetooth_sm_encryption_information::DESC;
    t[ProtoId::SMMasterIdentification.0 as usize] = &bluetooth_sm_master_identification::DESC;
    t[ProtoId::SMIdentityInformation.0 as usize] = &bluetooth_sm_identity_information::DESC;
    t[ProtoId::SMSigningInformation.0 as usize] = &bluetooth_sm_signing_information::DESC;
    t[ProtoId::SMSecurityRequest.0 as usize] = &bluetooth_sm_security_request::DESC;
    t[ProtoId::SMPublicKey.0 as usize] = &bluetooth_sm_public_key::DESC;
    t[ProtoId::SMDHKeyCheck.0 as usize] = &bluetooth_sm_dhkey_check::DESC;
    t[ProtoId::EIRFlags.0 as usize] = &bluetooth_eir_flags::DESC;
    t[ProtoId::EIRSecurityManagerOOBFlags.0 as usize] =
        &bluetooth_eir_securitymanageroobflags::DESC;
    t[ProtoId::EIRPeripheralConnectionIntervalRange.0 as usize] =
        &bluetooth_eir_peripheralconnectionintervalrange::DESC;
    t[ProtoId::EIRDeviceID.0 as usize] = &bluetooth_eir_device_id::DESC;
    t[ProtoId::HCICmdInquiry.0 as usize] = &bluetooth_hci_cmd_inquiry::DESC;
    t[ProtoId::HCICmdPeriodicInquiryMode.0 as usize] =
        &bluetooth_hci_cmd_periodic_inquiry_mode::DESC;
    t[ProtoId::HCICmdDisconnect.0 as usize] = &bluetooth_hci_cmd_disconnect::DESC;
    t[ProtoId::HCICmdChangeConnectionPacketType.0 as usize] =
        &bluetooth_hci_cmd_change_connection_packet_type::DESC;
    t[ProtoId::HCICmdAuthenticationRequested.0 as usize] =
        &bluetooth_hci_cmd_authentication_requested::DESC;
    t[ProtoId::HCICmdSetConnectionEncryption.0 as usize] =
        &bluetooth_hci_cmd_set_connection_encryption::DESC;
    t[ProtoId::HCICmdChangeConnectionLinkKey.0 as usize] =
        &bluetooth_hci_cmd_change_connection_link_key::DESC;
    t[ProtoId::HCICmdLinkKeySelection.0 as usize] = &bluetooth_hci_cmd_link_key_selection::DESC;
    t[ProtoId::HCICmdReadRemoteSupportedFeatures.0 as usize] =
        &bluetooth_hci_cmd_read_remote_supported_features::DESC;
    t[ProtoId::HCICmdReadRemoteExtendedFeatures.0 as usize] =
        &bluetooth_hci_cmd_read_remote_extended_features::DESC;
    t[ProtoId::HCICmdHoldMode.0 as usize] = &bluetooth_hci_cmd_hold_mode::DESC;
    t[ProtoId::HCICmdSetEventMask.0 as usize] = &bluetooth_hci_cmd_set_event_mask::DESC;
    t[ProtoId::HCICmdSetEventFilter.0 as usize] = &bluetooth_hci_cmd_set_event_filter::DESC;
    t[ProtoId::HCICmdWriteLocalName.0 as usize] = &bluetooth_hci_cmd_write_local_name::DESC;
    t[ProtoId::HCICmdWriteConnectAcceptTimeout.0 as usize] =
        &bluetooth_hci_cmd_write_connect_accept_timeout::DESC;
    t[ProtoId::HCICmdWriteLEHostSupport.0 as usize] =
        &bluetooth_hci_cmd_write_le_host_support::DESC;
    t[ProtoId::HCICmdReadLocalExtendedFeatures.0 as usize] =
        &bluetooth_hci_cmd_read_local_extended_features::DESC;
    t[ProtoId::HCICmdReadLinkQuality.0 as usize] = &bluetooth_hci_cmd_read_link_quality::DESC;
    t[ProtoId::HCICmdReadRSSI.0 as usize] = &bluetooth_hci_cmd_read_rssi::DESC;
    t[ProtoId::HCICmdWriteLoopbackMode.0 as usize] = &bluetooth_hci_cmd_write_loopback_mode::DESC;
    t[ProtoId::HCICmdLESetScanResponseData.0 as usize] =
        &bluetooth_hci_cmd_le_set_scan_response_data::DESC;
    t[ProtoId::HCICmdLESetAdvertiseEnable.0 as usize] =
        &bluetooth_hci_cmd_le_set_advertise_enable::DESC;
    t[ProtoId::HCICmdLESetScanParameters.0 as usize] =
        &bluetooth_hci_cmd_le_set_scan_parameters::DESC;
    t[ProtoId::HCICmdLESetScanEnable.0 as usize] = &bluetooth_hci_cmd_le_set_scan_enable::DESC;
    t[ProtoId::HCICmdLEConnectionUpdate.0 as usize] = &bluetooth_hci_cmd_le_connection_update::DESC;
    t[ProtoId::HCICmdLEReadRemoteFeatures.0 as usize] =
        &bluetooth_hci_cmd_le_read_remote_features::DESC;
    t[ProtoId::HCICmdLEEnableEncryption.0 as usize] = &bluetooth_hci_cmd_le_enable_encryption::DESC;
    t[ProtoId::HCICmdLELongTermKeyRequestReply.0 as usize] =
        &bluetooth_hci_cmd_le_long_term_key_request_reply::DESC;
    t[ProtoId::HCICmdLELongTermKeyRequestNegativeReply.0 as usize] =
        &bluetooth_hci_cmd_le_long_term_key_request_negative_reply::DESC;
    t[ProtoId::HCIEventInquiryComplete.0 as usize] = &bluetooth_hci_event_inquiry_complete::DESC;
    t[ProtoId::HCIEventDisconnectionComplete.0 as usize] =
        &bluetooth_hci_event_disconnection_complete::DESC;
    t[ProtoId::HCIEventEncryptionChange.0 as usize] = &bluetooth_hci_event_encryption_change::DESC;
    t[ProtoId::HCIEventReadRemoteVersionInformationComplete.0 as usize] =
        &bluetooth_hci_event_read_remote_version_information_complete::DESC;
    t[ProtoId::HCIEventCommandComplete.0 as usize] = &bluetooth_hci_event_command_complete::DESC;
    t[ProtoId::HCIEventCommandStatus.0 as usize] = &bluetooth_hci_event_command_status::DESC;
    t[ProtoId::HCIEventReadRemoteExtendedFeaturesComplete.0 as usize] =
        &bluetooth_hci_event_read_remote_extended_features_complete::DESC;
    t[ProtoId::HCIEventLEMeta.0 as usize] = &bluetooth_hci_event_le_meta::DESC;
    t[ProtoId::HCICmdCompleteReadLocalName.0 as usize] =
        &bluetooth_hci_cmd_complete_read_local_name::DESC;
    t[ProtoId::HCICmdCompleteReadLocalVersionInformation.0 as usize] =
        &bluetooth_hci_cmd_complete_read_local_version_information::DESC;
    t[ProtoId::HCICmdCompleteReadLocalExtendedFeatures.0 as usize] =
        &bluetooth_hci_cmd_complete_read_local_extended_features::DESC;
    t[ProtoId::HCICmdCompleteLEReadWhiteListSize.0 as usize] =
        &bluetooth_hci_cmd_complete_le_read_white_list_size::DESC;
    t[ProtoId::HCILEMetaConnectionUpdateComplete.0 as usize] =
        &bluetooth_hci_le_meta_connection_update_complete::DESC;
    t[ProtoId::HCILEMetaLongTermKeyRequest.0 as usize] =
        &bluetooth_hci_le_meta_long_term_key_request::DESC;
    t[ProtoId::HCIMonHdr.0 as usize] = &bluetooth_hci_mon_hdr::DESC;
    t[ProtoId::HCIMonPcapHdr.0 as usize] = &bluetooth_hci_mon_pcap_hdr::DESC;
    t[ProtoId::BTLECTRL.0 as usize] = &bluetooth4LE_btle_ctrl::DESC;
    t[ProtoId::LLCONNECTIONUPDATEIND.0 as usize] = &bluetooth4LE_ll_connection_update_ind::DESC;
    t[ProtoId::LLTERMINATEIND.0 as usize] = &bluetooth4LE_ll_terminate_ind::DESC;
    t[ProtoId::LLENCREQ.0 as usize] = &bluetooth4LE_ll_enc_req::DESC;
    t[ProtoId::LLENCRSP.0 as usize] = &bluetooth4LE_ll_enc_rsp::DESC;
    t[ProtoId::LLUNKNOWNRSP.0 as usize] = &bluetooth4LE_ll_unknown_rsp::DESC;
    t[ProtoId::LLVERSIONIND.0 as usize] = &bluetooth4LE_ll_version_ind::DESC;
    t[ProtoId::LLREJECTIND.0 as usize] = &bluetooth4LE_ll_reject_ind::DESC;
    t[ProtoId::LLCONNECTIONPARAMREQ.0 as usize] = &bluetooth4LE_ll_connection_param_req::DESC;
    t[ProtoId::LLCONNECTIONPARAMRSP.0 as usize] = &bluetooth4LE_ll_connection_param_rsp::DESC;
    t[ProtoId::LLREJECTEXTIND.0 as usize] = &bluetooth4LE_ll_reject_ext_ind::DESC;
    t[ProtoId::LLLENGTHREQ.0 as usize] = &bluetooth4LE_ll_length_req::DESC;
    t[ProtoId::LLLENGTHRSP.0 as usize] = &bluetooth4LE_ll_length_rsp::DESC;
    t[ProtoId::LLCLOCKACCURACYREQ.0 as usize] = &bluetooth4LE_ll_clock_accuracy_req::DESC;
    t[ProtoId::LLCLOCKACCURACYRSP.0 as usize] = &bluetooth4LE_ll_clock_accuracy_rsp::DESC;
    t[ProtoId::LLCISRSP.0 as usize] = &bluetooth4LE_ll_cis_rsp::DESC;
    t[ProtoId::LLCISIND.0 as usize] = &bluetooth4LE_ll_cis_ind::DESC;
    t[ProtoId::LLCISTERMINATEIND.0 as usize] = &bluetooth4LE_ll_cis_terminate_ind::DESC;
    t[ProtoId::LLSUBRATEREQ.0 as usize] = &bluetooth4LE_ll_subrate_req::DESC;
    t[ProtoId::LLSUBRATEIND.0 as usize] = &bluetooth4LE_ll_subrate_ind::DESC;
    t[ProtoId::LLCHANNELREPORTINGIND.0 as usize] = &bluetooth4LE_ll_channel_reporting_ind::DESC;
    t[ProtoId::DceRpcSecVTBitmask.0 as usize] = &dcerpc_dcerpcsecvtbitmask::DESC;
    t[ProtoId::DceRpcSecVTHeader2.0 as usize] = &dcerpc_dcerpcsecvtheader2::DESC;
    t[ProtoId::DceRpc5Version.0 as usize] = &dcerpc_dcerpc5version::DESC;
    t[ProtoId::DceRpc5Auth3.0 as usize] = &dcerpc_dcerpc5auth3::DESC;
    t[ProtoId::NDRSerialization1Header.0 as usize] = &dcerpc_ndrserialization1header::DESC;
    t[ProtoId::DUIDEN.0 as usize] = &dhcp6_duid_en::DESC;
    t[ProtoId::DHCP6OptGeoConfElement.0 as usize] = &dhcp6_dhcp6optgeoconfelement::DESC;
    t[ProtoId::DHCP6NTPSubOptSrvAddr.0 as usize] = &dhcp6_dhcp6ntpsuboptsrvaddr::DESC;
    t[ProtoId::DHCP6NTPSubOptMCAddr.0 as usize] = &dhcp6_dhcp6ntpsuboptmcaddr::DESC;
    t[ProtoId::EDNS0DAU.0 as usize] = &dns_edns0dau::DESC;
    t[ProtoId::EDNS0DHU.0 as usize] = &dns_edns0dhu::DESC;
    t[ProtoId::EDNS0N3U.0 as usize] = &dns_edns0n3u::DESC;
    t[ProtoId::EDNS0COOKIE.0 as usize] = &dns_edns0cookie::DESC;
    t[ProtoId::EDNS0ExtendedDNSError.0 as usize] = &dns_edns0extendeddnserror::DESC;
    t[ProtoId::RSNCipherSuite.0 as usize] = &dot11_rsnciphersuite::DESC;
    t[ProtoId::AKMSuite.0 as usize] = &dot11_akmsuite::DESC;
    t[ProtoId::Dot11EltCountryConstraintTriplet.0 as usize] =
        &dot11_dot11eltcountryconstrainttriplet::DESC;
    t[ProtoId::Dot11VHTOperationInfo.0 as usize] = &dot11_dot11vhtoperationinfo::DESC;
    t[ProtoId::Dot11Disas.0 as usize] = &dot11_dot11disas::DESC;
    t[ProtoId::Dot11ReassoReq.0 as usize] = &dot11_dot11reassoreq::DESC;
    t[ProtoId::Dot11ReassoResp.0 as usize] = &dot11_dot11reassoresp::DESC;
    t[ProtoId::Dot11Deauth.0 as usize] = &dot11_dot11deauth::DESC;
    t[ProtoId::Dot11Action.0 as usize] = &dot11_dot11action::DESC;
    t[ProtoId::Dot11WNM.0 as usize] = &dot11_dot11wnm::DESC;
    t[ProtoId::SubelemTLV.0 as usize] = &dot11_subelemtlv::DESC;
    t[ProtoId::BSSTerminationDuration.0 as usize] = &dot11_bssterminationduration::DESC;
    t[ProtoId::Dot11SpectrumManagement.0 as usize] = &dot11_dot11spectrummanagement::DESC;
    t[ProtoId::Dot11S1GBeacon.0 as usize] = &dot11_dot11s1gbeacon::DESC;
    t[ProtoId::Dot11CCMP.0 as usize] = &dot11_dot11ccmp::DESC;
    t[ProtoId::Dot15d4CmdCoordRealignPage.0 as usize] = &dot15d4_dot15d4cmdcoordrealignpage::DESC;
    t[ProtoId::Dot15d4CmdAssocReq.0 as usize] = &dot15d4_dot15d4cmdassocreq::DESC;
    t[ProtoId::Dot15d4CmdAssocResp.0 as usize] = &dot15d4_dot15d4cmdassocresp::DESC;
    t[ProtoId::Dot15d4CmdDisassociation.0 as usize] = &dot15d4_dot15d4cmddisassociation::DESC;
    t[ProtoId::Dot15d4CmdGTSReq.0 as usize] = &dot15d4_dot15d4cmdgtsreq::DESC;
    t[ProtoId::MKAPeerListTuple.0 as usize] = &eap_mkapeerlisttuple::DESC;
    t[ProtoId::MKASAKUseParamSet.0 as usize] = &eap_mkasakuseparamset::DESC;
    t[ProtoId::MKADistributedCAKParamSet.0 as usize] = &eap_mkadistributedcakparamset::DESC;
    t[ProtoId::MKAICVSet.0 as usize] = &eap_mkaicvset::DESC;
    t[ProtoId::GssBufferDesc.0 as usize] = &gssapi_gssbufferdesc::DESC;
    t[ProtoId::IPOptionHDR.0 as usize] = &inet_ipoption_hdr::DESC;
    t[ProtoId::IPOptionEOL.0 as usize] = &inet_ipoption_eol::DESC;
    t[ProtoId::IPOptionNOP.0 as usize] = &inet_ipoption_nop::DESC;
    t[ProtoId::IPOptionSecurity.0 as usize] = &inet_ipoption_security::DESC;
    t[ProtoId::IPOptionRR.0 as usize] = &inet_ipoption_rr::DESC;
    t[ProtoId::IPOptionLSRR.0 as usize] = &inet_ipoption_lsrr::DESC;
    t[ProtoId::IPOptionSSRR.0 as usize] = &inet_ipoption_ssrr::DESC;
    t[ProtoId::IPOptionStreamId.0 as usize] = &inet_ipoption_stream_id::DESC;
    t[ProtoId::IPOptionMTUProbe.0 as usize] = &inet_ipoption_mtu_probe::DESC;
    t[ProtoId::IPOptionMTUReply.0 as usize] = &inet_ipoption_mtu_reply::DESC;
    t[ProtoId::IPOptionTraceroute.0 as usize] = &inet_ipoption_traceroute::DESC;
    t[ProtoId::IPOptionAddressExtension.0 as usize] = &inet_ipoption_address_extension::DESC;
    t[ProtoId::IPOptionRouterAlert.0 as usize] = &inet_ipoption_router_alert::DESC;
    t[ProtoId::IPOptionSDBM.0 as usize] = &inet_ipoption_sdbm::DESC;
    t[ProtoId::PseudoIPv6.0 as usize] = &inet6_pseudoipv6::DESC;
    t[ProtoId::IPv6ExtHdrSegmentRoutingTLVIngressNode.0 as usize] =
        &inet6_ipv6exthdrsegmentroutingtlvingressnode::DESC;
    t[ProtoId::IPv6ExtHdrSegmentRoutingTLVEgressNode.0 as usize] =
        &inet6_ipv6exthdrsegmentroutingtlvegressnode::DESC;
    t[ProtoId::IPv6ExtHdrSegmentRoutingTLVPad1.0 as usize] =
        &inet6_ipv6exthdrsegmentroutingtlvpad1::DESC;
    t[ProtoId::IPv6ExtHdrSegmentRoutingTLVHMAC.0 as usize] =
        &inet6_ipv6exthdrsegmentroutingtlvhmac::DESC;
    t[ProtoId::MIP6OptBRAdvice.0 as usize] = &inet6_mip6optbradvice::DESC;
    t[ProtoId::MIP6OptAltCoA.0 as usize] = &inet6_mip6optaltcoa::DESC;
    t[ProtoId::MIP6OptNonceIndices.0 as usize] = &inet6_mip6optnonceindices::DESC;
    t[ProtoId::MIP6OptMobNetPrefix.0 as usize] = &inet6_mip6optmobnetprefix::DESC;
    t[ProtoId::MIP6OptLLAddr.0 as usize] = &inet6_mip6optlladdr::DESC;
    t[ProtoId::MIP6OptMNID.0 as usize] = &inet6_mip6optmnid::DESC;
    t[ProtoId::MIP6OptCGAParamsReq.0 as usize] = &inet6_mip6optcgaparamsreq::DESC;
    t[ProtoId::MIP6OptCGAParams.0 as usize] = &inet6_mip6optcgaparams::DESC;
    t[ProtoId::MIP6OptSignature.0 as usize] = &inet6_mip6optsignature::DESC;
    t[ProtoId::MIP6OptHomeKeygenToken.0 as usize] = &inet6_mip6opthomekeygentoken::DESC;
    t[ProtoId::MIP6OptCareOfTestInit.0 as usize] = &inet6_mip6optcareoftestinit::DESC;
    t[ProtoId::NONESP.0 as usize] = &ipsec_non_esp::DESC;
    t[ProtoId::NATKEEPALIVE.0 as usize] = &ipsec_nat_keepalive::DESC;
    t[ProtoId::IrLAPHead.0 as usize] = &ir_irlaphead::DESC;
    t[ProtoId::IrLAPCommand.0 as usize] = &ir_irlapcommand::DESC;
    t[ProtoId::IrLMP.0 as usize] = &ir_irlmp::DESC;
    t[ProtoId::KPasswdRepData.0 as usize] = &kerberos_kpasswdrepdata::DESC;
    t[ProtoId::GRErouting.0 as usize] = &l2_grerouting::DESC;
    t[ProtoId::LoopbackOpenBSD.0 as usize] = &l2_loopbackopenbsd::DESC;
    t[ProtoId::Dot1AH.0 as usize] = &l2_dot1ah::DESC;
    t[ProtoId::LLTDHello.0 as usize] = &lltd_lltdhello::DESC;
    t[ProtoId::LLTDDiscover.0 as usize] = &lltd_lltddiscover::DESC;
    t[ProtoId::LLTDEmiteeDesc.0 as usize] = &lltd_lltdemiteedesc::DESC;
    t[ProtoId::LLTDEmit.0 as usize] = &lltd_lltdemit::DESC;
    t[ProtoId::LLTDRecveeDesc.0 as usize] = &lltd_lltdrecveedesc::DESC;
    t[ProtoId::LLTDQueryLargeTlv.0 as usize] = &lltd_lltdquerylargetlv::DESC;
    t[ProtoId::LLTDAttributeEOP.0 as usize] = &lltd_lltdattributeeop::DESC;
    t[ProtoId::LLTDAttributeHostID.0 as usize] = &lltd_lltdattributehostid::DESC;
    t[ProtoId::LLTDAttributeCharacteristics.0 as usize] = &lltd_lltdattributecharacteristics::DESC;
    t[ProtoId::LLTDAttributePhysicalMedium.0 as usize] = &lltd_lltdattributephysicalmedium::DESC;
    t[ProtoId::LLTDAttributeIPv4Address.0 as usize] = &lltd_lltdattributeipv4address::DESC;
    t[ProtoId::LLTDAttributeIPv6Address.0 as usize] = &lltd_lltdattributeipv6address::DESC;
    t[ProtoId::LLTDAttribute80211MaxRate.0 as usize] = &lltd_lltdattribute80211maxrate::DESC;
    t[ProtoId::LLTDAttributePerformanceCounterFrequency.0 as usize] =
        &lltd_lltdattributeperformancecounterfrequency::DESC;
    t[ProtoId::LLTDAttributeLinkSpeed.0 as usize] = &lltd_lltdattributelinkspeed::DESC;
    t[ProtoId::LLTDAttributeLargeTLV.0 as usize] = &lltd_lltdattributelargetlv::DESC;
    t[ProtoId::LLTDAttributeQOSCharacteristics.0 as usize] =
        &lltd_lltdattributeqoscharacteristics::DESC;
    t[ProtoId::LLTDAttribute80211PhysicalMedium.0 as usize] =
        &lltd_lltdattribute80211physicalmedium::DESC;
    t[ProtoId::LLTDAttributeSeesList.0 as usize] = &lltd_lltdattributeseeslist::DESC;
    t[ProtoId::MobileIP.0 as usize] = &mobileip_mobileip::DESC;
    t[ProtoId::MobileIPRRQ.0 as usize] = &mobileip_mobileiprrq::DESC;
    t[ProtoId::MobileIPRRP.0 as usize] = &mobileip_mobileiprrp::DESC;
    t[ProtoId::MobileIPTunnelData.0 as usize] = &mobileip_mobileiptunneldata::DESC;
    t[ProtoId::NRTPEndHeader.0 as usize] = &ms_nrtp_nrtpendheader::DESC;
    t[ProtoId::NRTPStatusCodeHeader.0 as usize] = &ms_nrtp_nrtpstatuscodeheader::DESC;
    t[ProtoId::NRTPCloseConnectionHeader.0 as usize] = &ms_nrtp_nrtpcloseconnectionheader::DESC;
    t[ProtoId::ArrayInfo.0 as usize] = &ms_nrtp_arrayinfo::DESC;
    t[ProtoId::NRBFArraySingleObject.0 as usize] = &ms_nrtp_nrbfarraysingleobject::DESC;
    t[ProtoId::NRBFMemberReference.0 as usize] = &ms_nrtp_nrbfmemberreference::DESC;
    t[ProtoId::NRBFObjectNull.0 as usize] = &ms_nrtp_nrbfobjectnull::DESC;
    t[ProtoId::NRBFMessageEnd.0 as usize] = &ms_nrtp_nrbfmessageend::DESC;
    t[ProtoId::OctetStringT.0 as usize] = &msrpce_ept_octet_string_t::DESC;
    t[ProtoId::PACINFOBUFFER.0 as usize] = &msrpce_mspac_pac_info_buffer::DESC;
    t[ProtoId::PACCREDENTIALINFO.0 as usize] = &msrpce_mspac_pac_credential_info::DESC;
    t[ProtoId::NBNSHeader.0 as usize] = &netbios_nbnsheader::DESC;
    t[ProtoId::NBNSADDENTRY.0 as usize] = &netbios_nbns_add_entry::DESC;
    t[ProtoId::NBNSNodeStatusResponseService.0 as usize] =
        &netbios_nbnsnodestatusresponseservice::DESC;
    t[ProtoId::NetflowHeader.0 as usize] = &netflow_netflowheader::DESC;
    t[ProtoId::NetflowRecordV1.0 as usize] = &netflow_netflowrecordv1::DESC;
    t[ProtoId::NetflowRecordV5.0 as usize] = &netflow_netflowrecordv5::DESC;
    t[ProtoId::NetflowRecordV9.0 as usize] = &netflow_netflowrecordv9::DESC;
    t[ProtoId::NetflowOptionsRecordScopeV9.0 as usize] = &netflow_netflowoptionsrecordscopev9::DESC;
    t[ProtoId::NetflowOptionsRecordOptionV9.0 as usize] =
        &netflow_netflowoptionsrecordoptionv9::DESC;
    t[ProtoId::NetflowOptionsFlowsetScopeV9.0 as usize] =
        &netflow_netflowoptionsflowsetscopev9::DESC;
    t[ProtoId::NTLMVersion.0 as usize] = &ntlm_ntlm_version::DESC;
    t[ProtoId::LMRESPONSE.0 as usize] = &ntlm_lm_response::DESC;
    t[ProtoId::LMv2RESPONSE.0 as usize] = &ntlm_lmv2_response::DESC;
    t[ProtoId::NTLMRESPONSE.0 as usize] = &ntlm_ntlm_response::DESC;
    t[ProtoId::NTLMSSPMESSAGESIGNATURE.0 as usize] = &ntlm_ntlmssp_message_signature::DESC;
    t[ProtoId::NTPSystemStatusPacketX.0 as usize] = &ntp_ntpsystemstatuspacket::DESC;
    t[ProtoId::NTPPeerStatusPacketX.0 as usize] = &ntp_ntppeerstatuspacket::DESC;
    t[ProtoId::NTPClockStatusPacketX.0 as usize] = &ntp_ntpclockstatuspacket::DESC;
    t[ProtoId::NTPErrorStatusPacketX.0 as usize] = &ntp_ntperrorstatuspacket::DESC;
    t[ProtoId::NTPInfoPeerListX.0 as usize] = &ntp_ntpinfopeerlist::DESC;
    t[ProtoId::NTPInfoPeerStatsX.0 as usize] = &ntp_ntpinfopeerstats::DESC;
    t[ProtoId::NTPInfoSysStatsX.0 as usize] = &ntp_ntpinfosysstats::DESC;
    t[ProtoId::NTPInfoIOStatsX.0 as usize] = &ntp_ntpinfoiostats::DESC;
    t[ProtoId::NTPInfoTimerStatsX.0 as usize] = &ntp_ntpinfotimerstats::DESC;
    t[ProtoId::NTPConfPeerX.0 as usize] = &ntp_ntpconfpeer::DESC;
    t[ProtoId::NTPConfUnpeerX.0 as usize] = &ntp_ntpconfunpeer::DESC;
    t[ProtoId::NTPConfRestrictX.0 as usize] = &ntp_ntpconfrestrict::DESC;
    t[ProtoId::NTPInfoKernelX.0 as usize] = &ntp_ntpinfokernel::DESC;
    t[ProtoId::NTPInfoIfStatsIPv4X.0 as usize] = &ntp_ntpinfoifstatsipv4::DESC;
    t[ProtoId::NTPInfoIfStatsIPv6X.0 as usize] = &ntp_ntpinfoifstatsipv6::DESC;
    t[ProtoId::NTPInfoMonitor1X.0 as usize] = &ntp_ntpinfomonitor1::DESC;
    t[ProtoId::NTPInfoAuthX.0 as usize] = &ntp_ntpinfoauth::DESC;
    t[ProtoId::NTPConfTrapX.0 as usize] = &ntp_ntpconftrap::DESC;
    t[ProtoId::NTPInfoControlX.0 as usize] = &ntp_ntpinfocontrol::DESC;
    t[ProtoId::NTPPrivateReqPacketX.0 as usize] = &ntp_ntpprivatereqpacket::DESC;
    t[ProtoId::PPPoETagX.0 as usize] = &ppp_pppoetag::DESC;
    t[ProtoId::PPPoEDTagsX.0 as usize] = &ppp_pppoed_tags::DESC;
    t[ProtoId::HDLCX.0 as usize] = &ppp_hdlc::DESC;
    t[ProtoId::DIRPPPX.0 as usize] = &ppp_dir_ppp::DESC;
    t[ProtoId::PPPECPOptionOUIX.0 as usize] = &ppp_ppp_ecp_option_oui::DESC;
    t[ProtoId::PPPLCPMRUOptionX.0 as usize] = &ppp_ppp_lcp_mru_option::DESC;
    t[ProtoId::PPPLCPACCMOptionX.0 as usize] = &ppp_ppp_lcp_accm_option::DESC;
    t[ProtoId::PPPLCPQualityProtocolOptionX.0 as usize] =
        &ppp_ppp_lcp_quality_protocol_option::DESC;
    t[ProtoId::PPPLCPMagicNumberOptionX.0 as usize] = &ppp_ppp_lcp_magic_number_option::DESC;
    t[ProtoId::PPPLCPCallbackOptionX.0 as usize] = &ppp_ppp_lcp_callback_option::DESC;
    t[ProtoId::PPPLCPTerminateX.0 as usize] = &ppp_ppp_lcp_terminate::DESC;
    t[ProtoId::PPPLCPDiscardRequestX.0 as usize] = &ppp_ppp_lcp_discard_request::DESC;
    t[ProtoId::PPPLCPEchoX.0 as usize] = &ppp_ppp_lcp_echo::DESC;
    t[ProtoId::PPTPStartControlConnectionRequest.0 as usize] =
        &pptp_pptpstartcontrolconnectionrequest::DESC;
    t[ProtoId::PPTPStartControlConnectionReply.0 as usize] =
        &pptp_pptpstartcontrolconnectionreply::DESC;
    t[ProtoId::PPTPStopControlConnectionRequest.0 as usize] =
        &pptp_pptpstopcontrolconnectionrequest::DESC;
    t[ProtoId::PPTPStopControlConnectionReply.0 as usize] =
        &pptp_pptpstopcontrolconnectionreply::DESC;
    t[ProtoId::PPTPEchoRequest.0 as usize] = &pptp_pptpechorequest::DESC;
    t[ProtoId::PPTPEchoReply.0 as usize] = &pptp_pptpechoreply::DESC;
    t[ProtoId::PPTPOutgoingCallRequest.0 as usize] = &pptp_pptpoutgoingcallrequest::DESC;
    t[ProtoId::PPTPOutgoingCallReply.0 as usize] = &pptp_pptpoutgoingcallreply::DESC;
    t[ProtoId::PPTPIncomingCallRequest.0 as usize] = &pptp_pptpincomingcallrequest::DESC;
    t[ProtoId::PPTPIncomingCallReply.0 as usize] = &pptp_pptpincomingcallreply::DESC;
    t[ProtoId::PPTPIncomingCallConnected.0 as usize] = &pptp_pptpincomingcallconnected::DESC;
    t[ProtoId::PPTPCallClearRequest.0 as usize] = &pptp_pptpcallclearrequest::DESC;
    t[ProtoId::PPTPCallDisconnectNotify.0 as usize] = &pptp_pptpcalldisconnectnotify::DESC;
    t[ProtoId::PPTPWANErrorNotify.0 as usize] = &pptp_pptpwanerrornotify::DESC;
    t[ProtoId::PPTPSetLinkInfo.0 as usize] = &pptp_pptpsetlinkinfo::DESC;
    t[ProtoId::QUICPADDING.0 as usize] = &quic_quic_padding::DESC;
    t[ProtoId::QUICPING.0 as usize] = &quic_quic_ping::DESC;
    t[ProtoId::QUICACK.0 as usize] = &quic_quic_ack::DESC;
    t[ProtoId::MSCHAP2Response.0 as usize] = &radius_ms_chap2_response::DESC;
    t[ProtoId::MSCHAP2Success.0 as usize] = &radius_ms_chap2_success::DESC;
    t[ProtoId::MSCHAPError.0 as usize] = &radius_ms_chap_error::DESC;
    t[ProtoId::MSCHAPDomain.0 as usize] = &radius_ms_chap_domain::DESC;
    t[ProtoId::RTPExtension.0 as usize] = &rtp_rtpextension::DESC;
    t[ProtoId::SCTPChunkParamIPv4Addr.0 as usize] = &sctp_sctpchunkparamipv4addr::DESC;
    t[ProtoId::SCTPChunkParamIPv6Addr.0 as usize] = &sctp_sctpchunkparamipv6addr::DESC;
    t[ProtoId::SCTPChunkParamCookiePreservative.0 as usize] =
        &sctp_sctpchunkparamcookiepreservative::DESC;
    t[ProtoId::SCTPChunkParamSSNTSNResetReq.0 as usize] = &sctp_sctpchunkparamssntsnresetreq::DESC;
    t[ProtoId::SCTPChunkParamReConfigRes.0 as usize] = &sctp_sctpchunkparamreconfigres::DESC;
    t[ProtoId::SCTPChunkParamAddOutgoingStreamReq.0 as usize] =
        &sctp_sctpchunkparamaddoutgoingstreamreq::DESC;
    t[ProtoId::SCTPChunkParamAddIncomingStreamReq.0 as usize] =
        &sctp_sctpchunkparamaddincomingstreamreq::DESC;
    t[ProtoId::SCTPChunkParamECNCapable.0 as usize] = &sctp_sctpchunkparamecncapable::DESC;
    t[ProtoId::SCTPChunkParamFwdTSN.0 as usize] = &sctp_sctpchunkparamfwdtsn::DESC;
    t[ProtoId::SCTPChunkParamSuccessIndication.0 as usize] =
        &sctp_sctpchunkparamsuccessindication::DESC;
    t[ProtoId::SCTPChunkParamAdaptationLayer.0 as usize] =
        &sctp_sctpchunkparamadaptationlayer::DESC;
    t[ProtoId::SCTPForwardSkip.0 as usize] = &sctp_sctpforwardskip::DESC;
    t[ProtoId::SCTPIForwardSkip.0 as usize] = &sctp_sctpiforwardskip::DESC;
    t[ProtoId::SCTPChunkShutdown.0 as usize] = &sctp_sctpchunkshutdown::DESC;
    t[ProtoId::SCTPChunkShutdownAck.0 as usize] = &sctp_sctpchunkshutdownack::DESC;
    t[ProtoId::SCTPChunkCookieAck.0 as usize] = &sctp_sctpchunkcookieack::DESC;
    t[ProtoId::SCTPChunkShutdownComplete.0 as usize] = &sctp_sctpchunkshutdowncomplete::DESC;
    t[ProtoId::LoWPANUncompressedIPv6.0 as usize] = &sixlowpan_lowpanuncompressedipv6::DESC;
    t[ProtoId::LoWPANHC2UDP.0 as usize] = &sixlowpan_lowpan_hc2_udp::DESC;
    t[ProtoId::LoWPANFragmentationFirst.0 as usize] = &sixlowpan_lowpanfragmentationfirst::DESC;
    t[ProtoId::LoWPANBroadcast.0 as usize] = &sixlowpan_lowpanbroadcast::DESC;
    t[ProtoId::SixLoWPANESC.0 as usize] = &sixlowpan_sixlowpan_esc::DESC;
    t[ProtoId::Skinny.0 as usize] = &skinny_skinny::DESC;
    t[ProtoId::SMBSessionNull.0 as usize] = &smb_smbsession_null::DESC;
    t[ProtoId::DcSockAddr.0 as usize] = &smb_dcsockaddr::DESC;
    t[ProtoId::FileAlignmentInformation.0 as usize] = &smb2_filealignmentinformation::DESC;
    t[ProtoId::FileEaInformation.0 as usize] = &smb2_fileeainformation::DESC;
    t[ProtoId::FileInternalInformation.0 as usize] = &smb2_fileinternalinformation::DESC;
    t[ProtoId::FilePositionInformation.0 as usize] = &smb2_filepositioninformation::DESC;
    t[ProtoId::FileStandardInformation.0 as usize] = &smb2_filestandardinformation::DESC;
    t[ProtoId::WINNTSIDIDENTIFIERAUTHORITY.0 as usize] = &smb2_winnt_sid_identifier_authority::DESC;
    t[ProtoId::FileFsSizeInformation.0 as usize] = &smb2_filefssizeinformation::DESC;
    t[ProtoId::SMB2FILEID.0 as usize] = &smb2_smb2_fileid::DESC;
    t[ProtoId::SMB2CREATEDURABLEHANDLERESPONSE.0 as usize] =
        &smb2_smb2_create_durable_handle_response::DESC;
    t[ProtoId::SMB2CREATEQUERYONDISKID.0 as usize] = &smb2_smb2_create_query_on_disk_id::DESC;
    t[ProtoId::SMB2CREATEDURABLEHANDLEREQUEST.0 as usize] =
        &smb2_smb2_create_durable_handle_request::DESC;
    t[ProtoId::SMB2CREATEQUERYMAXIMALACCESSREQUEST.0 as usize] =
        &smb2_smb2_create_query_maximal_access_request::DESC;
    t[ProtoId::SMB2CREATEALLOCATIONSIZE.0 as usize] = &smb2_smb2_create_allocation_size::DESC;
    t[ProtoId::SMB2CREATETIMEWARPTOKEN.0 as usize] = &smb2_smb2_create_timewarp_token::DESC;
    t[ProtoId::SMB2CREATEAPPINSTANCEID.0 as usize] = &smb2_smb2_create_app_instance_id::DESC;
    t[ProtoId::SMB2CREATEAPPINSTANCEVERSION.0 as usize] =
        &smb2_smb2_create_app_instance_version::DESC;
    t[ProtoId::SMB2IOCTLOFFLOADREADRequest.0 as usize] =
        &smb2_smb2_ioctl_offload_read_request::DESC;
    t[ProtoId::SMB2TransformHeader.0 as usize] = &smb2_smb2_transform_header::DESC;
    t[ProtoId::SMB2CompressionTransformHeader.0 as usize] =
        &smb2_smb2_compression_transform_header::DESC;
    t[ProtoId::NEGOEXEXTENSIONVECTOR.0 as usize] = &spnego_negoex_extension_vector::DESC;
    t[ProtoId::SSHNewKeys.0 as usize] = &ssh_sshnewkeys::DESC;
    t[ProtoId::SSHUnimplemented.0 as usize] = &ssh_sshunimplemented::DESC;
    t[ProtoId::SSHNewCompress.0 as usize] = &ssh_sshnewcompress::DESC;
    t[ProtoId::TFTPDATA.0 as usize] = &tftp_tftp_data::DESC;
    t[ProtoId::TFTPACK.0 as usize] = &tftp_tftp_ack::DESC;
    t[ProtoId::UnEncryptedPreMasterSecret.0 as usize] =
        &tls_keyexchange_unencryptedpremastersecret::DESC;
    t[ProtoId::ClientPSKIdentity.0 as usize] = &tls_keyexchange_clientpskidentity::DESC;
    t[ProtoId::PSKBinderEntry.0 as usize] = &tls_keyexchange_tls13_pskbinderentry::DESC;
    t[ProtoId::TLSEncryptedContent.0 as usize] = &tls_record_tlsencryptedcontent::DESC;
    t[ProtoId::TLSChangeCipherSpec.0 as usize] = &tls_record_tlschangecipherspec::DESC;
    t[ProtoId::TLSAlert.0 as usize] = &tls_record_tlsalert::DESC;
    t[ProtoId::TLSApplicationData.0 as usize] = &tls_record_tlsapplicationdata::DESC;
    t[ProtoId::TLSPlaintext.0 as usize] = &tls_tools_tlsplaintext::DESC;
    t[ProtoId::TLSCompressed.0 as usize] = &tls_tools_tlscompressed::DESC;
    t[ProtoId::TLSCiphertext.0 as usize] = &tls_tools_tlsciphertext::DESC;
    t[ProtoId::TPMSSCHEMESIGHASH.0 as usize] = &tpm_tpms_scheme_sighash::DESC;
    t[ProtoId::TPMSNULLPARMS.0 as usize] = &tpm_tpms_null_parms::DESC;
    t[ProtoId::TPM2BPRIVATEKEYRSA.0 as usize] = &tpm_tpm2b_private_key_rsa::DESC;
    t[ProtoId::TPM2BDIGESTX.0 as usize] = &tpm_tpm2b_digest::DESC;
    t[ProtoId::TPM2BNAME.0 as usize] = &tpm_tpm2b_name::DESC;
    t[ProtoId::TPM2BDATA.0 as usize] = &tpm_tpm2b_data::DESC;
    t[ProtoId::TPMALOCALITY.0 as usize] = &tpm_tpma_locality::DESC;
    t[ProtoId::TPMSPCRSELECTION.0 as usize] = &tpm_tpms_pcr_selection::DESC;
    t[ProtoId::TPMLPCRSELECTION.0 as usize] = &tpm_tpml_pcr_selection::DESC;
    t[ProtoId::TPMSCLOCKINFO.0 as usize] = &tpm_tpms_clock_info::DESC;
    t[ProtoId::TPM2BPUBLICKEYRSA.0 as usize] = &tpm_tpm2b_public_key_rsa::DESC;
    t[ProtoId::DarwinUtunPacketInfo.0 as usize] = &tuntap_darwinutunpacketinfo::DESC;
    t[ProtoId::USBpcapTransferIsochronous.0 as usize] = &usb_usbpcaptransferisochronous::DESC;
    t[ProtoId::USBpcapTransferInterrupt.0 as usize] = &usb_usbpcaptransferinterrupt::DESC;
    t[ProtoId::USBpcapTransferControl.0 as usize] = &usb_usbpcaptransfercontrol::DESC;
    t[ProtoId::LinkStatusEntry.0 as usize] = &zigbee_linkstatusentry::DESC;
    t[ProtoId::ZDPActiveEPReq.0 as usize] = &zigbee_zdpactiveepreq::DESC;
    t[ProtoId::ZCLGeneralReadAttributes.0 as usize] = &zigbee_zclgeneralreadattributes::DESC;
    t[ProtoId::ZCLGeneralDefaultResponse.0 as usize] = &zigbee_zclgeneraldefaultresponse::DESC;
    t[ProtoId::ZCLIASZoneZoneEnrollResponse.0 as usize] =
        &zigbee_zcliaszonezoneenrollresponse::DESC;
    t[ProtoId::ZCLIASZoneZoneStatusChangeNotification.0 as usize] =
        &zigbee_zcliaszonezonestatuschangenotification::DESC;
    t[ProtoId::ZCLMeteringGetProfile.0 as usize] = &zigbee_zclmeteringgetprofile::DESC;
    t[ProtoId::ZCLPriceGetCurrentPrice.0 as usize] = &zigbee_zclpricegetcurrentprice::DESC;
    t[ProtoId::ZCLPriceGetScheduledPrices.0 as usize] = &zigbee_zclpricegetscheduledprices::DESC;
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
        ProtoId::ATTFindByTypeValueResponse => {
            Some(&crate::layers::bluetooth_att_find_by_type_value_response::GROUP)
        }
        ProtoId::ATTReadMultipleRequest => {
            Some(&crate::layers::bluetooth_att_read_multiple_request::GROUP)
        }
        ProtoId::EDNS0DAU => Some(&crate::layers::dns_edns0dau::GROUP),
        ProtoId::EDNS0DHU => Some(&crate::layers::dns_edns0dhu::GROUP),
        ProtoId::EDNS0N3U => Some(&crate::layers::dns_edns0n3u::GROUP),
        ProtoId::SubelemTLV => Some(&crate::layers::dot11_subelemtlv::GROUP),
        ProtoId::IPOptionRR => Some(&crate::layers::inet_ipoption_rr::GROUP),
        ProtoId::IPOptionLSRR => Some(&crate::layers::inet_ipoption_lsrr::GROUP),
        ProtoId::IPOptionSSRR => Some(&crate::layers::inet_ipoption_ssrr::GROUP),
        ProtoId::IPOptionSDBM => Some(&crate::layers::inet_ipoption_sdbm::GROUP),
        ProtoId::LLTDDiscover => Some(&crate::layers::lltd_lltddiscover::GROUP),
        ProtoId::LLTDEmit => Some(&crate::layers::lltd_lltdemit::GROUP),
        ProtoId::PPPoEDTagsX => Some(&crate::layers::ppp_pppoed_tags::GROUP),
        ProtoId::RTPExtension => Some(&crate::layers::rtp_rtpextension::GROUP),
        ProtoId::TPMLPCRSELECTION => Some(&crate::layers::tpm_tpml_pcr_selection::GROUP),
        ProtoId::ZCLGeneralReadAttributes => {
            Some(&crate::layers::zigbee_zclgeneralreadattributes::GROUP)
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
        ProtoId::ATTFindByTypeValueResponse => "handles",
        ProtoId::ATTReadMultipleRequest => "handles",
        ProtoId::EDNS0DAU => "alg_code",
        ProtoId::EDNS0DHU => "alg_code",
        ProtoId::EDNS0N3U => "alg_code",
        ProtoId::SubelemTLV => "value",
        ProtoId::IPOptionRR => "routers",
        ProtoId::IPOptionLSRR => "routers",
        ProtoId::IPOptionSSRR => "routers",
        ProtoId::IPOptionSDBM => "addresses",
        ProtoId::LLTDDiscover => "stations_list",
        ProtoId::LLTDEmit => "descs_list",
        ProtoId::PPPoEDTagsX => "tag_list",
        ProtoId::RTPExtension => "header",
        ProtoId::TPMLPCRSELECTION => "pcrSelections",
        ProtoId::ZCLGeneralReadAttributes => "attribute_identifiers",
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
    /// Values are already in wire form.
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
    let conds = conds
        .into_iter()
        .map(|(f, v)| (f, field::wire_uint(f, v)))
        .collect::<Vec<_>>();
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
        .find(|b| {
            b.parent == parent
                && b.conds
                    .iter()
                    .all(|(f, v)| field::read_bits(hdr, f.bit_off, f.bit_len) == *v)
        })
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
            field::write_bits(hdr, f.bit_off, f.bit_len, *v);
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
