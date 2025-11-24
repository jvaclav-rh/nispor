// SPDX-License-Identifier: Apache-2.0
use std::{collections::HashMap, net::IpAddr, str::FromStr};

use rtnetlink::packet_route::{
    link::{InfoData, InfoIpTunnel},
    IpProtocol,
};
use serde::{Deserialize, Serialize};

use crate::{Iface, IfaceType, NisporError};

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone, Copy)]
#[non_exhaustive]
#[serde(rename_all = "snake_case")]
pub enum TunnelEncapFlags {
    CSum,
    CSum6,
    RemCSum,
    Other(u16),
}

impl From<TunnelEncapFlags>
    for rtnetlink::packet_route::link::TunnelEncapFlags
{
    fn from(d: TunnelEncapFlags) -> Self {
        match d {
            TunnelEncapFlags::CSum => Self::CSum,
            TunnelEncapFlags::CSum6 => Self::CSum6,
            TunnelEncapFlags::RemCSum => Self::RemCSum,
            TunnelEncapFlags::Other(d) => rtnetlink::packet_route::link::TunnelEncapFlags::from_bits_retain(d),
        }
    }
}

impl From<rtnetlink::packet_route::link::TunnelEncapFlags>
    for TunnelEncapFlags
{
    fn from(d: rtnetlink::packet_route::link::TunnelEncapFlags) -> Self {
        match d {
            rtnetlink::packet_route::link::TunnelEncapFlags::CSum => Self::CSum,
            rtnetlink::packet_route::link::TunnelEncapFlags::CSum6 => {
                Self::CSum6
            }
            rtnetlink::packet_route::link::TunnelEncapFlags::RemCSum => {
                Self::RemCSum
            }
            _ => Self::Other(d.bits()),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone, Copy)]
#[non_exhaustive]
#[serde(rename_all = "snake_case")]
pub enum TunnelEncapType {
    None,
    Fou,
    Gue,
    Mpls,
    Other(u16),
}

impl From<TunnelEncapType> for rtnetlink::packet_route::link::TunnelEncapType {
    fn from(d: TunnelEncapType) -> Self {
        match d {
            TunnelEncapType::None => Self::None,
            TunnelEncapType::Fou => Self::Fou,
            TunnelEncapType::Gue => Self::Gue,
            TunnelEncapType::Mpls => Self::Mpls,
            TunnelEncapType::Other(d) => Self::Other(d),
        }
    }
}

impl From<rtnetlink::packet_route::link::TunnelEncapType> for TunnelEncapType {
    fn from(d: rtnetlink::packet_route::link::TunnelEncapType) -> Self {
        match d {
            rtnetlink::packet_route::link::TunnelEncapType::None => Self::None,
            rtnetlink::packet_route::link::TunnelEncapType::Fou => Self::Fou,
            rtnetlink::packet_route::link::TunnelEncapType::Gue => Self::Gue,
            rtnetlink::packet_route::link::TunnelEncapType::Mpls => Self::Mpls,
            rtnetlink::packet_route::link::TunnelEncapType::Other(d) => {
                Self::Other(d)
            }
            _ => Self::Other(d.into()),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone, Copy)]
#[non_exhaustive]
#[serde(rename_all = "snake_case")]
pub enum Ip6TunnelFlags {
    IgnEncapLimit,
    UseOrigTclass,
    UseOrigFlowlabel,
    Mip6Dev,
    RcvDscpCopy,
    UseOrigFwMark,
    AllowLocalRemote,
    CapXmit,
    CapRcv,
    CapPerPacket,
    Other(u32),
}

impl From<rtnetlink::packet_route::link::Ip6TunnelFlags> for Ip6TunnelFlags {
    fn from(d: rtnetlink::packet_route::link::Ip6TunnelFlags) -> Self {
        match d {
            rtnetlink::packet_route::link::Ip6TunnelFlags::IgnEncapLimit => {
                Self::IgnEncapLimit
            }
            rtnetlink::packet_route::link::Ip6TunnelFlags::UseOrigTclass => {
                Self::UseOrigTclass
            }
            rtnetlink::packet_route::link::Ip6TunnelFlags::UseOrigFlowlabel => {
                Self::UseOrigFlowlabel
            }
            rtnetlink::packet_route::link::Ip6TunnelFlags::Mip6Dev => {
                Self::Mip6Dev
            }
            rtnetlink::packet_route::link::Ip6TunnelFlags::RcvDscpCopy => {
                Self::RcvDscpCopy
            }
            rtnetlink::packet_route::link::Ip6TunnelFlags::UseOrigFwMark => {
                Self::UseOrigFwMark
            }
            rtnetlink::packet_route::link::Ip6TunnelFlags::AllowLocalRemote => {
                Self::AllowLocalRemote
            }
            rtnetlink::packet_route::link::Ip6TunnelFlags::CapXmit => {
                Self::CapXmit
            }
            rtnetlink::packet_route::link::Ip6TunnelFlags::CapRcv => {
                Self::CapRcv
            }
            rtnetlink::packet_route::link::Ip6TunnelFlags::CapPerPacket => {
                Self::CapPerPacket
            }
            _ => Self::Other(d.bits()),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
#[serde(into = "String")]
#[serde(try_from = "String")]
#[non_exhaustive]
pub enum IpTunnelFlags {
    Ipv4Flags(u16),
    Ipv6SitFlags(u16),
    Ipv6Flags(Vec<Ip6TunnelFlags>),
}

fn parse_flag_integer_u16(s: &str) -> Result<u16, NisporError> {
    u16::from_str_radix(s.strip_prefix("0x").unwrap_or(s), 16).map_err(|e| {
        NisporError::invalid_argument(format!("Invalid flag integer: {}", e))
    })
}

fn parse_flag_integer_u32(s: &str) -> Result<u32, NisporError> {
    u32::from_str_radix(s.strip_prefix("0x").unwrap_or(s), 16).map_err(|e| {
        NisporError::invalid_argument(format!("Invalid flag integer: {}", e))
    })
}

impl std::fmt::Display for Ip6TunnelFlags {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::IgnEncapLimit => write!(f, "ign_encap_limit"),
            Self::UseOrigTclass => write!(f, "use_orig_tclass"),
            Self::UseOrigFlowlabel => write!(f, "use_orig_flowlabel"),
            Self::Mip6Dev => write!(f, "mip6_dev"),
            Self::RcvDscpCopy => write!(f, "rcv_dscp_copy"),
            Self::UseOrigFwMark => write!(f, "use_orig_fw_mark"),
            Self::AllowLocalRemote => write!(f, "allow_local_remote"),
            Self::CapXmit => write!(f, "cap_xmit"),
            Self::CapRcv => write!(f, "cap_rcv"),
            Self::CapPerPacket => write!(f, "cap_per_packet"),
            Self::Other(val) => write!(f, "0x{:x}", val),
        }
    }
}

impl FromStr for Ip6TunnelFlags {
    type Err = NisporError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "ign_encap_limit" => Ok(Self::IgnEncapLimit),
            "use_orig_tclass" => Ok(Self::UseOrigTclass),
            "use_orig_flowlabel" => Ok(Self::UseOrigFlowlabel),
            "mip6_dev" => Ok(Self::Mip6Dev),
            "rcv_dscp_copy" => Ok(Self::RcvDscpCopy),
            "use_orig_fw_mark" => Ok(Self::UseOrigFwMark),
            "allow_local_remote" => Ok(Self::AllowLocalRemote),
            "cap_xmit" => Ok(Self::CapXmit),
            "cap_rcv" => Ok(Self::CapRcv),
            "cap_per_packet" => Ok(Self::CapPerPacket),
            _ => Ok(Self::Other(parse_flag_integer_u32(s)?)),
        }
    }
}

impl std::fmt::Display for IpTunnelFlags {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ipv4Flags(flags) => {
                write!(f, "ipv4:0x{:x}", flags)
            }
            Self::Ipv6SitFlags(flags) => {
                write!(f, "ipv6_sit:0x{:x}", flags)
            }
            Self::Ipv6Flags(flags) => {
                write!(
                    f,
                    "ipv6:{}",
                    flags
                        .iter()
                        .map(|flag| flag.to_string())
                        .collect::<Vec<String>>()
                        .join(",")
                )
            }
        }
    }
}

impl TryFrom<String> for IpTunnelFlags {
    type Error = NisporError;

    fn try_from(v: String) -> Result<Self, Self::Error> {
        let (flag_type, flags) = v.split_once(":").ok_or_else(|| {
            NisporError::invalid_argument(format!(
                "Invalid IpTunnelFlags: {}",
                v
            ))
        })?;

        match flag_type {
            "ipv4" => {
                Ok(IpTunnelFlags::Ipv4Flags(parse_flag_integer_u16(flags)?))
            }
            "ipv6_sit" => {
                Ok(IpTunnelFlags::Ipv6SitFlags(parse_flag_integer_u16(flags)?))
            }
            "ipv6" => Ok(IpTunnelFlags::Ipv6Flags(
                flags
                    .split(',')
                    .map(|flag| {
                        Ip6TunnelFlags::from_str(flag).map_err(|_| {
                            NisporError::invalid_argument(format!(
                                "Invalid Ip6TunnelFlags: {}",
                                flag
                            ))
                        })
                    })
                    .collect::<Result<Vec<Ip6TunnelFlags>, NisporError>>()?,
            )),
            _ => Err(NisporError::invalid_argument(format!(
                "Invalid IpTunnelFlags type: {}",
                flag_type
            ))),
        }
    }
}

impl From<IpTunnelFlags> for String {
    fn from(flags: IpTunnelFlags) -> Self {
        flags.to_string()
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone, Copy)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
#[derive(Default)]
pub enum IpTunnelMode {
    #[default]
    Unknown,
    Ipip,
    Sit,
    Ip6ip6,
    Ipip6,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone, Default)]
#[non_exhaustive]
pub struct IpTunnelInfo {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub local: Option<IpAddr>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub remote: Option<IpAddr>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent: Option<String>,

    pub mode: IpTunnelMode,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttl: Option<u8>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub tos: Option<u8>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub flags: Option<IpTunnelFlags>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub pmtu_disc: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub encap_limit: Option<u8>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub flow_info: Option<u32>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub encap_type: Option<TunnelEncapType>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub encap_flags: Option<Vec<TunnelEncapFlags>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub encap_source_port: Option<u16>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub encap_destination_port: Option<u16>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub collect_metadata: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub fwmark: Option<u32>,

    #[serde(skip_serializing)]
    _parent_ifindex: Option<u32>,
}

pub(crate) fn get_ip_tunnel_info(
    data: &InfoData,
    if_type: IfaceType,
) -> Option<IpTunnelInfo> {
    let mut ip_tunnel_info = IpTunnelInfo::default();
    let mut protocol: Option<IpProtocol> = None;

    if let InfoData::IpTunnel(infos) = data {
        for info in infos {
            match *info {
                InfoIpTunnel::Local(d) => {
                    ip_tunnel_info.local = Some(d);
                }
                InfoIpTunnel::Remote(d) => {
                    ip_tunnel_info.remote = Some(d);
                }
                InfoIpTunnel::Link(d) => {
                    ip_tunnel_info._parent_ifindex = Some(d);
                }
                InfoIpTunnel::Ttl(d) => {
                    ip_tunnel_info.ttl = Some(d);
                }
                InfoIpTunnel::Tos(d) => {
                    ip_tunnel_info.tos = Some(d);
                }
                InfoIpTunnel::FlowInfo(d) => {
                    ip_tunnel_info.flow_info = Some(d);
                }
                InfoIpTunnel::Ipv6SitFlags(d) => {
                    ip_tunnel_info.flags = Some(IpTunnelFlags::Ipv6SitFlags(d));
                }
                InfoIpTunnel::Ipv4Flags(d) => {
                    ip_tunnel_info.flags = Some(IpTunnelFlags::Ipv4Flags(d));
                }
                InfoIpTunnel::Ipv6Flags(d) => {
                    ip_tunnel_info.flags = Some(IpTunnelFlags::Ipv6Flags(
                        d.iter().map(Ip6TunnelFlags::from).collect(),
                    ));
                }
                InfoIpTunnel::Protocol(d) => {
                    protocol = Some(d);
                }
                InfoIpTunnel::PMtuDisc(d) => {
                    ip_tunnel_info.pmtu_disc = Some(d);
                }
                InfoIpTunnel::EncapLimit(d) => {
                    ip_tunnel_info.encap_limit = Some(d);
                }
                InfoIpTunnel::EncapType(d) => {
                    ip_tunnel_info.encap_type = Some(d.into());
                }
                InfoIpTunnel::EncapFlags(d) => {
                    ip_tunnel_info.encap_flags =
                        Some(d.iter().map(TunnelEncapFlags::from).collect());
                }
                InfoIpTunnel::EncapSPort(d) => {
                    ip_tunnel_info.encap_source_port = Some(d);
                }
                InfoIpTunnel::EncapDPort(d) => {
                    ip_tunnel_info.encap_destination_port = Some(d);
                }
                InfoIpTunnel::CollectMetadata(d) => {
                    ip_tunnel_info.collect_metadata = Some(d);
                }
                InfoIpTunnel::FwMark(d) => {
                    ip_tunnel_info.fwmark = Some(d);
                }
                _ => {}
            }
        }

        ip_tunnel_info.mode = match (protocol, if_type) {
            (_, IfaceType::SitTun) => IpTunnelMode::Sit,
            (_, IfaceType::Ipip) => IpTunnelMode::Ipip,
            (Some(IpProtocol::Ipip), IfaceType::Ip6Tnl) => IpTunnelMode::Ipip6,
            (Some(IpProtocol::Ipv6), IfaceType::Ip6Tnl) => IpTunnelMode::Ip6ip6,
            _ => IpTunnelMode::Unknown,
        };

        Some(ip_tunnel_info)
    } else {
        None
    }
}

pub(crate) fn ip_tunnel_iface_tidy_up(
    iface_states: &mut HashMap<String, Iface>,
) {
    fill_port_iface_names(iface_states);
}

fn fill_port_iface_names(iface_states: &mut HashMap<String, Iface>) {
    let mut index_to_name = HashMap::new();
    for iface in iface_states.values() {
        index_to_name.insert(iface.index, iface.name.clone());
    }

    for iface in iface_states.values_mut() {
        if let Some(tun) = iface.ip_tunnel.as_mut() {
            if let Some(parent_iface_name) =
                index_to_name.get(&tun._parent_ifindex.unwrap_or_default())
            {
                tun.parent = Some(parent_iface_name.to_string());
            }
        }
    }
}
