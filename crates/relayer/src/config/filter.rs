//! Custom `serde` deserializer for `FilterMatch`

use core::fmt;
use core::str::FromStr;
use itertools::Itertools;
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;
use std::collections::HashMap;
use std::hash::Hash;

use ibc_relayer_types::applications::transfer::RawCoin;
use ibc_relayer_types::bigint::U256;
use ibc_relayer_types::core::ics24_host::identifier::{ChannelId, PortId};
use ibc_relayer_types::events::IbcEventType;

/// Represents all the filtering policies for packets.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PacketFilter {
    #[serde(flatten)]
    pub channel_policy: ChannelPolicy,
    #[serde(default)]
    pub min_fees: HashMap<ChannelFilterMatch, FeePolicy>,
    #[serde(default)]
    pub hook_policy: HashMap<ChannelFilterMatch, HookPolicy>,
}

impl Default for PacketFilter {
    /// By default, allows all channels & ports.
    fn default() -> Self {
        Self {
            channel_policy: ChannelPolicy::default(),
            min_fees: HashMap::new(),
            hook_policy: HashMap::new(),
        }
    }
}

impl PacketFilter {
    pub fn new(
        channel_policy: ChannelPolicy,
        min_fees: HashMap<ChannelFilterMatch, FeePolicy>,
        hook_policy: HashMap<ChannelFilterMatch, HookPolicy>,
    ) -> Self {
        Self {
            channel_policy,
            min_fees,
            hook_policy,
        }
    }

    pub fn allow(filters: Vec<(PortFilterMatch, ChannelFilterMatch)>) -> PacketFilter {
        PacketFilter::new(
            ChannelPolicy::Allow(ChannelFilters::new(filters)),
            HashMap::new(),
            HashMap::new(),
        )
    }
}

/// Represents the ways in which packets can be filtered.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    rename_all = "lowercase",
    tag = "policy",
    content = "list",
    deny_unknown_fields
)]
pub enum ChannelPolicy {
    /// Allow packets from the specified channels.
    Allow(ChannelFilters),
    /// Deny packets from the specified channels.
    Deny(ChannelFilters),
    /// Allow any & all packets.
    AllowAll,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    rename_all = "lowercase",
    tag = "policy",
    content = "list",
    deny_unknown_fields
)]
pub enum HookPolicy {
    /// Allow packets from the specified channels.
    Allow(HookFilters),
    /// Allow any & all packets.
    AllowAll,
}

impl Default for HookPolicy {
    /// By default, allows all channels & ports.
    fn default() -> Self {
        Self::AllowAll
    }
}

impl HookPolicy {
    /// Returns true if the packets can be relayed on the channel with [`PortId`] and [`ChannelId`],
    /// false otherwise.
    pub fn is_allowed(&self, data: &Vec<u8>) -> bool {
        match self {
            HookPolicy::Allow(filters) => filters.matches(data),
            HookPolicy::AllowAll => true,
        }
    }
}

/// Represents the policy used to filter incentivized packets.
/// Currently only filtering on `recv_fee` is authorized.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeePolicy {
    recv: Vec<MinFee>,
}

impl FeePolicy {
    pub fn new(recv: Vec<MinFee>) -> Self {
        Self { recv }
    }

    pub fn should_relay(&self, event_type: IbcEventType, fees: &[RawCoin]) -> bool {
        match event_type {
            IbcEventType::SendPacket => fees
                .iter()
                .any(|fee| self.recv.iter().any(|e| e.is_enough(fee))),
            _ => true,
        }
    }
}

/// Represents the minimum fee authorized when filtering.
/// If no denom is specified, any denom is allowed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MinFee {
    amount: u64,
    denom: Option<String>,
}

impl MinFee {
    pub fn new(amount: u64, denom: Option<String>) -> Self {
        Self { amount, denom }
    }

    pub fn is_enough(&self, fee: &RawCoin) -> bool {
        match self.denom.clone() {
            Some(denom) => fee.amount.0 >= U256::from(self.amount) && denom.eq(&fee.denom),
            None => fee.amount.0 >= U256::from(self.amount),
        }
    }
}

impl Default for ChannelPolicy {
    /// By default, allows all channels & ports.
    fn default() -> Self {
        Self::AllowAll
    }
}

impl ChannelPolicy {
    /// Returns true if the packets can be relayed on the channel with [`PortId`] and [`ChannelId`],
    /// false otherwise.
    pub fn is_allowed(&self, port_id: &PortId, channel_id: &ChannelId) -> bool {
        match self {
            ChannelPolicy::Allow(filters) => filters.matches((port_id, channel_id)),
            ChannelPolicy::Deny(filters) => !filters.matches((port_id, channel_id)),
            ChannelPolicy::AllowAll => true,
        }
    }
}

/// The internal representation of channel filter policies.
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChannelFilters(Vec<(PortFilterMatch, ChannelFilterMatch)>);

impl ChannelFilters {
    /// Create a new filter from the given list of port/channel filters.
    pub fn new(filters: Vec<(PortFilterMatch, ChannelFilterMatch)>) -> Self {
        Self(filters)
    }

    /// Returns the number of filters.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns true if there are no filters, false otherwise.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Indicates whether a match for the given [`PortId`]-[`ChannelId`] pair
    /// exists in the filter policy.
    pub fn matches(&self, channel_port: (&PortId, &ChannelId)) -> bool {
        let (port_id, channel_id) = channel_port;
        self.0.iter().any(|(port_filter, chan_filter)| {
            port_filter.matches(port_id) && chan_filter.matches(channel_id)
        })
    }

    /// Indicates whether this filter policy contains only exact patterns.
    #[inline]
    pub fn is_exact(&self) -> bool {
        self.0.iter().all(|(port_filter, channel_filter)| {
            port_filter.is_exact() && channel_filter.is_exact()
        })
    }

    /// An iterator over the [`PortId`]-[`ChannelId`] pairs that don't contain wildcards.
    pub fn iter_exact(&self) -> impl Iterator<Item = (&PortId, &ChannelId)> {
        self.0.iter().filter_map(|port_chan_filter| {
            if let &(FilterPattern::Exact(ref port_id), FilterPattern::Exact(ref chan_id)) =
                port_chan_filter
            {
                Some((port_id, chan_id))
            } else {
                None
            }
        })
    }
}

impl fmt::Display for ChannelFilters {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            self.0
                .iter()
                .map(|(pid, cid)| format!("{pid}/{cid}"))
                .join(", ")
        )
    }
}

impl Serialize for ChannelFilters {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        use serde::ser::SerializeSeq;

        struct Pair<'a> {
            a: &'a FilterPattern<PortId>,
            b: &'a FilterPattern<ChannelId>,
        }

        impl<'a> Serialize for Pair<'a> {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                let mut seq = serializer.serialize_seq(Some(2))?;
                seq.serialize_element(self.a)?;
                seq.serialize_element(self.b)?;
                seq.end()
            }
        }

        let mut outer_seq = serializer.serialize_seq(Some(self.0.len()))?;

        for (port, channel) in &self.0 {
            outer_seq.serialize_element(&Pair {
                a: port,
                b: channel,
            })?;
        }

        outer_seq.end()
    }
}

/// Newtype wrapper for expressing wildcard patterns compiled to a [`regex::Regex`].
#[derive(Clone, Debug)]
pub struct Wildcard {
    pattern: String,
    regex: regex::Regex,
}

impl Wildcard {
    pub fn new(pattern: String) -> Result<Self, regex::Error> {
        let escaped = regex::escape(&pattern).replace("\\*", "(?:.*)");
        let regex = format!("^{escaped}$").parse()?;
        Ok(Self { pattern, regex })
    }

    #[inline]
    pub fn is_match(&self, text: &str) -> bool {
        self.regex.is_match(text)
    }
}

impl FromStr for Wildcard {
    type Err = regex::Error;

    fn from_str(pattern: &str) -> Result<Self, Self::Err> {
        Self::new(pattern.to_string())
    }
}

impl fmt::Display for Wildcard {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.pattern)
    }
}

impl Serialize for Wildcard {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.pattern)
    }
}

impl PartialEq for Wildcard {
    fn eq(&self, other: &Self) -> bool {
        self.pattern == other.pattern
    }
}

impl Eq for Wildcard {}

impl Hash for Wildcard {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.pattern.hash(state);
    }
}

/// Represents a single channel to be filtered in a [`ChannelFilters`] list.
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub enum FilterPattern<T> {
    /// A channel specified exactly with its [`PortId`] & [`ChannelId`].
    Exact(T),
    /// A glob of channel(s) specified with a wildcard in either or both [`PortId`] & [`ChannelId`].
    Wildcard(Wildcard),
}

impl<T> FilterPattern<T> {
    /// Indicates whether this filter is specified in part with a wildcard.
    pub fn is_wildcard(&self) -> bool {
        matches!(self, Self::Wildcard(_))
    }

    /// Indicates whether this filter is specified as an exact match.
    pub fn is_exact(&self) -> bool {
        matches!(self, Self::Exact(_))
    }

    /// Matches the given value via strict equality if the filter is an `Exact`, or via
    /// wildcard matching if the filter is a `Pattern`.
    pub fn matches(&self, value: &T) -> bool
    where
        T: PartialEq + ToString,
    {
        match self {
            FilterPattern::Exact(v) => value == v,
            FilterPattern::Wildcard(regex) => regex.is_match(&value.to_string()),
        }
    }

    /// Returns the contained value if this filter contains an `Exact` variant, or
    /// `None` if it contains a `Pattern`.
    pub fn exact_value(&self) -> Option<&T> {
        match self {
            FilterPattern::Exact(value) => Some(value),
            FilterPattern::Wildcard(_) => None,
        }
    }
}

impl<T: fmt::Display> fmt::Display for FilterPattern<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FilterPattern::Exact(value) => write!(f, "{value}"),
            FilterPattern::Wildcard(regex) => write!(f, "{regex}"),
        }
    }
}

impl<T> Serialize for FilterPattern<T>
where
    T: ToString,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            FilterPattern::Exact(e) => serializer.serialize_str(&e.to_string()),
            FilterPattern::Wildcard(t) => serializer.serialize_str(&t.to_string()),
        }
    }
}

/// Type alias for a [`FilterPattern`] containing a [`PortId`].
pub type PortFilterMatch = FilterPattern<PortId>;
/// Type alias for a [`FilterPattern`] containing a [`ChannelId`].
pub type ChannelFilterMatch = FilterPattern<ChannelId>;

pub type StringFilterMatch = FilterPattern<String>;

impl<'de> Deserialize<'de> for PortFilterMatch {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<PortFilterMatch, D::Error> {
        deserializer.deserialize_string(port::PortFilterMatchVisitor)
    }
}

impl<'de> Deserialize<'de> for ChannelFilterMatch {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<ChannelFilterMatch, D::Error> {
        deserializer.deserialize_string(channel::ChannelFilterMatchVisitor)
    }
}

impl<'de> Deserialize<'de> for StringFilterMatch {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<StringFilterMatch, D::Error> {
        deserializer.deserialize_string(StringFilterMatchVisitor)
    }
}

pub(crate) mod port {
    use super::*;
    use ibc_relayer_types::core::ics24_host::identifier::PortId;

    pub struct PortFilterMatchVisitor;

    impl<'de> de::Visitor<'de> for PortFilterMatchVisitor {
        type Value = PortFilterMatch;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("valid PortId or wildcard")
        }

        fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
            if let Ok(port_id) = PortId::from_str(v) {
                Ok(PortFilterMatch::Exact(port_id))
            } else {
                let wildcard = v.parse().map_err(E::custom)?;
                Ok(PortFilterMatch::Wildcard(wildcard))
            }
        }

        fn visit_string<E: de::Error>(self, v: String) -> Result<Self::Value, E> {
            self.visit_str(&v)
        }
    }
}

pub(crate) mod channel {
    use super::*;
    use ibc_relayer_types::core::ics24_host::identifier::ChannelId;

    pub struct ChannelFilterMatchVisitor;

    impl<'de> de::Visitor<'de> for ChannelFilterMatchVisitor {
        type Value = ChannelFilterMatch;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("valid ChannelId or wildcard")
        }

        fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
            if let Ok(channel_id) = ChannelId::from_str(v) {
                Ok(ChannelFilterMatch::Exact(channel_id))
            } else {
                let wildcard = v.parse().map_err(E::custom)?;
                Ok(ChannelFilterMatch::Wildcard(wildcard))
            }
        }

        fn visit_string<E: de::Error>(self, v: String) -> Result<Self::Value, E> {
            self.visit_str(&v)
        }
    }
}

pub struct StringFilterMatchVisitor;

impl<'de> de::Visitor<'de> for StringFilterMatchVisitor {
    type Value = StringFilterMatch;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("valid Filter or wildcard")
    }

    fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
        let res = str_to_string_filter_match(v);
        Ok(res)
    }

    fn visit_string<E: de::Error>(self, v: String) -> Result<Self::Value, E> {
        self.visit_str(&v)
    }
}

fn str_to_string_filter_match(s: &str) -> StringFilterMatch {
    if s.contains("*") {
        let wildcard = s.parse().unwrap();
        StringFilterMatch::Wildcard(wildcard)
    } else {
        StringFilterMatch::Exact(s.to_string())
    }
}


/// The internal representation of channel filter policies.
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HookFilters(Vec<HookFilterMatchString>);

pub type HookFilterMatchString = String;
impl Into<HookFilterMatch> for HookFilterMatchString {
    fn into(self) -> HookFilterMatch {
        let separate = self.split("::");
        let mut iter = separate.into_iter();
        let key = iter.next().unwrap_or("");
        if key == "move" {
            let module_address = iter.next();
            let module_name = iter.next();
            let function_name = iter.next();
            
            if !(function_name.is_none() || module_name.is_none() || module_address.is_none()) {
                return HookFilterMatch::MoveFilterMatch { 
                    module_address: module_address.unwrap().to_string(),
                    module_name: str_to_string_filter_match(module_name.unwrap()),
                    function_name: str_to_string_filter_match(function_name.unwrap()),
                }
            }
        }

        if key == "wasm" {
            let contract = iter.next();
            let msg = iter.next();
            
            if !(contract.is_none() || msg.is_none()) {
                return HookFilterMatch::WasmFilterMatch { 
                    contract: contract.unwrap().to_string(),
                    msg: str_to_string_filter_match(msg.unwrap()),
                }
            }
        }

        return HookFilterMatch::Unknown
    }
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub enum HookFilterMatch {
    WasmFilterMatch {
        contract: String,
        msg: FilterPattern<String>,
    },
    MoveFilterMatch{
        module_address: String,
        module_name: FilterPattern<String>,
        function_name: FilterPattern<String>,
    },
    Unknown // alway pass
}

impl HookFilters {
    /// Create a new filter from the given list.
    pub fn new(filters: Vec<HookFilterMatchString>) -> Self {
        Self(filters)
    }

    /// Returns the number of filters.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns true if there are no filters, false otherwise.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn matches(&self, data: &Vec<u8>) -> bool {
        let hook = Hook::from_packet_data(data);

        match hook {
            Hook::None => true,
            Hook::MoveHook(hook) => self.move_hook_matches(hook),
            Hook::WasmHook(hook) => self.wasm_hook_matches(hook),
        }
    }

    fn move_hook_matches(&self, hook: MoveHook) -> bool {
        self.0.iter().any(|hook_filter_string: &HookFilterMatchString| {
            match hook_filter_string.clone().into() {
                HookFilterMatch::MoveFilterMatch {
                    module_address,
                    module_name,
                    function_name,
                } => {
                    hook.module_address == module_address && module_name.matches(&hook.module_name) && function_name.matches(&hook.function_name)
                }
                _ => false
            }
        })
    }

    fn wasm_hook_matches(&self, hook: WasmHook) -> bool {
        self.0.iter().any(|hook_filter_string: &HookFilterMatchString| {
            let hook_filter: HookFilterMatch = hook_filter_string.clone().into();
            match hook_filter {
                HookFilterMatch::WasmFilterMatch { contract, msg } => {
                    hook.contract == contract && msg.matches(&hook.msg)
                }
                _ => false
            }
        })
    }
}

impl fmt::Display for HookFilters {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            self.0
                .iter()
                .map(|_| format!("hook filter (TODO: change fmt)"))
                .join(", ")
        )
    }
}

impl Serialize for HookFilters {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        use serde::ser::SerializeSeq;

        let mut outer_seq = serializer.serialize_seq(Some(self.0.len()))?;

        for hook_filter_match in &self.0 {
            outer_seq.serialize_element(hook_filter_match)?;
        }

        outer_seq.end()
    }
}

pub struct WasmHook {
    pub contract: String,
    pub msg: String,
}

pub struct MoveHook {
    pub module_address: String,
    pub module_name: String,
    pub function_name: String,
}

pub enum Hook {
    WasmHook(WasmHook),
    MoveHook(MoveHook),
    None
}

impl Hook {
    pub fn from_memo(memo: &String) -> Self {
        let memo = match serde_json::from_str::<Value>(memo) {
            Ok(memo) => memo,
            _ => {return Hook::None}
        };

        if memo["wasm"].is_object() {
            let valid = memo["wasm"]["contract"].is_string() && memo["wasm"]["msg"].is_object();
            if valid {
                let contract = memo["wasm"]["contract"].as_str().unwrap().to_string();
                let msg = memo["wasm"]["msg"].as_object().unwrap().keys().into_iter().next().unwrap().clone();

                return Hook::WasmHook(WasmHook{ contract, msg })
            };
        }

        if memo["move"].is_object() {
            let valid = memo["move"]["module_address"].is_string() 
                && memo["move"]["module_name"].is_string()
                && memo["move"]["function_name"].is_string();

            if valid {
                let module_address = memo["move"]["module_address"].as_str().unwrap().to_string();
                let module_name = memo["move"]["module_name"].as_str().unwrap().to_string();
                let function_name = memo["move"]["function_name"].as_str().unwrap().to_string();

                return Hook::MoveHook(MoveHook{ module_address, module_name, function_name })
            }
        }

        return Hook::None
    }

    pub fn from_packet_data(data: &Vec<u8>) -> Self {
        if data.len() == 0 {
            return Hook::None
        };

        let packet_data = match serde_json::from_slice::<Value>(data) {
            Ok(data) => data,
            _ => {return Hook::None}
        };

        let memo = packet_data["memo"].as_str();
        if memo.is_none() {
            return Hook::None
        };

        Hook::from_memo(&memo.unwrap().to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::filter::ChannelPolicy;

    #[test]
    fn deserialize_packet_filter_policy() {
        let toml_content = r#"
            policy = 'allow'
            list = [
              ['ica*', '*'],
              ['transfer', 'channel-0'],
            ]
            "#;

        let filter_policy: ChannelPolicy =
            toml::from_str(toml_content).expect("could not parse filter policy");

        dbg!(filter_policy);
    }

    #[test]
    fn serialize_packet_filter_policy() {
        use std::str::FromStr;

        use ibc_relayer_types::core::ics24_host::identifier::{ChannelId, PortId};

        let filter_policy = ChannelFilters(vec![
            (
                FilterPattern::Exact(PortId::from_str("transfer").unwrap()),
                FilterPattern::Exact(ChannelId::from_str("channel-0").unwrap()),
            ),
            (
                FilterPattern::Wildcard("ica*".parse().unwrap()),
                FilterPattern::Wildcard("*".parse().unwrap()),
            ),
        ]);

        let fp = ChannelPolicy::Allow(filter_policy);
        let toml_str = toml::to_string_pretty(&fp).expect("could not serialize packet filter");

        println!("{toml_str}");
    }

    #[test]
    fn channel_filter_iter_exact() {
        let toml_content = r#"
            policy = 'deny'
            list = [
              ['ica', 'channel-*'],
              ['ica*', '*'],
              ['transfer', 'channel-0'],
              ['transfer*', 'channel-1'],
              ['ft-transfer', 'channel-2'],
            ]
            "#;

        let pf: ChannelPolicy =
            toml::from_str(toml_content).expect("could not parse filter policy");

        if let ChannelPolicy::Deny(channel_filters) = pf {
            let exact_matches = channel_filters.iter_exact().collect::<Vec<_>>();
            assert_eq!(
                exact_matches,
                vec![
                    (
                        &PortId::from_str("transfer").unwrap(),
                        &ChannelId::from_str("channel-0").unwrap()
                    ),
                    (
                        &PortId::from_str("ft-transfer").unwrap(),
                        &ChannelId::from_str("channel-2").unwrap()
                    )
                ]
            );
        } else {
            panic!("expected `ChannelPolicy::Deny` variant");
        }
    }

    #[test]
    fn packet_filter_deny_policy() {
        let deny_policy = r#"
            policy = 'deny'
            list = [
              ['ica', 'channel-*'],
              ['ica*', '*'],
              ['transfer', 'channel-0'],
              ['transfer*', 'channel-1'],
              ['ft-transfer', 'channel-2'],
            ]
            "#;

        let pf: ChannelPolicy = toml::from_str(deny_policy).expect("could not parse filter policy");

        assert!(!pf.is_allowed(
            &PortId::from_str("ft-transfer").unwrap(),
            &ChannelId::from_str("channel-2").unwrap()
        ));
        assert!(pf.is_allowed(
            &PortId::from_str("ft-transfer").unwrap(),
            &ChannelId::from_str("channel-1").unwrap()
        ));
        assert!(pf.is_allowed(
            &PortId::from_str("transfer").unwrap(),
            &ChannelId::from_str("channel-2").unwrap()
        ));
        assert!(!pf.is_allowed(
            &PortId::from_str("ica-1").unwrap(),
            &ChannelId::from_str("channel-2").unwrap()
        ));
    }

    #[test]
    fn packet_filter_allow_policy() {
        let allow_policy = r#"
            policy = 'allow'
            list = [
              ['ica', 'channel-*'],
              ['ica*', '*'],
              ['transfer', 'channel-0'],
              ['transfer*', 'channel-1'],
              ['ft-transfer', 'channel-2'],
            ]
            "#;

        let pf: ChannelPolicy =
            toml::from_str(allow_policy).expect("could not parse filter policy");

        assert!(pf.is_allowed(
            &PortId::from_str("ft-transfer").unwrap(),
            &ChannelId::from_str("channel-2").unwrap()
        ));
        assert!(!pf.is_allowed(
            &PortId::from_str("ft-transfer").unwrap(),
            &ChannelId::from_str("channel-1").unwrap()
        ));
        assert!(!pf.is_allowed(
            &PortId::from_str("transfer-1").unwrap(),
            &ChannelId::from_str("channel-2").unwrap()
        ));
        assert!(pf.is_allowed(
            &PortId::from_str("ica-1").unwrap(),
            &ChannelId::from_str("channel-2").unwrap()
        ));
        assert!(pf.is_allowed(
            &PortId::from_str("ica").unwrap(),
            &ChannelId::from_str("channel-1").unwrap()
        ));
    }

    #[test]
    fn packet_filter_regex() {
        let allow_policy = r#"
            policy = 'allow'
            list = [
              ['transfer*', 'channel-1'],
            ]
            "#;

        let pf: ChannelPolicy =
            toml::from_str(allow_policy).expect("could not parse filter policy");

        assert!(!pf.is_allowed(
            &PortId::from_str("ft-transfer").unwrap(),
            &ChannelId::from_str("channel-1").unwrap()
        ));
        assert!(!pf.is_allowed(
            &PortId::from_str("ft-transfer-port").unwrap(),
            &ChannelId::from_str("channel-1").unwrap()
        ));
    }

    #[test]
    fn to_string_wildcards() {
        let wildcard = "ica*".parse::<Wildcard>().unwrap();
        assert_eq!(wildcard.to_string(), "ica*".to_string());
    }
}
