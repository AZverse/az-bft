/// Deterministic fault injected before a devnet run starts.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum DevnetFault {
    /// Run all validators normally.
    #[default]
    None,
    /// Keep the round-one leader offline so the remaining quorum must change view.
    UnavailableInitialLeader,
    /// Keep the listed validator indices offline for the whole run.
    UnavailableValidators(Vec<usize>),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_runs_all_validators() {
        assert_eq!(DevnetFault::default(), DevnetFault::None);
    }
}
