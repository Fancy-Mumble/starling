//! Priority lanes and their overflow policies.

/// A priority class.
///
/// **Assigned by the kernel at registration, never chosen by a sender.** A
/// feature that could pick its own lane could promote its traffic above the
/// control plane, which is the whole property this type exists to protect.
///
/// Ordered most-urgent-first so `Lane::Realtime < Lane::Io` compares the way an
/// operator reads it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Lane {
    /// Gates audio correctness: routing-table publication, crypt setup.
    ///
    /// Audio frames themselves never traverse the bus — they take the
    /// published routing snapshot. This lane carries what that snapshot
    /// depends on.
    Realtime,
    /// Client protocol: sessions, channels, permissions.
    Control,
    /// Feature request/reply and event fan-out.
    ///
    /// The request/reply half needs `MessageBus::call`, which does not exist
    /// yet — see the note on that trait.
    Feature,
    /// Persistence and log flush.
    Io,
}

impl Lane {
    /// Every lane, most urgent first.
    pub const ALL: &'static [Self] = &[Self::Realtime, Self::Control, Self::Feature, Self::Io];

    /// Index into a per-lane array.
    #[must_use]
    pub fn index(self) -> usize {
        self as usize
    }

    /// Short name for metrics and logs.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Realtime => "realtime",
            Self::Control => "control",
            Self::Feature => "feature",
            Self::Io => "io",
        }
    }

    /// The default policy for this lane.
    ///
    /// Each lane wants a *different* failure. Uniform bounded queues would be
    /// the easy mistake: dropping a `ChannelState` corrupts protocol state,
    /// while keeping a stale audio-gating message is worse than dropping it.
    #[must_use]
    pub fn default_overflow(self) -> Overflow {
        match self {
            Self::Realtime => Overflow::DropOldest,
            Self::Control => Overflow::DisconnectPeer,
            Self::Feature => Overflow::Reject,
            Self::Io => Overflow::BlockProducer,
        }
    }

    /// The default queue bound for this lane.
    #[must_use]
    pub fn default_capacity(self) -> usize {
        match self {
            Self::Realtime => 64,
            Self::Control => 1024,
            Self::Feature => 512,
            Self::Io => 8192,
        }
    }
}

/// What happens when a lane's queue is full.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Overflow {
    /// Discard the oldest envelope. For traffic where stale is worthless.
    DropOldest,
    /// Refuse and tell the caller to close the peer's connection.
    DisconnectPeer,
    /// Refuse and return an error to the sender.
    Reject,
    /// Block the producer until space appears. Durability over latency.
    BlockProducer,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lanes_order_most_urgent_first() {
        assert!(Lane::Realtime < Lane::Control);
        assert!(Lane::Control < Lane::Feature);
        assert!(Lane::Feature < Lane::Io);
    }

    #[test]
    fn indices_are_dense_and_match_all() {
        for (i, lane) in Lane::ALL.iter().enumerate() {
            assert_eq!(lane.index(), i, "{lane:?} index must match its ALL slot");
        }
        assert_eq!(Lane::ALL.len(), 4);
    }

    #[test]
    fn labels_are_unique() {
        let mut labels: Vec<_> = Lane::ALL.iter().map(|l| l.label()).collect();
        let count = labels.len();
        labels.sort_unstable();
        labels.dedup();
        assert_eq!(labels.len(), count);
    }

    #[test]
    fn each_lane_gets_a_distinct_failure_mode() {
        // The point of per-lane policy: uniform queues would be the easy bug.
        let policies: Vec<_> = Lane::ALL.iter().map(|l| l.default_overflow()).collect();
        assert_eq!(
            policies,
            vec![
                Overflow::DropOldest,
                Overflow::DisconnectPeer,
                Overflow::Reject,
                Overflow::BlockProducer
            ]
        );
    }

    #[test]
    fn the_realtime_queue_is_the_shallowest() {
        // A deep realtime queue is just latency with extra steps.
        let shallowest = Lane::ALL
            .iter()
            .min_by_key(|l| l.default_capacity())
            .copied();
        assert_eq!(shallowest, Some(Lane::Realtime));
    }

    #[test]
    fn control_never_silently_drops() {
        // Losing a ChannelState desynchronises the client permanently.
        assert_ne!(Lane::Control.default_overflow(), Overflow::DropOldest);
    }
}
