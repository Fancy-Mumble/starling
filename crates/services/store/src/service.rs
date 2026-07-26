//! Persistence as a bus participant.
//!
//! A reactor: one loop draining [`Lane::Io`], one message at a time, each
//! handled to completion before the next is taken. Nothing here waits on anyone
//! else, and nobody waits on it — a requester posts and is resumed later by the
//! reply.
//!
//! # Why this is the whole of the concurrency design
//!
//! The database is the slowest thing in the process, and it is the one that must
//! never make anything else slow. Giving it its own lane and its own loop means
//! a query that takes a second delays exactly the next query, and nothing else:
//! not the control plane, not a handshake, and above all not audio, which never
//! touches the bus at all.
//!
//! It also removes the need for a synchronous `call` on the bus. There is no
//! caller to run at the caller's priority, because there is no caller waiting —
//! which is what made the priority-inheritance problem disappear rather than
//! need solving.
//!
//! # Ordering
//!
//! One loop means writes land in the order they were posted, per sender, which
//! is the only ordering guarantee anything needs: a rename followed by a delete
//! must not arrive reversed. Concurrency across *unrelated* writes would buy
//! throughput this workload does not want — persistence here is a handful of
//! messages a minute, not a hot path.

use std::sync::Arc;
use std::time::Duration;

use starling_api::{
    Store, StoreReply, StoreRequest, StoredWorld,
};
use starling_bus::{Envelope, Lane, MessageBus, PortId};
use starling_model::{ChannelId, UserId};
use tracing::{debug, warn};

/// How long the loop waits for a message before looking at its stop flag.
///
/// Long enough that an idle server is not spinning, short enough that shutdown
/// is not perceptibly delayed.
const POLL: Duration = Duration::from_millis(250);

/// The persistence port.
///
/// Registered on [`Lane::Io`] by whoever builds it; a participant does not
/// choose its own lane, which is what stops a service promoting its own traffic.
#[derive(Debug)]
pub struct StoreService {
    store: Box<dyn Store>,
    bus: Arc<dyn MessageBus>,
    port: PortId,
}

impl StoreService {
    /// Bind a store to a port on the bus.
    ///
    /// Registers the port on [`Lane::Io`]. The caller supplies the port id
    /// rather than one being invented here, because the composition root is the
    /// only place that can know which ids are already taken.
    #[must_use]
    pub fn new(store: Box<dyn Store>, bus: Arc<dyn MessageBus>, port: PortId) -> Self {
        bus.register(port, Lane::Io);
        Self { store, bus, port }
    }

    /// The port other services address.
    #[must_use]
    pub const fn port(&self) -> PortId {
        self.port
    }

    /// Drain the I/O lane until the bus shuts down.
    ///
    /// One message at a time, each to completion. A failed request is reported
    /// back and the loop continues: a database that refuses one write has not
    /// necessarily stopped working, and a persistence service that exited on the
    /// first error would take the server with it.
    pub async fn run(self) {
        debug!(port = %self.port, backend = self.store.backend(), "persistence port open");

        loop {
            let Some(envelope) = self.bus.take(Lane::Io, POLL) else {
                // Nothing waiting. `take` returning `None` on a shut-down bus is
                // indistinguishable from a quiet one here, which is why the
                // composition root aborts this task rather than signalling it.
                continue;
            };
            self.handle(envelope).await;
        }
    }

    /// Decode one envelope, do what it asks, and answer if it asked.
    async fn handle(&self, envelope: Envelope) {
        let request: StoreRequest = match postcard::from_bytes(&envelope.payload) {
            Ok(request) => request,
            Err(error) => {
                // The bus does not parse, so a malformed payload gets here
                // rather than being refused at the door. It means a sender is
                // encoding something this build does not understand.
                warn!(%error, "undecodable message on the persistence port");
                return;
            }
        };

        match self.apply(request).await {
            Ok(Some(reply)) => self.answer(&envelope, &reply),
            Ok(None) => {}
            Err(message) => {
                // Reported rather than dropped: the caller cannot undo the write
                // it just lost, but an operator needs to know the database is
                // refusing them before the next restart reads a stale world.
                warn!(message, "persistence operation failed");
                self.answer(&envelope, &StoreReply::Failed(message));
            }
        }
    }

    /// Post a reply, if the request asked for one.
    fn answer(&self, request: &Envelope, reply: &StoreReply) {
        let Some(envelope) = postcard::to_allocvec(reply)
            .ok()
            .and_then(|bytes| request.reply_to_request(bytes))
        else {
            return; // nothing asked, or the reply would not encode
        };
        if let Err(error) = self.bus.send(envelope) {
            // The requester unregistered while the query ran — a client that
            // disconnected mid-handshake, most often. Not worth more than a line.
            debug!(?error, "nobody left to receive a persistence reply");
        }
    }

    /// Carry out one request.
    ///
    /// `Ok(None)` for a write that succeeded and wanted no answer, which is most
    /// of them.
    async fn apply(&self, request: StoreRequest) -> Result<Option<StoreReply>, String> {
        match request {
            StoreRequest::LoadEverything => {
                let world = self.load().await?;
                Ok(Some(StoreReply::Everything(Box::new(world))))
            }

            StoreRequest::SaveChannel(channel) => {
                self.store.channels().save(&channel).await.map_err(say)?;
                Ok(None)
            }
            StoreRequest::RemoveChannel(id) => {
                self.store
                    .channels()
                    .remove(ChannelId(id))
                    .await
                    .map_err(say)?;
                Ok(None)
            }
            StoreRequest::LinkChannels(one, other) => {
                self.store
                    .channels()
                    .link(ChannelId(one), ChannelId(other))
                    .await
                    .map_err(say)?;
                Ok(None)
            }
            StoreRequest::UnlinkChannels(one, other) => {
                self.store
                    .channels()
                    .unlink(ChannelId(one), ChannelId(other))
                    .await
                    .map_err(say)?;
                Ok(None)
            }

            StoreRequest::SaveUser(user) => {
                self.store.users().save(&user).await.map_err(say)?;
                Ok(None)
            }
            StoreRequest::RemoveUser(id) => {
                self.store.users().remove(UserId(id)).await.map_err(say)?;
                Ok(None)
            }
            StoreRequest::SetUserProperty { user, key, value } => {
                self.store
                    .users()
                    .set_property(UserId(user), &key, &value)
                    .await
                    .map_err(say)?;
                Ok(None)
            }

            StoreRequest::AddListener(listener) => {
                self.store
                    .channels()
                    .add_listener(listener)
                    .await
                    .map_err(say)?;
                Ok(None)
            }
            StoreRequest::RemoveListener { user, channel } => {
                self.store
                    .channels()
                    .remove_listener(UserId(user), ChannelId(channel))
                    .await
                    .map_err(say)?;
                Ok(None)
            }

            StoreRequest::ReplaceBans(bans) => {
                self.store.bans().replace_all(&bans).await.map_err(say)?;
                Ok(None)
            }
            StoreRequest::SetConfig { key, value } => {
                self.store.config().set(&key, &value).await.map_err(say)?;
                Ok(None)
            }
            StoreRequest::AppendLog { at, message } => {
                self.store.log().append(at, &message).await.map_err(say)?;
                Ok(None)
            }
        }
    }

    /// Read the durable world in one pass.
    async fn load(&self) -> Result<StoredWorld, String> {
        Ok(StoredWorld {
            channels: self.store.channels().all().await.map_err(say)?,
            links: self
                .store
                .channels()
                .links()
                .await
                .map_err(say)?
                .into_iter()
                .map(|(low, high)| (low.0, high.0))
                .collect(),
            users: self.store.users().all().await.map_err(say)?,
            listeners: self.store.channels().listeners().await.map_err(say)?,
            bans: self.store.bans().all().await.map_err(say)?,
            config: self.store.config().all().await.map_err(say)?,
        })
    }
}

/// Render a store error for a caller that has no branch on its kind.
fn say(error: starling_api::StoreError) -> String {
    error.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SqlStore;
    use starling_bus::LaneBus;
    use starling_api::StoredChannel;

    const STORE: PortId = PortId(1);
    const CALLER: PortId = PortId(2);

    /// A running persistence port, and the bus to reach it on.
    async fn running() -> Arc<dyn MessageBus> {
        let bus: Arc<dyn MessageBus> = Arc::new(LaneBus::new());
        let store = SqlStore::open("sqlite::memory:", 1).await.expect("open");
        let service = StoreService::new(Box::new(store), Arc::clone(&bus), STORE);

        // The caller is a real port, so replies have somewhere to land.
        bus.register(CALLER, Lane::Control);
        drop(tokio::spawn(service.run()));
        bus
    }

    /// Post a request and wait for its reply.
    async fn ask(bus: &Arc<dyn MessageBus>, request: &StoreRequest) -> StoreReply {
        let bytes = postcard::to_allocvec(request).expect("encode");
        bus.send(Envelope::request(STORE, CALLER, bytes))
            .expect("send");

        for _ in 0..40 {
            if let Some(envelope) = bus.take(Lane::Control, Duration::from_millis(100)) {
                return postcard::from_bytes(&envelope.payload).expect("decode");
            }
        }
        panic!("no reply arrived");
    }

    /// Post a write, which expects no reply.
    fn tell(bus: &Arc<dyn MessageBus>, request: &StoreRequest) {
        let bytes = postcard::to_allocvec(request).expect("encode");
        bus.send(Envelope::new(STORE, bytes)).expect("send");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_write_then_a_read_comes_back_through_the_bus() {
        // The whole architecture in one test: nothing calls the store directly,
        // and nothing waits — the write is posted, the read is posted, and the
        // answer arrives as its own message.
        let bus = running().await;

        tell(
            &bus,
            &StoreRequest::SaveChannel(StoredChannel::new(ChannelId(0), None, "Root")),
        );
        tell(
            &bus,
            &StoreRequest::SetConfig {
                key: "welcometext".into(),
                value: "hello".into(),
            },
        );

        match ask(&bus, &StoreRequest::LoadEverything).await {
            StoreReply::Everything(world) => {
                assert_eq!(world.channels.len(), 1, "the channel was not persisted");
                assert_eq!(world.channels[0].name, "Root");
                assert_eq!(
                    world.config,
                    vec![("welcometext".to_owned(), "hello".to_owned())]
                );
            }
            other => panic!("expected a world, got {other:?}"),
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_fresh_database_says_so() {
        // The caller needs to tell "nothing stored yet" from "could not read",
        // because it seeds a root channel on the first and must not on the
        // second — seeding over data it could not see would destroy it.
        let bus = running().await;
        match ask(&bus, &StoreRequest::LoadEverything).await {
            StoreReply::Everything(world) => assert!(world.is_fresh()),
            other => panic!("expected a world, got {other:?}"),
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn an_undecodable_message_does_not_stop_the_port() {
        // The bus does not parse, so nonsense reaches this loop rather than
        // being refused at the door. A port that exited on it would take
        // persistence down for the life of the process.
        let bus = running().await;
        bus.send(Envelope::new(STORE, vec![0xFF, 0xFF, 0xFF]))
            .expect("send");

        match ask(&bus, &StoreRequest::LoadEverything).await {
            StoreReply::Everything(_) => {}
            other => panic!("the port stopped serving after bad input: {other:?}"),
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_write_that_wants_no_answer_gets_none() {
        // Most writes are posts. A reply nobody asked for would sit in the
        // caller's inbox and be mistaken for the answer to something else.
        let bus = running().await;
        tell(
            &bus,
            &StoreRequest::SaveChannel(StoredChannel::new(ChannelId(0), None, "Root")),
        );

        // Give the write time to land, then check nothing was posted back.
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert!(
            bus.take(Lane::Control, Duration::from_millis(50)).is_none(),
            "an unrequested reply was sent"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_failing_write_is_reported_rather_than_swallowed() {
        // A channel whose parent does not exist violates the foreign key. The
        // caller cannot undo it, but an operator must learn the database is
        // refusing writes before a restart reads a stale world.
        let bus = running().await;
        let orphan = StoredChannel::new(ChannelId(5), Some(ChannelId(99)), "Orphan");

        match ask(&bus, &StoreRequest::SaveChannel(orphan)).await {
            StoreReply::Failed(message) => assert!(!message.is_empty()),
            other => panic!("a constraint violation was not reported: {other:?}"),
        }
    }
}
