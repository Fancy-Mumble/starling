//! Letting go of livery artwork the document stops showing.
//!
//! The art lives in `userdata`'s blob store, one reference per `PutBlob`. The
//! upload that sets a key takes that reference (`operator-api`'s `write_art`)
//! and the document holds it, the way an account holds its avatar: so
//! whatever a write replaces is released here once the new document is
//! written. Before, nothing was, and every banner and icon an operator ever
//! uploaded stayed stored for good.

use starling_proto_fancy::userdata::BlobRef;
use starling_proto_fancy::userdata::user_data_client::UserDataClient;

use crate::{ServerConfigService, unhex};

impl ServerConfigService {
    /// Drop the reference the document held for each of `keys`.
    pub(crate) async fn release_art(&self, keys: &[String]) {
        if keys.is_empty() {
            return;
        }
        let Ok(channel) = self.resolver.channel("userdata") else {
            tracing::warn!("userdata is unreachable; replaced livery art stays stored");
            return;
        };
        let mut userdata = UserDataClient::new(channel);
        for hash in keys.iter().filter_map(|key| unhex(key)) {
            if let Err(status) = userdata.release_blob(BlobRef { hash, size: 0 }).await {
                tracing::warn!(%status, "could not release replaced livery art");
            }
        }
    }
}
