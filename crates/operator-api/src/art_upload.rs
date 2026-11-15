//! Storing a livery image and pointing the livery at it, as one step.
//!
//! The put takes a reference in the blob store that the livery takes over
//! once it names the image. If naming it fails, nothing ever will, so the
//! put is released on that path rather than staying stored for good.

/// Where the image goes: `userdata`'s blob store in the service, a counter in
/// the tests.
pub(crate) trait Blobs {
    /// What a failed call is reported as.
    type Error;

    /// Store `bytes`, returning their hash and holding one reference.
    async fn put(&mut self, bytes: Vec<u8>) -> Result<Vec<u8>, Self::Error>;

    /// Drop the reference a [`Self::put`] took. Best effort: a failure here
    /// costs storage, not correctness, and is the store's to log.
    async fn release(&mut self, hash: Vec<u8>);
}

/// Put `bytes`, then `name` the hash; release the put when naming fails.
pub(crate) async fn put_and_name<B: Blobs>(
    blobs: &mut B,
    bytes: Vec<u8>,
    name: impl AsyncFnOnce(Vec<u8>) -> Result<(), B::Error>,
) -> Result<(), B::Error> {
    let hash = blobs.put(bytes).await?;
    if let Err(refusal) = name(hash.clone()).await {
        blobs.release(hash).await;
        return Err(refusal);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A store that counts what it holds.
    #[derive(Default)]
    struct Counted {
        held: i32,
    }

    impl Blobs for Counted {
        type Error = &'static str;

        async fn put(&mut self, bytes: Vec<u8>) -> Result<Vec<u8>, Self::Error> {
            self.held += 1;
            Ok(bytes)
        }

        async fn release(&mut self, _hash: Vec<u8>) {
            self.held -= 1;
        }
    }

    #[tokio::test]
    async fn an_image_the_livery_could_not_name_is_not_kept() {
        let mut blobs = Counted::default();
        let named = put_and_name(&mut blobs, b"banner".to_vec(), async |_| {
            Err("server-config refused")
        })
        .await;
        assert_eq!(
            named,
            Err("server-config refused"),
            "the refusal is the answer"
        );
        assert_eq!(blobs.held, 0, "the put was let go");
    }

    #[tokio::test]
    async fn an_image_the_livery_names_is_handed_to_it() {
        let mut blobs = Counted::default();
        let mut told = Vec::new();
        let named = put_and_name(&mut blobs, b"banner".to_vec(), async |hash| {
            told = hash;
            Ok(())
        })
        .await;
        assert_eq!(named, Ok(()));
        assert_eq!(told, b"banner", "named by what was stored");
        assert_eq!(blobs.held, 1, "the livery holds it now");
    }
}
