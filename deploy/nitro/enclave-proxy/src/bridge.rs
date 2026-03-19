//! Bidirectional byte bridge between two async streams.

use tokio::io::{AsyncRead, AsyncWrite};
use tracing::debug;

/// Copy bytes bidirectionally between two streams until either side closes.
pub async fn bridge<A, B>(mut a: A, mut b: B) -> std::io::Result<()>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    let result = tokio::io::copy_bidirectional(&mut a, &mut b).await;
    match result {
        Ok((a_to_b, b_to_a)) => {
            debug!(a_to_b, b_to_a, "bridge closed");
            Ok(())
        }
        Err(e) => {
            debug!(error = %e, "bridge error");
            Err(e)
        }
    }
}
