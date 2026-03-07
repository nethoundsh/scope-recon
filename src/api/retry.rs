use std::future::Future;
use std::time::Duration;
use anyhow::Result;
use tokio::time::sleep;

/// Runs `f` once. If it fails with a 429 rate-limit response, prints a warning
/// to stderr, waits `delay`, and tries once more.
pub async fn with_retry<F, Fut, T>(label: &str, delay: Duration, f: F) -> Result<T>
where
    F: Fn() -> Fut,
    Fut: Future<Output = Result<T>>,
{
    match f().await {
        Ok(v) => Ok(v),
        Err(e) if is_rate_limited(&e) => {
            eprintln!(
                "warning: {} rate limited (429) — retrying in {}s...",
                label,
                delay.as_secs()
            );
            sleep(delay).await;
            f().await.map_err(|e2| {
                if is_rate_limited(&e2) {
                    anyhow::anyhow!("{} rate limited after retry", label)
                } else {
                    e2
                }
            })
        }
        Err(e) => Err(e),
    }
}

fn is_rate_limited(e: &anyhow::Error) -> bool {
    e.to_string().contains("429")
}
