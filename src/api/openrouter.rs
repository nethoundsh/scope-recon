use anyhow::Result;
use futures::StreamExt;
use serde::Deserialize;
use serde_json::json;
use tokio::sync::mpsc;

use crate::model::{AiAnalysisSummary, ThreatReport};
use crate::tui::app::SourceUpdate;

const OPENROUTER_URL: &str = "https://openrouter.ai/api/v1/chat/completions";
const MODEL: &str = "x-ai/grok-3-beta";

#[derive(Deserialize)]
struct StreamChunk {
    choices: Vec<StreamChoice>,
}

#[derive(Deserialize)]
struct StreamChoice {
    delta: Delta,
}

#[derive(Deserialize)]
struct Delta {
    content: Option<String>,
}

#[derive(Deserialize)]
struct CompletionResponse {
    choices: Vec<CompletionChoice>,
}

#[derive(Deserialize)]
struct CompletionChoice {
    message: CompletionMessage,
}

#[derive(Deserialize)]
struct CompletionMessage {
    content: String,
}

fn build_messages(report: &ThreatReport) -> serde_json::Value {
    let report_json = serde_json::to_string_pretty(report).unwrap_or_default();

    let has_threatfox_iocs = report
        .threatfox
        .as_ref()
        .map(|tf| tf.ioc_count > 0)
        .unwrap_or(false);

    let mut user_content = format!(
        "{}\n\nProvide a 2-3 paragraph threat assessment for this IP.",
        report_json
    );

    if has_threatfox_iocs {
        user_content.push_str(
            " For each unique malware family present, add a brief paragraph explaining what it is and how it is typically used.",
        );
    }

    json!([
        {
            "role": "system",
            "content": "You are a threat intelligence analyst. Be concise and technical."
        },
        {
            "role": "user",
            "content": user_content
        }
    ])
}

/// TUI: streams chunks, sends intermediate SourceUpdates as text accumulates.
pub async fn stream_openrouter(
    report: &ThreatReport,
    key: &str,
    tx: mpsc::Sender<SourceUpdate>,
) -> Result<()> {
    let client = reqwest::Client::new();
    let messages = build_messages(report);

    let resp = client
        .post(OPENROUTER_URL)
        .header("Authorization", format!("Bearer {}", key))
        .json(&json!({
            "model": MODEL,
            "stream": true,
            "messages": messages
        }))
        .send()
        .await?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        anyhow::bail!("OpenRouter error {}: {}", status, body);
    }

    let mut stream = resp.bytes_stream();
    let mut line_buf = String::new();
    let mut accumulated = String::new();

    while let Some(chunk) = stream.next().await {
        let bytes = chunk?;
        line_buf.push_str(&String::from_utf8_lossy(&bytes));

        // Process all complete lines in the buffer
        while let Some(pos) = line_buf.find('\n') {
            let line = line_buf[..pos].trim_end_matches('\r').to_string();
            line_buf = line_buf[pos + 1..].to_string();

            if let Some(data) = line.strip_prefix("data: ") {
                if data == "[DONE]" {
                    break;
                }
                if let Ok(chunk_val) = serde_json::from_str::<StreamChunk>(data) {
                    if let Some(content) = chunk_val
                        .choices
                        .first()
                        .and_then(|c| c.delta.content.as_deref())
                    {
                        if !content.is_empty() {
                            accumulated.push_str(content);
                            let _ = tx
                                .send(SourceUpdate::AiAnalysis(Ok(AiAnalysisSummary {
                                    analysis: accumulated.clone(),
                                })))
                                .await;
                        }
                    }
                }
            }
        }
    }

    // Send final update with complete text (covers the case where stream ends
    // without [DONE] or the last chunk had no content delta)
    if !accumulated.is_empty() {
        let _ = tx
            .send(SourceUpdate::AiAnalysis(Ok(AiAnalysisSummary {
                analysis: accumulated,
            })))
            .await;
    }

    Ok(())
}

/// CLI: awaits complete response, returns finished struct.
pub async fn fetch_openrouter(report: &ThreatReport, key: &str) -> Result<AiAnalysisSummary> {
    let client = reqwest::Client::new();
    let messages = build_messages(report);

    let resp = client
        .post(OPENROUTER_URL)
        .header("Authorization", format!("Bearer {}", key))
        .json(&json!({
            "model": MODEL,
            "messages": messages
        }))
        .send()
        .await?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        anyhow::bail!("OpenRouter error {}: {}", status, body);
    }

    let completion: CompletionResponse = resp.json().await?;
    let content = completion
        .choices
        .into_iter()
        .next()
        .map(|c| c.message.content)
        .unwrap_or_default();

    Ok(AiAnalysisSummary { analysis: content })
}
