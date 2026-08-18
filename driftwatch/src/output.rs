// Turn validator samples into readable status lines.

use crate::rpc::{Sample, ValidatorSample};

/// Format one poll as a single status line.
/// e.g: epoch 0 | slot 1,084 | last vote 1,083 | lag 1 | credits 4,201 | OK
/// or:  DOWN | getEpochInfo: request failed: ...
pub fn status_line(sample: &Sample) -> String {
    match sample {
        Sample::Up(s) => up_line(s),
        Sample::Down { reason } => format!("DOWN | {reason}"),
    }
}

/// Short form for the combined timeline:
/// slot 4,321 | lag 1 | credits 26,412 | OK      (or "validator DOWN")
pub fn compact(sample: &Sample) -> String {
    match sample {
        Sample::Up(s) => format!(
            "slot {} | lag {} | credits {} | {}",
            commas(s.network_slot),
            s.vote_lag,
            commas(s.credits),
            state(s)
        ),
        Sample::Down { .. } => "validator DOWN".into(),
    }
}

pub fn state(s: &ValidatorSample) -> &'static str {
    if !s.healthy {
        "UNHEALTHY"
    } else if s.delinquent {
        "DELINQUENT"
    } else if s.vote_lag > 150 {
        // rough "falling behind" heuristic; tuned properly later
        "LAGGING"
    } else {
        "OK"
    }
}

fn up_line(s: &ValidatorSample) -> String {
    let state = state(s);
    format!(
        "epoch {} | slot {} | last vote {} | lag {} | credits {} | {}",
        s.epoch,
        commas(s.network_slot),
        commas(s.my_last_vote),
        s.vote_lag,
        commas(s.credits),
        state,
    )
}

/// Turns 1234567 into "1,234,567".
fn commas(n: u64) -> String {
    let digits = n.to_string();
    let mut out = String::new();
    let len = digits.len();
    for (i, ch) in digits.chars().enumerate() {
        if i > 0 && (len - i) % 3 == 0 {
            out.push(',');
        }
        out.push(ch);
    }
    out
}
