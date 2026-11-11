use crate::AegisError;

/// Default maximum allowed Shannon entropy for non-binary configuration text.
pub const DEFAULT_MAX_ENTROPY: f64 = 5.6;

const FORBIDDEN_SIGNATURES: &[(&str, &str)] = &[
    ("-----BEGIN PRIVATE KEY-----", "PKCS#8 Private Key"),
    ("-----BEGIN RSA PRIVATE KEY-----", "RSA Private Key"),
    ("-----BEGIN OPENSSH PRIVATE KEY-----", "OpenSSH Private Key"),
    ("AKIA", "AWS Access Key ID Prefix"),
    ("ghp_", "GitHub Personal Access Token"),
    ("sk_live_", "Stripe Live Secret Key"),
    ("xoxb-", "Slack Bot Token"),
];

/// Computes Shannon entropy (bits per byte, 0.0 to 8.0) of a byte slice.
pub fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u64; 256];
    for &b in data {
        if let Some(slot) = counts.get_mut(b as usize) {
            *slot = slot.saturating_add(1);
        }
    }
    let len = data.len() as f64;
    let mut entropy = 0.0;
    for &count in &counts {
        if count > 0 {
            let p = (count as f64) / len;
            entropy -= p * p.log2();
        }
    }
    entropy
}

/// Evaluates a byte buffer against zero-trust secret patterns and entropy ceilings.
pub fn enforce_zero_trust_policy(data: &[u8], max_entropy: Option<f64>) -> Result<f64, AegisError> {
    let text_view = String::from_utf8_lossy(data);
    for &(pattern, label) in FORBIDDEN_SIGNATURES {
        if text_view.contains(pattern) {
            return Err(AegisError::PolicyViolation(format!(
                "Forbidden credential pattern detected: {}",
                label
            )));
        }
    }
    let ceiling = max_entropy.unwrap_or(DEFAULT_MAX_ENTROPY);
    let overall_entropy = shannon_entropy(data);
    if data.len() >= 64 {
        for window in data.windows(64).step_by(16) {
            if window.iter().all(|&b| b.is_ascii_graphic()) {
                let w_entropy = shannon_entropy(window);
                if w_entropy > ceiling {
                    return Err(AegisError::PolicyViolation(format!(
                        "High-entropy credential candidate detected ({:.2} bits > {:.2} limit)",
                        w_entropy, ceiling
                    )));
                }
            }
        }
    }
    // NOTE: source paste ended here; module completed 2026-11-10.
    Ok(overall_entropy)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[allow(clippy::unwrap_used)]
    fn clean_text_passes_policy() {
        let data = b"ordinary configuration text with nothing sensitive inside it";
        let result = enforce_zero_trust_policy(data, None);
        assert!(result.is_ok());
    }

    #[test]
    fn forbidden_pattern_is_rejected() {
        let data = b"config: key = sk_live_example_do_not_use";
        let result = enforce_zero_trust_policy(data, None);
        assert!(matches!(result, Err(AegisError::PolicyViolation(_))));
    }

    #[test]
    fn private_key_header_is_rejected() {
        let data = b"-----BEGIN PRIVATE KEY-----\nMIIB...\n-----END PRIVATE KEY-----";
        let result = enforce_zero_trust_policy(data, None);
        assert!(matches!(result, Err(AegisError::PolicyViolation(_))));
    }

    #[test]
    fn empty_input_has_zero_entropy() {
        assert_eq!(shannon_entropy(&[]), 0.0);
    }

    #[test]
    fn repeated_byte_has_low_entropy() {
        let data = [b'a'; 128];
        assert!(shannon_entropy(&data) < 0.1);
    }
}
