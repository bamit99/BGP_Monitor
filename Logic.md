# BGP Monitor - Detection Logic Explained

This document explains the logic behind the security checks performed by the `utils/security_analyzer.py` module in the BGP Monitor tool. These checks aim to identify potentially malicious or misconfigured BGP updates.

## Overview

The core function `check_suspicious_patterns` orchestrates several checks on each BGP announcement. If any check flags an update as suspicious, an alert is generated with associated reasons and a severity level (LOW, MEDIUM, HIGH). Configuration for thresholds, critical prefixes, and known bad actors is loaded from `config/security_config.json` and `config/app_settings.json`.

## 1. Hijack Detection (`check_possible_hijack`)

This check looks for patterns commonly associated with BGP prefix hijacking.

*   **Origin AS Change:**
    *   **Logic:** Compares the origin AS (the last AS in the path) of the current announcement for a prefix against the previously seen origin AS for the *same* prefix (requires state/cache).
    *   **Why:** A sudden, unexpected change in the AS authorized to originate a prefix is a strong indicator of a potential hijack.
    *   **Severity:** Raised severity (often HIGH) if the prefix is listed in `critical_prefixes` in `security_config.json`.

*   **Suspicious More-Specific Announcement:**
    *   **Logic:** Checks if the announced prefix is a more specific subnet (e.g., `/24`) of a known `critical_prefix` (e.g., `/16`) and if the difference in prefix length exceeds a configured threshold (from `app_settings.json`).
    *   **Why:** Attackers might announce a more specific route for a critical prefix to attract traffic intended for the legitimate, larger block. While legitimate uses exist, unexpected more-specifics warrant scrutiny.
    *   **Severity:** Typically MEDIUM or HIGH, especially for critical prefixes.

*   **Known Bad Actor Origin:**
    *   **Logic:** Checks if the origin AS is present in the `known_bad_actors` list in `security_config.json`.
    *   **Why:** If an AS known for malicious activity originates an announcement, it's highly suspicious.
    *   **Severity:** HIGH.

## 2. Route Leak Detection (`check_route_leak`)

This check identifies patterns suggesting routes are being announced outside of their intended scope, often violating business agreements between networks.

*   **Valley-Free Violation (AS Relationships):**
    *   **Logic:** Uses pre-loaded AS relationship data (Customer-Provider, Peer-Peer, Sibling-Sibling) to validate the AS path. It checks if a route learned from a Provider or Peer (going "down" or "across") is subsequently announced *back up* to another Provider.
    *   **Why:** This violates the "valley-free" routing principle, where traffic should generally flow down the customer cone or across peers, but not back up from a customer/peer to a provider. This indicates an AS is improperly re-announcing routes it shouldn't.
    *   **Severity:** Typically MEDIUM.

*   **Suspiciously Long AS Path:**
    *   **Logic:** Checks if the number of ASNs in the path exceeds a configured threshold (from `app_settings.json`).
    *   **Why:** While not always malicious, very long paths can indicate inefficient routing, potential path manipulation, or misconfigurations.
    *   **Severity:** Typically LOW.

*   **Private ASNs in Path:**
    *   **Logic:** Checks if any ASNs within the standard private ranges (64512-65534, 4200000000-4294967294) appear in the AS path.
    *   **Why:** Private ASNs are intended for internal network use and should not appear in public BGP announcements exchanged over the internet. Their presence indicates a configuration error or leak.
    *   **Severity:** Typically MEDIUM.

## 3. RPKI Validity (`check_rpki_validity`)

Resource Public Key Infrastructure (RPKI) provides a way to cryptographically verify an AS's authorization to originate a specific prefix.

*   **Logic:** Queries an RPKI validation service (currently the RIPEstat API via `RPKIValidator`) with the announced prefix and origin AS. It checks if the result is "INVALID".
*   **Why:** An "INVALID" state means the origin AS is definitively *not* authorized according to RPKI data to announce this prefix, strongly suggesting a hijack or misconfiguration. "VALID" means it is authorized, and "UNKNOWN" means no RPKI data covers this announcement.
*   **Severity:** HIGH if INVALID.

## 4. Path Attributes (`check_path_prepending`, `check_unusual_transit`)

These checks look at other characteristics of the AS path.

*   **Excessive Path Prepending:**
    *   **Logic:** Counts consecutive repetitions of the same ASN in the path and flags if it exceeds a configured threshold (from `app_settings.json`).
    *   **Why:** AS Path Prepending (intentionally repeating an ASN) is a legitimate traffic engineering technique. However, *excessive* prepending might indicate misconfiguration or unusual routing policies.
    *   **Severity:** Typically LOW.

*   **Known Bad Actor in Transit Path:**
    *   **Logic:** Checks if any ASN *within* the transit path (not just the origin) is listed in `known_bad_actors` in `security_config.json`.
    *   **Why:** Even if not originating the route, a known malicious actor involved in transiting the traffic is a significant risk.
    *   **Severity:** HIGH.

## 5. ML Anomaly Detection (`anomaly_detector`)

This uses machine learning (specifically Isolation Forest) for unsupervised anomaly detection.

*   **Logic:**
    1.  Extracts numerical features from the update: AS path length, number of unique ASNs, prefix length (e.g., 24 for /24), time since the prefix was last seen, and whether the origin AS changed for this prefix.
    2.  Feeds these features into a pre-trained (or theoretically, online-trained) Isolation Forest model.
    3.  The model predicts whether the feature combination is an outlier (-1) or an inlier (1) compared to what it learned during training.
*   **Why:** This aims to catch unusual combinations of factors that might not trigger specific heuristic rules but deviate significantly from typical BGP behavior observed by the model.
*   **Severity:** Configurable (default MEDIUM), triggered if the model predicts -1 (anomaly).
*   **Note:** Currently, the model runs *unfitted* (predicting 'normal' by default) as the training mechanism is not yet implemented.

---

This overview should provide a good starting point for understanding the security checks within the BGP Monitor. Each check contributes to building a picture of whether a BGP update is legitimate or potentially harmful.
