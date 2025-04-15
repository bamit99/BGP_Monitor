# BGP Security Monitor - Improvement Tracker

This file tracks suggested improvements for the BGP security monitoring capabilities (`utils/security_analyzer.py`). Check items off as they are completed.

## Suggested Enhancements:

- [x] **Integrate AS Relationship Data:**
    *   **Description:** Replace basic route leak checks with validation against reliable AS relationship data (e.g., CAIDA ASRank) for accurate valley-free routing checks. **(Framework implemented; requires data file)**
    *   **Impact:** High (Crucial for reliable leak detection).

- [ ] **Deploy Local RPKI Validator:**
    *   **Description:** Integrate with a local RPKI Relying Party cache (e.g., Routinator, OctoRPKI) instead of relying solely on external APIs.
    *   **Impact:** High (Essential for performance, reliability, and avoiding rate limits).

- [ ] **Add Internet Routing Registry (IRR) Checks:**
    *   **Description:** Implement validation of announcements against registered route/route6 objects in IRR databases (e.g., RADb).
    *   **Impact:** High (Adds another layer of routing policy validation).

- [ ] **Implement Bogon Filtering:**
    *   **Description:** Add filtering for announcements involving bogon prefixes (unallocated/reserved IPs) and bogon ASNs using lists like Team Cymru's.
    *   **Impact:** Medium (Important for hygiene and detecting noise/errors).

- [ ] **Integrate Dynamic Threat Intelligence:**
    *   **Description:** Replace static bad actor lists with integration into dynamic threat intelligence feeds for malicious ASNs/prefixes.
    *   **Impact:** Medium-High (Improves detection of known malicious activity).

- [ ] **Enhance Anomaly Detection:** (In Progress)
    *   **Description:** Move beyond simple origin checks. Build historical profiles/baselines for prefix behavior (origins, upstreams, stability) and flag deviations. **(Initial Isolation Forest implementation added; requires model training/loading)**
    *   **Impact:** Medium-High (Can detect novel or subtle hijacking attempts).

- [ ] **Improve Configuration Management:**
    *   **Description:** Develop a more robust way to manage critical lists (prefixes, ASNs) than just JSON files (e.g., GUI section, dedicated tool).
    *   **Impact:** Medium (Improves usability and maintainability).

- [ ] **Implement Alert Correlation / Episode Management:**
    *   **Description:** Group related low-level alerts into single, higher-priority incidents (episodes) to reduce noise and improve focus. Integrate with incident response systems if possible. **(Core aggregation logic, persistence loading, automated cleanup, and basic GUI tab/table implemented; dynamic updates/details view pending)**
    *   **Impact:** Medium (Improves operational efficiency).

- [ ] **Optimize for Performance/Scalability:**
    *   **Description:** Investigate and implement optimizations (batching, async checks, sampling) if needed for high-volume BGP feeds.
    *   **Impact:** Medium (Depends on observed performance with real-world data).

- [ ] **Integrate PeeringDB Data:**
    *   **Description:** Query PeeringDB (via API or data dump) to validate potential peer-to-peer relationships seen in BGP paths and gather richer context about ASNs (IXP presence, facility info, contacts). Complements CAIDA data.
    *   **Impact:** Medium (Enhances validation of peering links and provides operational context).
