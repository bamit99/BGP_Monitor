# BGP Security Monitor - Improvement Tracker

This file tracks suggested improvements for the BGP security monitoring capabilities (`utils/security_analyzer.py`). Check items off as they are completed.

## Recent Review (2026-01-23) - Prioritized Improvement Roadmap

Based on comprehensive code review, the following prioritized improvements have been identified to enhance functionality, address limitations, and modernize the thick-client architecture.

## Completed Enhancements:

- [x] **Integrate AS Relationship Data:**
    *   **Description:** Replace basic route leak checks with validation against reliable AS relationship data (e.g., CAIDA ASRank) for accurate valley-free routing checks. **(Framework implemented; requires data file)**
    *   **Impact:** High (Crucial for reliable leak detection).

- [x] **Deploy Local RPKI Validator:**
    *   **Description:** Integrate with a local RPKI Relying Party cache (e.g., Routinator, OctoRPKI) instead of relying solely on external APIs. **(Implemented support for querying validator via HTTP API; requires user setup & config)**
    *   **Impact:** High (Essential for performance, reliability, and avoiding rate limits).

## Suggested Enhancements (Pending):

- [ ] **Comprehensive RPKI Monitoring:**
    *   **Description:** Extend RPKI checks beyond simple validity. Monitor for ROA expirations, additions/deletions/edits compared to a baseline, and potentially Trust Anchor status changes. Requires deeper integration with local validator data.
    *   **Impact:** High (Provides proactive alerting on RPKI infrastructure issues).

- [ ] **Visibility Loss Detection:**
    *   **Description:** Implement monitoring to detect when configured prefixes lose visibility entirely or from a significant number of vantage points/peers. Requires significant state tracking per prefix.
    *   **Impact:** High (Critical for detecting outages or large-scale hijacks).

- [ ] **New Prefix Announcement Detection:**
    *   **Description:** Maintain a historical baseline of announced prefixes per AS. Alert when a monitored AS announces a prefix it has not announced before (or within a long timeframe). Requires persistent storage and baseline management.
    *   **Impact:** High (Can detect hijacks or significant network changes).

- [ ] **Add Internet Routing Registry (IRR) Checks:**
    *   **Description:** Implement validation of announcements against registered route/route6 objects in IRR databases (e.g., RADb).
    *   **Impact:** High (Adds another layer of routing policy validation).

- [ ] **Enhance Anomaly Detection:** (In Progress)
    *   **Description:** Move beyond simple origin checks. Build historical profiles/baselines for prefix behavior (origins, upstreams, stability) and flag deviations. **(Initial Isolation Forest implementation added; requires model training/loading)**
    *   **Impact:** Medium-High (Can detect novel or subtle hijacking attempts).

- [ ] **Integrate Dynamic Threat Intelligence:**
    *   **Description:** Replace static bad actor lists with integration into dynamic threat intelligence feeds for malicious ASNs/prefixes.
    *   **Impact:** Medium-High (Improves detection of known malicious activity).

- [ ] **Improve Configuration Management:**
    *   **Description:** Develop a more robust way to manage critical lists (prefixes, ASNs) than just JSON files (e.g., GUI section, dedicated tool).
    *   **Impact:** Medium (Improves usability and maintainability).

- [ ] **Implement Episode Management (GUI Enhancements):**
    *   **Description:** Enhance the GUI Episodes tab with dynamic updates as episodes evolve and add a view for seeing the individual alerts within a selected episode. **(Core logic, persistence, cleanup, basic GUI tab implemented)**
    *   **Impact:** Medium (Improves usability and operational insight).

- [ ] **Integrate PeeringDB Data (Path Validation):**
    *   **Description:** Use PeeringDB data (beyond AS Info context) to potentially validate peer-to-peer relationships seen in BGP paths. **(AS Info context lookup implemented)**
    *   **Impact:** Medium (Enhances validation of peering links).

- [ ] **Implement Bogon Filtering:**
    *   **Description:** Add filtering for announcements involving bogon prefixes (unallocated/reserved IPs) and bogon ASNs using lists like Team Cymru's.
    *   **Impact:** Medium (Important for hygiene and detecting noise/errors).

- [ ] **Optimize for Performance/Scalability:**
    *   **Description:** Investigate and implement optimizations (batching, async checks, sampling) if needed for high-volume BGP feeds.
    *   **Impact:** Medium (Depends on observed performance with real-world data).

### High Priority Improvements (Immediate Impact)

- [ ] **Develop Web-Based Interface**
    *   **Description:** Convert from Tkinter desktop app to a web application (e.g., using FastAPI + WebSockets + React/Vue frontend). Enables remote access, multi-user support, and easier deployment.
    *   **Impact:** High (Addresses thick-client limitation, improves accessibility).

- [ ] **Enhance AI Anomaly Detection**
    *   **Description:** Implement online learning for Isolation Forest, add more features (communities, peer diversity), integrate supervised models, add model persistence and automated retraining.
    *   **Impact:** High (Strengthens AI capabilities for better threat detection).

- [ ] **Optimize Performance & Scalability**
    *   **Description:** Move processing to background threads/async tasks, implement batch processing, add memory-efficient caching with LRU eviction, consider distributed processing.
    *   **Impact:** High (Critical for handling high-volume feeds without blocking UI).

### Medium Priority Improvements (Enhanced Functionality)

- [ ] **Dynamic Threat Intelligence Integration**
    *   **Description:** Replace static bad actor lists with feeds from BGPStream, CIRCL, or commercial providers. Add automated updates and reputation scoring.
    *   **Impact:** Medium-High (Improves detection of known malicious activity).

- [ ] **Additional Security Checks**
    *   **Description:** Add IRR validation, bogon filtering, visibility loss detection, and new prefix announcement monitoring.
    *   **Impact:** Medium-High (Enhances security monitoring coverage).

- [ ] **Improved Configuration Management**
    *   **Description:** Develop GUI/web interface for managing critical prefixes, AS lists, and thresholds with validation and bulk operations.
    *   **Impact:** Medium (Improves usability and maintainability).

### Lower Priority Improvements (Quality of Life)

- [ ] **Enhanced Visualization & Reporting**
    *   **Description:** Add interactive dashboards with charts for BGP trends, security incidents, and episode timelines. Implement advanced export capabilities.
    *   **Impact:** Medium (Better operational insights).

- [ ] **API Development**
    *   **Description:** Create REST API for programmatic access to monitoring data, alerts, and configuration.
    *   **Impact:** Medium (Enables SIEM integration and automation).

- [ ] **Comprehensive Testing & Monitoring**
    *   **Description:** Add extensive unit/integration tests and implement health checks with metrics collection.
    *   **Impact:** Medium (Improves reliability and maintainability).

- [ ] **Documentation & Training**
    *   **Description:** Expand documentation with deployment guides, troubleshooting, and training materials including video tutorials.
    *   **Impact:** Low-Medium (Enhances user adoption).
