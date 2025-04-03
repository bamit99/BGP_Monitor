# BGP Monitor Security Analysis & Improvement Plan

This document outlines the analysis of the current security monitoring implementation (`utils/security_analyzer.py`) and a plan for improvements, focusing on reliability for SIEM integration and minimizing false positives/negatives.

## Current Security Checks & Analysis

1.  **RPKI Validation (`check_rpki_validity`, `RPKIValidator`):**
    *   **Mechanism:** Uses RIPEstat API with 1-hour caching.
    *   **Assessment:** Fundamental check, common approach. Reliability depends on ROA/API accuracy. "RPKI Invalid: None" means API didn't provide a reason string, but the status is Invalid.
    *   **SIEM:** High value (Invalid), useful context (Valid/Unknown).
    *   **Improvements:** Consider fallback validator API; clarify "None" reason message.

2.  **Hijack Detection - Origin Change (`check_possible_hijack`):**
    *   **Mechanism:** Compares current origin AS with history (intended).
    *   **Assessment:** Core technique, but **currently non-functional** as history (`prefix_history={}`) is not maintained/passed correctly from the GUI.
    *   **SIEM:** High value *if* functional.
    *   **Improvements:** **CRITICAL FIX REQUIRED.** Implement state management (DB query or in-memory LRU cache) to track previous origins.

3.  **Hijack Detection - More Specifics (`check_possible_hijack`):**
    *   **Mechanism:** Checks if announcement is `+3` prefix length more specific than a configured critical prefix.
    *   **Assessment:** Valid concept, but arbitrary `+3` threshold is prone to false positives (traffic engineering) and false negatives.
    *   **SIEM:** Moderate value, needs investigation. High noise potential.
    *   **Improvements:** Make threshold configurable; correlate with other indicators (origin change, RPKI) for higher confidence.

4.  **Hijack Detection - Known Bad Actors (`check_possible_hijack`, `check_unusual_transit`):**
    *   **Mechanism:** Checks origin/transit AS against static list in `config/security_config.json`.
    *   **Assessment:** Good practice, but effectiveness depends entirely on list quality/maintenance.
    *   **SIEM:** High value if list is good.
    *   **Improvements:** Integrate with dynamic threat intelligence feeds if feasible.

5.  **Route Leak Detection - Valley-Free Paths (`check_route_leak`):**
    *   **Mechanism:** Uses AS relationship data (`utils/bgp_utils.py`) to check for C2P after P2C/P2P transitions.
    *   **Assessment:** Standard heuristic. Reliability depends heavily on AS relationship data accuracy/completeness (source/update frequency undocumented). Ignores `UNKNOWN` relationships.
    *   **SIEM:** Moderate value, often needs manual verification.
    *   **Improvements:** Document AS relationship data source/updates; consider configurability for handling `UNKNOWN`.

6.  **Route Leak Detection - Long AS Path (`check_route_leak`):**
    *   **Mechanism:** Flags paths `> 20` hops.
    *   **Assessment:** Weak heuristic, prone to false positives.
    *   **SIEM:** Low value, high noise.
    *   **Improvements:** Make threshold configurable (higher default); consider disabling by default or correlating.

7.  **Route Leak Detection - Private ASNs (`check_route_leak`):**
    *   **Mechanism:** Checks for standard private ASNs in path.
    *   **Assessment:** Good hygiene check.
    *   **SIEM:** Moderate value (indicates upstream misconfiguration/filtering issues).
    *   **Improvements:** Generally okay.

8.  **Path Prepending Check (`check_path_prepending`):**
    *   **Mechanism:** Flags `> 3` consecutive ASN repetitions.
    *   **Assessment:** Weak heuristic (prepending is legitimate), arbitrary threshold.
    *   **SIEM:** Low value, high noise.
    *   **Improvements:** Make threshold configurable; consider disabling by default.

9.  **Critical Prefix Check (`is_critical_prefix`):**
    *   **Mechanism:** Checks overlap with user-defined list in `config/security_config.json`.
    *   **Assessment:** Essential for prioritization.
    *   **SIEM:** Adds context/severity to other alerts.
    *   **Improvements:** Ensure configuration is well-documented and maintained by the user.

## Overall Assessment

*   **Strengths:** Covers key BGP security concepts (RPKI, Origin, Leaks, Bad Actors). Configurable critical prefixes.
*   **Weaknesses:**
    *   **Lack of State:** Origin change detection is broken. **(Highest Priority Fix)**
    *   **Weak Heuristics:** Long path, prepending, more-specific checks generate noise.
    *   **Data Dependency:** Relies on AS relationship data (source unclear) and static config lists.
    *   **SIEM Formatting:** Current log messages are strings, not structured data.
*   **SIEM Readiness:** Requires improvement. RPKI Invalid and Bad Actor alerts are most valuable currently. Others need fixing (origin change) or tuning (heuristics) to avoid overwhelming a SIEM.

## Improvement Plan

1.  **Implement State Management (CRITICAL):**
    *   **Goal:** Fix origin AS change detection.
    *   **Action:** Modify `check_suspicious_patterns` and `BGPMonitorGUI.process_update`. Implement retrieval of the *actual* last known origin for the prefix before calling the check.
    *   **Preferred Option:** Use an in-memory LRU cache within `BGPMonitorGUI` or a dedicated state manager class for performance, accepting state loss on restart as a trade-off. Alternatively, query Neo4j (slower).

2.  **Refine Heuristics & Thresholds:**
    *   **Goal:** Reduce noise from weak heuristics.
    *   **Action:**
        *   Move thresholds (long path, prepending, more-specific diff) to `config/app_settings.json`.
        *   Set conservative defaults (e.g., path > 30, prepend > 5).
        *   Lower default severity for alerts based *only* on these heuristics.
        *   Add config options to disable these checks individually.

3.  **Improve Alert Context & Formatting:**
    *   **Goal:** Enhance alert clarity and SIEM integration.
    *   **Action:**
        *   Modify `SecurityAlertLogger.log_alert` to use `logging.LoggerAdapter` or `extra` dictionary parameter to pass structured data (key-value pairs or JSON) to configured handlers (including Syslog). Include fields like `previous_origin_as`, `rpki_state`, `alert_type`, `prefix`, `origin_as`, `peer_as`, `as_path`, `reasons_list`, `is_critical`.
        *   Update the Syslog formatter in `main.py` to handle structured data if necessary (e.g., output JSON).
        *   Clarify the "RPKI Invalid: None" message.

4.  **Enhance Configuration & Data:**
    *   **Goal:** Improve transparency and reliability.
    *   **Action:**
        *   **Investigate & Document:** Determine the source and update process for the AS relationship data used in `utils/bgp_utils.py` and document it in the README or code comments.
        *   Add comments to `config/security_config.json` template explaining lists.
        *   Consider adding a configuration section for whitelisting expected origin changes.