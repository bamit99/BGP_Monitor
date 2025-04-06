# BGP Monitor Security Analysis & Improvement Plan

This document outlines the analysis of the security monitoring implementation (`utils/security_analyzer.py`) as of 2025-04-03 and the plan implemented to improve it.

## Security Checks Analysis (Post-Implementation)

1.  **RPKI Validation (`check_rpki_validity`, `RPKIValidator`):**
    *   **Mechanism:** Uses RIPEstat API with 1-hour caching.
    *   **Status:** Functional. "RPKI Invalid: None" reason clarified to "Reason unspecified by API".
    *   **SIEM:** High value (Invalid), useful context (Valid/Unknown).

2.  **Hijack Detection - Origin Change (`check_possible_hijack`):**
    *   **Mechanism:** Compares current origin AS with previous origin AS retrieved from an in-memory cache (`prefix_origin_cache` in `BGPMonitorGUI`).
    *   **Status:** **FIXED.** Now correctly uses state information passed from the GUI cache.
    *   **SIEM:** High value.

3.  **Hijack Detection - More Specifics (`check_possible_hijack`):**
    *   **Mechanism:** Checks if announcement is more specific than a configured critical prefix by a configurable length difference (`prefix_length_diff` in `app_settings.json`). Compares only same IP versions.
    *   **Status:** Functional. IP version comparison bug **FIXED**. Threshold configurable.
    *   **SIEM:** Moderate value. Configurable threshold helps tuning. Default severity configurable.

4.  **Hijack Detection - Known Bad Actors (`check_possible_hijack`, `check_unusual_transit`):**
    *   **Mechanism:** Checks origin/transit AS against static list in `config/security_config.json`.
    *   **Status:** Functional. Effectiveness depends on list maintenance.
    *   **SIEM:** High value if list is good.

5.  **Route Leak Detection - Valley-Free Paths (`check_route_leak`):**
    *   **Mechanism:** Uses AS relationship data (`utils/bgp_utils.py` from CAIDA file) to check for C2P after P2C/P2P transitions.
    *   **Status:** Functional. Reliability depends on CAIDA data file (`data/as_relationships.txt.bz2`) being present and up-to-date. Ignores `UNKNOWN` relationships.
    *   **SIEM:** Moderate value.

6.  **Route Leak Detection - Long AS Path (`check_route_leak`):**
    *   **Mechanism:** Flags paths longer than a configurable threshold (`long_path.threshold` in `app_settings.json`). Check can be disabled.
    *   **Status:** Functional. Configurable threshold allows tuning/disabling. Default severity configurable.
    *   **SIEM:** Low-Moderate value depending on tuning.

7.  **Route Leak Detection - Private ASNs (`check_route_leak`):**
    *   **Mechanism:** Checks for standard private ASNs in path.
    *   **Status:** Functional.
    *   **SIEM:** Moderate value (indicates upstream misconfiguration).

8.  **Path Prepending Check (`check_path_prepending`):**
    *   **Mechanism:** Flags paths where an ASN repeats consecutively more times than a configurable threshold (`prepending.threshold` in `app_settings.json`). Check can be disabled.
    *   **Status:** Functional. Configurable threshold allows tuning/disabling. Default severity configurable.
    *   **SIEM:** Low value depending on tuning.

9.  **Critical Prefix Check (`is_critical_prefix`):**
    *   **Mechanism:** Checks overlap with user-defined list in `config/security_config.json`.
    *   **Status:** Functional.
    *   **SIEM:** Adds context/severity.

10. **Alert Logging & Formatting:**
    *   **Mechanism:** `SecurityAlertLogger` uses standard Python logging, passing structured data via `extra`. `main.py` configures a `JsonSyslogFormatter` for the Syslog handler. CSV and DB logging retained as secondary options.
    *   **Status:** **IMPROVED.** Alerts logged centrally, structured data available for handlers. Syslog output is JSON.
    *   **SIEM:** Significantly improved readiness due to structured logging.

## Implemented Improvements Summary

*   **Fixed Origin Change Detection:** Implemented in-memory prefix origin cache in GUI.
*   **Configurable Heuristics:** Added thresholds, enable flags, and severities for long path, prepending, and more-specific checks to `app_settings.json`.
*   **Fixed IP Version Bug:** Corrected comparison logic in more-specific check.
*   **Structured Logging:** Implemented JSON formatter for Syslog and passed structured alert data via `logger` calls.
*   **Clarified RPKI Reason:** Improved message for "RPKI Invalid" when API provides no specific reason.
*   **Documentation:** Added comments regarding AS relationship data source and updated README for new configurations.
*   **Fixed Alert Storage:** Ensured `alert_logger.log_alert` is called correctly from GUI to trigger DB/CSV storage. Made DB alert storage more robust.
*   **Fixed AS Path Filtering:** Implemented filtering logic in `BGPMonitorGUI.process_update`.
*   **Fixed UI Layout:** Used `ttk.PanedWindow` to ensure both main panels are always visible and resizable.