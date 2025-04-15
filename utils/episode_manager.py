"""
Episode Manager for BGP Monitor

This module provides functionality for aggregating BGP security alerts into episodes,
scoring them, and enriching them with metadata.

An episode is a group of related BGP events (e.g., hijacks, leaks) for the same prefix
and/or origin ASN, occurring within a configurable time window.
"""

import logging
import datetime
from typing import Dict, List, Optional, Any, Tuple, Set
from dataclasses import dataclass, field
from datetime import datetime, timedelta # Ensure timedelta is imported
import json
import uuid
from utils.config_manager import config_manager

# Configure logging
logger = logging.getLogger(__name__)

# Load app settings globally for episode configuration
APP_SETTINGS = config_manager.load_app_settings()
EPISODE_CONFIG = APP_SETTINGS.get("episode_management", {})

def compute_edit_distance(path1: str, path2: str) -> int:
    """
    Compute the Levenshtein edit distance between two AS paths.
    
    Args:
        path1: First AS path as a comma-separated string
        path2: Second AS path as a comma-separated string
        
    Returns:
        Edit distance (number of operations to transform path1 to path2)
    """
    if not path1 or not path2:
        return 0
        
    # Split paths into ASN lists
    a = path1.split(",")
    b = path2.split(",")
    
    # Initialize DP table
    dp = [[0] * (len(b)+1) for _ in range(len(a)+1)]
    
    # Fill DP table
    for i in range(len(a)+1):
        for j in range(len(b)+1):
            if i == 0:
                dp[i][j] = j
            elif j == 0:
                dp[i][j] = i
            elif a[i-1] == b[j-1]:
                dp[i][j] = dp[i-1][j-1]
            else:
                dp[i][j] = 1 + min(dp[i-1][j], dp[i][j-1], dp[i-1][j-1])
    
    return dp[-1][-1]

def determine_hijack_scope(event: Dict) -> str:
    """
    Determine the scope of a hijack event (global, regional, etc.).
    
    Args:
        event: The event dictionary
        
    Returns:
        Scope as a string
    """
    # This is a placeholder implementation
    # In a real implementation, you would analyze the event data
    # to determine if the hijack is global, regional, etc.
    # For example, you could check the number of peers reporting the event
    # or the geographic distribution of peers
    
    # For now, return a default value
    return "UNKNOWN"

def determine_hijack_subtype(event: Dict) -> str:
    """
    Determine the subtype of a hijack event (origin change, more-specific, etc.).
    
    Args:
        event: The event dictionary
        
    Returns:
        Subtype as a string
    """
    # Check for origin change
    if 'previous_origin_as' in event and event.get('origin_as') != event.get('previous_origin_as'):
        return "ORIGIN_CHANGE"
    
    # Check for more-specific hijack (would need prefix and parent prefix info)
    if any("more-specific" in reason.lower() for reason in event.get('reasons', [])):
        return "MORE_SPECIFIC"
    
    # Check for path manipulation
    if any("prepending" in reason.lower() for reason in event.get('reasons', [])):
        return "PATH_MANIPULATION"
    
    # Default
    return "UNKNOWN"

class Episode:
    """
    Represents a group of related BGP security events.
    
    An episode is defined by a prefix, origin AS, and time window.
    It contains a list of events, a score, and metadata.
    """
    
    def __init__(self, prefix: str, origin_as: Optional[int], start_time: datetime):
        """
        Initialize a new episode.
        
        Args:
            prefix: The IP prefix
            origin_as: The origin AS number
            start_time: The start time of the episode
        """
        self.id = str(uuid.uuid4())
        self.prefix = prefix
        self.origin_as = origin_as
        self.start_time = start_time
        self.end_time = start_time
        self.events = []
        self.max_severity = "LOW"
        self.score = 0
        self.event_count = 0
        self.metadata = {
            "hijack_scope": None,
            "hijack_subtype": None,
            "edit_distance": None,
            "affected_asns": set(),
            "affected_countries": set(),
            "is_critical_prefix": False,
        }
        self.status = "OPEN"  # OPEN, CLOSED
    
    def add_event(self, event: Dict) -> None:
        """
        Add an event to the episode.
        
        Args:
            event: The event dictionary
        """
        self.events.append(event)
        self.event_count += 1
        
        # Update end time
        event_time = event.get('timestamp', datetime.now())
        if isinstance(event_time, str):
            try:
                event_time = datetime.fromisoformat(event_time.replace('Z', '+00:00'))
            except ValueError:
                event_time = datetime.now()
        
        self.end_time = max(self.end_time, event_time)
        
        # Update max severity
        event_severity = event.get('severity', 'LOW')
        severity_map = {"LOW": 0, "MEDIUM": 1, "HIGH": 2}
        if severity_map.get(event_severity, 0) > severity_map.get(self.max_severity, 0):
            self.max_severity = event_severity
        
        # Update score
        self.score += self._calculate_event_score(event)
        
        # Update metadata
        self._update_metadata(event)
    
    def _calculate_event_score(self, event: Dict) -> float:
        """
        Calculate a score for an event based on its severity and other factors.
        
        Args:
            event: The event dictionary
            
        Returns:
            Score as a float
        """
        # Base score by severity
        severity_scores = EPISODE_CONFIG.get("severity_scores", {"LOW": 1, "MEDIUM": 5, "HIGH": 10})
        base_score = severity_scores.get(event.get('severity', 'LOW'), 1)
        
        # Adjust for critical prefixes
        if event.get('is_critical_prefix', False):
            base_score *= EPISODE_CONFIG.get("critical_prefix_multiplier", 2)
        
        # Adjust for hijack subtype
        if 'previous_origin_as' in event and event.get('origin_as') != event.get('previous_origin_as'):
            base_score *= EPISODE_CONFIG.get("origin_change_multiplier", 1.5)
        
        # Adjust for RPKI invalidity
        if any("rpki invalid" in reason.lower() for reason in event.get('reasons', [])):
            base_score *= EPISODE_CONFIG.get("rpki_invalid_multiplier", 1.5)
        
        return base_score
    
    def _update_metadata(self, event: Dict) -> None:
        """
        Update episode metadata based on a new event.
        
        Args:
            event: The event dictionary
        """
        # Update edit distance if AS paths are available
        if 'as_path' in event and hasattr(self, 'previous_as_path'):
            edit_dist = compute_edit_distance(self.previous_as_path, event['as_path'])
            if self.metadata['edit_distance'] is None or edit_dist > self.metadata['edit_distance']:
                self.metadata['edit_distance'] = edit_dist
        
        # Store current AS path for future edit distance calculations
        if 'as_path' in event:
            self.previous_as_path = event['as_path']
        
        # Update hijack scope if not already set
        if self.metadata['hijack_scope'] is None or self.metadata['hijack_scope'] == "UNKNOWN":
            self.metadata['hijack_scope'] = determine_hijack_scope(event)
        
        # Update hijack subtype if not already set
        if self.metadata['hijack_subtype'] is None or self.metadata['hijack_subtype'] == "UNKNOWN":
            self.metadata['hijack_subtype'] = determine_hijack_subtype(event)
        
        # Update affected ASNs
        if 'origin_as' in event and event['origin_as']:
            self.metadata['affected_asns'].add(event['origin_as'])
        if 'previous_origin_as' in event and event['previous_origin_as']:
            self.metadata['affected_asns'].add(event['previous_origin_as'])
        
        # Update critical prefix flag
        if event.get('is_critical_prefix', False):
            self.metadata['is_critical_prefix'] = True
    
    def should_include_event(self, event: Dict) -> bool:
        """
        Determine if an event should be included in this episode.
        
        Args:
            event: The event dictionary
            
        Returns:
            True if the event should be included, False otherwise
        """
        # Check prefix match
        if event.get('prefix') != self.prefix:
            return False
        
        # Check origin AS match (if specified)
        if self.origin_as is not None:
            if event.get('origin_as') != self.origin_as and event.get('previous_origin_as') != self.origin_as:
                return False
        
        # Check time window
        event_time = event.get('timestamp', datetime.now())
        if isinstance(event_time, str):
            try:
                event_time = datetime.fromisoformat(event_time.replace('Z', '+00:00'))
            except ValueError:
                event_time = datetime.now()
        
        time_window = EPISODE_CONFIG.get("time_window_minutes", 60)
        if (event_time - self.end_time).total_seconds() > time_window * 60:
            return False
        
        return True
    
    def close(self) -> None:
        """
        Close the episode.
        """
        self.status = "CLOSED"
    
    def to_dict(self) -> Dict:
        """
        Convert the episode to a dictionary.
        
        Returns:
            Dictionary representation of the episode
        """
        # Convert set to list for JSON serialization
        metadata = dict(self.metadata)
        metadata['affected_asns'] = list(metadata['affected_asns'])
        metadata['affected_countries'] = list(metadata['affected_countries'])
        
        return {
            "id": self.id,
            "prefix": self.prefix,
            "origin_as": self.origin_as,
            "start_time": self.start_time.isoformat(),
            "end_time": self.end_time.isoformat(),
            "max_severity": self.max_severity,
            "score": self.score,
            "event_count": self.event_count,
            "metadata": metadata,
            "status": self.status,
            # Don't include full events by default to keep the dict size manageable
            # "events": self.events
        }

class EpisodeManager:
    """
    Manages episodes of BGP security events.
    
    Responsible for creating, updating, and retrieving episodes.
    """
    
    def __init__(self, db_manager=None):
        """
        Initialize the episode manager.
        
        Args:
            db_manager: Optional database manager for storing episodes
        """
        self.active_episodes = {}  # Dict of active episodes by (prefix, origin_as)
        self.db_manager = db_manager
        self.time_window_minutes = EPISODE_CONFIG.get("time_window_minutes", 60)
        self.max_events_per_episode = EPISODE_CONFIG.get("max_events_per_episode", 100)
        
        # Load episodes from database if available
        if db_manager:
            try:
                self._load_active_episodes()
            except Exception as e:
                logger.error(f"Failed to load active episodes from database: {e}")
    
    def _load_active_episodes(self) -> None:
        """
        Load active episodes from the database.
        """
        if not self.db_manager:
            return
        
        logger.info("Attempting to load active episodes from database...")
        try:
            active_episodes_data = self.db_manager.get_active_episodes()
            loaded_count = 0
            for episode_data in active_episodes_data:
                try:
                    # Convert Neo4j DateTime to Python datetime
                    start_time_native = episode_data['start_time']
                    if hasattr(start_time_native, 'to_native'):
                        start_time_native = start_time_native.to_native()
                    # Handle potential string fallback if stored incorrectly (less likely)
                    elif isinstance(start_time_native, str):
                         start_time_native = datetime.fromisoformat(start_time_native)
                    else: # Add a fallback if type is unexpected
                         logger.warning(f"Unexpected start_time type for episode {episode_data.get('id', 'N/A')}: {type(start_time_native)}. Using current time.")
                         start_time_native = datetime.now() # Fallback

                    # Create the episode instance
                    episode = Episode(
                        prefix=episode_data['prefix'],
                        origin_as=episode_data['origin_as'],
                        start_time=start_time_native # Use converted datetime
                    )

                    # Restore episode state from loaded data
                    episode.id = episode_data['id']

                    # Convert end_time
                    end_time_native = episode_data.get('end_time') # Use get() for safety
                    if end_time_native:
                        if hasattr(end_time_native, 'to_native'):
                            episode.end_time = end_time_native.to_native()
                        elif isinstance(end_time_native, str):
                             episode.end_time = datetime.fromisoformat(end_time_native)
                        else:
                             logger.warning(f"Unexpected end_time type for episode {episode.id}: {type(end_time_native)}. Using start time.")
                             episode.end_time = start_time_native # Fallback if end_time is missing/invalid
                    else:
                         episode.end_time = start_time_native # Fallback if end_time is missing

                    episode.max_severity = episode_data.get('max_severity', 'LOW') # Use get() with default
                    episode.score = episode_data.get('score', 0) # Use get() with default
                    episode.event_count = episode_data.get('event_count', 0) # Use get() with default
                    episode.status = episode_data.get('status', 'OPEN') # Use get() with default

                    # Restore metadata, converting lists back to sets where needed
                    loaded_metadata = episode_data.get('metadata', {})
                    if isinstance(loaded_metadata, dict): # Ensure metadata is a dict
                         episode.metadata = loaded_metadata
                         # Ensure keys exist before converting to set
                         episode.metadata['affected_asns'] = set(episode.metadata.get('affected_asns', []))
                         episode.metadata['affected_countries'] = set(episode.metadata.get('affected_countries', []))
                    else:
                         logger.warning(f"Invalid metadata format for episode {episode.id}, resetting.")
                         episode.metadata = {'affected_asns': set(), 'affected_countries': set()} # Reset with empty sets

                    # Add to active episodes dictionary
                    key = (episode.prefix, episode.origin_as)
                    self.active_episodes[key] = episode
                    loaded_count += 1

                except Exception as inner_e:
                    logger.error(f"Failed to reconstruct episode from data {episode_data.get('id', 'N/A')}: {inner_e}", exc_info=True) # Add traceback
                    continue # Skip this episode and try the next

            logger.info(f"Successfully loaded {loaded_count} active episodes.")

        except Exception as outer_e:
            logger.error(f"Failed to retrieve active episodes from database: {outer_e}", exc_info=True) # Add traceback
    
    def process_event(self, event: Dict) -> Optional[Dict]:
        """
        Process a new event and add it to an appropriate episode.
        
        Args:
            event: The event dictionary
            
        Returns:
            The updated episode as a dictionary, or None if the event wasn't added to any episode
        """
        if not event:
            return None
        
        prefix = event.get('prefix')
        origin_as = event.get('origin_as')
        previous_origin_as = event.get('previous_origin_as')
        
        if not prefix:
            return None
        
        # Try to find an existing episode for this event
        episode = self._find_matching_episode(event)
        
        # If no matching episode, create a new one
        if not episode:
            event_time = event.get('timestamp', datetime.now())
            if isinstance(event_time, str):
                try:
                    event_time = datetime.fromisoformat(event_time.replace('Z', '+00:00'))
                except ValueError:
                    event_time = datetime.now()
            
            episode = Episode(prefix, origin_as, event_time)
            
            # Add to active episodes
            key = (prefix, origin_as)
            self.active_episodes[key] = episode
        
        # Add event to episode
        episode.add_event(event)
        
        # Check if episode should be closed
        if episode.event_count >= self.max_events_per_episode:
            self._close_episode(episode)
        
        # Store episode in database if available
        if self.db_manager:
            try:
                self._store_episode(episode)
            except Exception as e:
                logger.error(f"Failed to store episode in database: {e}")
        
        return episode.to_dict()
    
    def _find_matching_episode(self, event: Dict) -> Optional[Episode]:
        """
        Find an existing episode that matches the event.
        
        Args:
            event: The event dictionary
            
        Returns:
            Matching episode or None
        """
        prefix = event.get('prefix')
        origin_as = event.get('origin_as')
        previous_origin_as = event.get('previous_origin_as')
        
        # Check for exact match by prefix and origin AS
        key = (prefix, origin_as)
        if key in self.active_episodes and self.active_episodes[key].should_include_event(event):
            return self.active_episodes[key]
        
        # Check for match by prefix and previous origin AS
        if previous_origin_as:
            key = (prefix, previous_origin_as)
            if key in self.active_episodes and self.active_episodes[key].should_include_event(event):
                return self.active_episodes[key]
        
        # Check for match by prefix only (origin AS is None)
        key = (prefix, None)
        if key in self.active_episodes and self.active_episodes[key].should_include_event(event):
            return self.active_episodes[key]
        
        return None
    
    def _close_episode(self, episode: Episode) -> None:
        """
        Close an episode and remove it from active episodes.
        
        Args:
            episode: The episode to close
        """
        episode.close()
        
        # Remove from active episodes
        key = (episode.prefix, episode.origin_as)
        if key in self.active_episodes:
            del self.active_episodes[key]
        
        # Store in database if available
        if self.db_manager:
            try:
                self._store_episode(episode, final=True)
            except Exception as e:
                logger.error(f"Failed to store closed episode in database: {e}")
    
    def _store_episode(self, episode: Episode, final: bool = False) -> None:
        """
        Store an episode in the database.
        
        Args:
            episode: The episode to store
            final: Whether this is the final update for the episode
        """
        if not self.db_manager:
            return
        
        # This is a placeholder - actual implementation depends on your DB schema
        # self.db_manager.store_episode(episode.to_dict(), final=final)

    def cleanup_old_episodes(self) -> None:
        """
        Periodically check active episodes and close those that have been inactive
        (no new events added) for longer than the configured threshold.
        """
        cleanup_threshold_hours = EPISODE_CONFIG.get("cleanup_threshold_hours", 24) # Default to 24 hours
        if not isinstance(cleanup_threshold_hours, (int, float)) or cleanup_threshold_hours <= 0:
            logger.warning(f"Invalid cleanup_threshold_hours ({cleanup_threshold_hours}), using default 24.")
            cleanup_threshold_hours = 24

        cleanup_delta = timedelta(hours=cleanup_threshold_hours)
        now = datetime.now()
        closed_count = 0
        episodes_to_close = [] # Collect episodes to close outside the loop

        # Iterate over a copy of the values to allow modification during iteration
        for episode in list(self.active_episodes.values()):
            # Ensure end_time is a datetime object
            end_time = episode.end_time
            if not isinstance(end_time, datetime):
                 # Attempt conversion if string, otherwise skip
                 if isinstance(end_time, str):
                     try:
                         end_time = datetime.fromisoformat(end_time.replace('Z', '+00:00'))
                     except ValueError:
                         logger.warning(f"Skipping cleanup check for episode {episode.id} due to invalid end_time format: {episode.end_time}")
                         continue
                 else:
                     logger.warning(f"Skipping cleanup check for episode {episode.id} due to unexpected end_time type: {type(episode.end_time)}")
                     continue

            if episode.status == "OPEN" and (now - end_time) > cleanup_delta:
                logger.info(f"Closing inactive episode {episode.id} (prefix: {episode.prefix}, origin: {episode.origin_as}). Last event: {end_time}")
                episodes_to_close.append(episode)

        # Close the collected episodes
        for episode in episodes_to_close:
             try:
                 self._close_episode(episode) # This handles DB update and removal from active_episodes
                 closed_count += 1
             except Exception as e:
                 logger.error(f"Error closing episode {episode.id} during cleanup: {e}")

        if closed_count > 0:
            logger.info(f"Automated cleanup closed {closed_count} inactive episodes.")
        # else:
            # logger.debug("Automated cleanup: No inactive episodes found to close.")

    def get_active_episodes(self) -> List[Dict]:
        """
        Get all active episodes.
        
        Returns:
            List of episode dictionaries
        """
        return [episode.to_dict() for episode in self.active_episodes.values()]
    
    def get_episode_by_id(self, episode_id: str) -> Optional[Dict]:
        """
        Get an episode by ID.
        
        Args:
            episode_id: The episode ID
            
        Returns:
            Episode dictionary or None
        """
        for episode in self.active_episodes.values():
            if episode.id == episode_id:
                return episode.to_dict()
        
        # If not found in active episodes, try database
        if self.db_manager:
            try:
                # This is a placeholder - actual implementation depends on your DB schema
                # return self.db_manager.get_episode_by_id(episode_id)
                pass
            except Exception as e:
                logger.error(f"Failed to get episode from database: {e}")
        
        return None
    
    def cleanup_old_episodes(self) -> None:
        """
        Close and remove episodes that have been inactive for too long.
        """
        now = datetime.now()
        episodes_to_close = []
        
        for key, episode in self.active_episodes.items():
            inactive_time = (now - episode.end_time).total_seconds() / 60
            if inactive_time > self.time_window_minutes:
                episodes_to_close.append(episode)
        
        for episode in episodes_to_close:
            self._close_episode(episode)

# Initialize global episode manager
episode_manager = None

def get_episode_manager(db_manager=None):
    """
    Get the global episode manager instance.
    
    Args:
        db_manager: Optional database manager for storing episodes
        
    Returns:
        EpisodeManager instance
    """
    global episode_manager
    if episode_manager is None:
        episode_manager = EpisodeManager(db_manager)
    return episode_manager
