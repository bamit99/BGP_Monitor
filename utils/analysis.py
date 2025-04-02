"""
BGP Data Analysis and Visualization
Focused on security analysis for UK telecom organizations
"""

import pandas as pd
import numpy as np
import logging
import json
import matplotlib.pyplot as plt
import networkx as nx
from pathlib import Path
import datetime
import ipaddress
from collections import Counter
import seaborn as sns
import plotly.graph_objects as go
import plotly.express as px
from typing import Dict, List, Tuple, Set, Any, Optional

# Import security analyzer for access to critical prefixes and ASNs
from utils.security_analyzer import (
    UK_CRITICAL_PREFIXES,
    # UK_TELECOM_ASNS, # Removed import
    is_critical_prefix
)

class BGPAnalyzer:
    """Analyze BGP data for security insights."""
    
    def __init__(self, output_dir: Optional[str] = None):
        """Initialize BGP Analyzer."""
        self.output_dir = Path(output_dir) if output_dir else Path("analysis_output")
        self.output_dir.mkdir(exist_ok=True)
        
        # Setup logging
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(logging.INFO)
        
    def load_data(self, filepath: str) -> pd.DataFrame:
        """Load BGP data from CSV file."""
        try:
            df = pd.read_csv(filepath)
            
            # Convert timestamp to datetime
            if 'timestamp' in df.columns:
                df['timestamp'] = pd.to_datetime(df['timestamp'])
            
            self.logger.info(f"Loaded {len(df)} BGP updates from {filepath}")
            return df
        except Exception as e:
            self.logger.error(f"Error loading data: {e}")
            return pd.DataFrame()
    
    def filter_uk_data(self, df: pd.DataFrame) -> pd.DataFrame:
        """Filter data to only UK-relevant updates."""
        if df.empty:
            return df
            
        uk_relevant = pd.DataFrame()
        
        try:
            # Removed filtering by UK telecom ASNs in the path
            uk_as_filter = pd.Series([False] * len(df)) # Create a series of False to avoid breaking logic below
            # Filter by critical prefixes
            if 'prefix' in df.columns:
                uk_prefix_filter = df['prefix'].apply(is_critical_prefix)
                
                # Combine filters
                uk_relevant = df[uk_as_filter | uk_prefix_filter].copy()
            else:
                uk_relevant = df[uk_as_filter].copy()
                
            self.logger.info(f"Filtered to {len(uk_relevant)} UK-relevant updates")
            return uk_relevant
        except Exception as e:
            self.logger.error(f"Error filtering UK data: {e}")
            return df
    
    def analyze_updates(self, df: pd.DataFrame) -> Dict[str, Any]:
        """Analyze BGP updates and return insights."""
        if df.empty:
            return {}
            
        results = {}
        
        try:
            # 1. Time-based analysis
            if 'timestamp' in df.columns:
                # Updates per hour
                df['hour'] = df['timestamp'].dt.floor('H')
                updates_per_hour = df.groupby('hour').size()
                results['updates_per_hour'] = updates_per_hour.to_dict()
                
                # Peak activity times
                peak_hours = updates_per_hour.nlargest(5)
                results['peak_activity_times'] = peak_hours.to_dict()
            
            # 2. AS path analysis
            if 'as_path' in df.columns:
                # Most common origin ASNs
                def extract_origin(path):
                    if not path or pd.isna(path):
                        return None
                    try:
                        # Handle both comma and semicolon separated paths
                        separator = ';' if ';' in str(path) else ','
                        asns = str(path).split(separator)
                        return int(asns[-1]) if asns else None
                    except:
                        return None
                
                df['origin_as'] = df['as_path'].apply(extract_origin)
                origin_counts = df['origin_as'].value_counts().head(10)
                results['top_origin_asns'] = origin_counts.to_dict()
                
                # Path length distribution
                def path_length(path):
                    if not path or pd.isna(path):
                        return 0
                    # Handle both comma and semicolon separated paths
                    separator = ';' if ';' in str(path) else ','
                    return len(str(path).split(separator))
                
                df['path_length'] = df['as_path'].apply(path_length)
                path_length_dist = df['path_length'].value_counts().sort_index()
                results['path_length_distribution'] = path_length_dist.to_dict()
                
                # Unusual path lengths (potential anomalies)
                q3 = df['path_length'].quantile(0.75)
                iqr = df['path_length'].quantile(0.75) - df['path_length'].quantile(0.25)
                anomaly_threshold = q3 + (1.5 * iqr)
                unusual_paths = df[df['path_length'] > anomaly_threshold]
                results['unusual_path_length_count'] = len(unusual_paths)
                
                # Collect some samples of unusual paths
                if not unusual_paths.empty:
                    results['unusual_path_samples'] = unusual_paths.head(5)[['timestamp', 'prefix', 'as_path']].to_dict('records')
            
            # 3. Prefix analysis
            if 'prefix' in df.columns:
                # Most active prefixes
                prefix_counts = df['prefix'].value_counts().head(10)
                results['most_active_prefixes'] = prefix_counts.to_dict()
                
                # Prefix length distribution
                def prefix_length(prefix):
                    if not prefix or pd.isna(prefix):
                        return 0
                    try:
                        return int(str(prefix).split('/')[1])
                    except:
                        return 0
                
                df['prefix_length'] = df['prefix'].apply(prefix_length)
                prefix_length_dist = df['prefix_length'].value_counts().sort_index()
                results['prefix_length_distribution'] = prefix_length_dist.to_dict()
                
                # More-specific prefixes (potential hijacks)
                more_specific = df[df['prefix_length'] > 24]  # IPv4 /24 is common boundary
                results['more_specific_prefix_count'] = len(more_specific)
                
                if not more_specific.empty:
                    results['more_specific_samples'] = more_specific.head(5)[['timestamp', 'prefix', 'origin_as']].to_dict('records')
            
            # 4. UK-specific analysis
            uk_data = self.filter_uk_data(df)
            
            if not uk_data.empty:
                # Removed UK telecom AS appearance counts analysis
                # results['uk_telecom_as_activity'] = {} # Or remove the key entirely
                
                # Critical prefix activity
                if 'prefix' in uk_data.columns:
                    critical_updates = uk_data[uk_data['prefix'].apply(is_critical_prefix)]
                    results['critical_prefix_update_count'] = len(critical_updates)
                    
                    if not critical_updates.empty:
                        results['critical_prefix_samples'] = critical_updates.head(5)[['timestamp', 'prefix', 'origin_as']].to_dict('records')
            
            # 5. Suspicious activity summary
            suspicious = df[df['suspicious'] == True] if 'suspicious' in df.columns else pd.DataFrame()
            
            if not suspicious.empty:
                results['suspicious_update_count'] = len(suspicious)
                results['suspicious_samples'] = suspicious.head(5)[['timestamp', 'prefix', 'as_path', 'alert_reasons']].to_dict('records')
            
            self.logger.info(f"Analysis complete: {len(results)} results categories")
            return results
        except Exception as e:
            self.logger.error(f"Error analyzing updates: {e}")
            return {'error': str(e)}
    
    def plot_as_relationships(self, df: pd.DataFrame, 
                             focus_on_uk: bool = True,
                             min_weight: int = 2,
                             save_path: Optional[str] = None) -> go.Figure:
        """
        Create an interactive graph of AS relationships.
        
        Parameters:
        - df: DataFrame with BGP updates
        - focus_on_uk: Whether to highlight UK telecom ASNs
        - min_weight: Minimum number of announcements to include a link
        - save_path: Path to save the visualization (HTML format)
        
        Returns:
        - Plotly figure object
        """
        if df.empty or 'as_path' not in df.columns:
            return None
            
        try:
            # Create a graph
            G = nx.DiGraph()
            
            # Track AS relationships and counts
            relationships = {}
            
            # Process AS paths
            for _, row in df.iterrows():
                if pd.isna(row['as_path']):
                    continue
                    
                try:
                    # Handle both comma and semicolon separated paths
                    path_str = str(row['as_path'])
                    separator = ';' if ';' in path_str else ','
                    asns = [int(asn) for asn in path_str.split(separator)]
                    
                    # Add nodes
                    for asn in asns:
                        if asn not in G:
                            # Removed UK highlighting logic
                            is_uk = False # Default to False
                            G.add_node(asn, is_uk=is_uk)
                    
                    # Add edges (AS relationships)
                    for i in range(len(asns) - 1):
                        as1, as2 = asns[i], asns[i+1]
                        key = (as1, as2)
                        
                        if key in relationships:
                            relationships[key] += 1
                        else:
                            relationships[key] = 1
                except:
                    continue
            
            # Add edges with weights to the graph
            for (as1, as2), weight in relationships.items():
                if weight >= min_weight:
                    G.add_edge(as1, as2, weight=weight)
            
            # If not enough nodes, lower the threshold
            if len(G.edges) < 5 and min_weight > 1:
                for (as1, as2), weight in relationships.items():
                    if weight >= 1:
                        G.add_edge(as1, as2, weight=weight)
            
            # Filter to largest connected component if there are disconnected parts
            if not nx.is_connected(G.to_undirected()):
                largest_cc = max(nx.connected_components(G.to_undirected()), key=len)
                G = G.subgraph(largest_cc).copy()
            
            # Use ForceAtlas2 layout
            pos = nx.spring_layout(G, k=0.15, iterations=50)
            
            # Prepare node attributes
            node_x = []
            node_y = []
            node_text = []
            node_size = []
            node_color = []
            
            for node in G.nodes():
                x, y = pos[node]
                node_x.append(x)
                node_y.append(y)
                
                # Simplified text label
                node_text.append(f"AS{node}")
                
                # Uniform node size and color
                node_size.append(10)
                node_color.append("blue")
            
            # Prepare edge attributes
            edge_x = []
            edge_y = []
            edge_width = []
            edge_text = []
            
            for edge in G.edges():
                x0, y0 = pos[edge[0]]
                x1, y1 = pos[edge[1]]
                
                # Draw curved lines for multiedges
                edge_x.append(x0)
                edge_x.append(x1)
                edge_x.append(None)
                edge_y.append(y0)
                edge_y.append(y1)
                edge_y.append(None)
                
                # Edge width based on weight
                weight = G.edges[edge]['weight']
                width = 1 + (weight / 5)  # Scale width
                edge_width.extend([width, width, None])
                
                # Edge text
                edge_text.extend([f"AS{edge[0]} → AS{edge[1]}<br>Weight: {weight}", "", ""])
            
            # Create the figure
            fig = go.Figure()
            
            # Add edges
            fig.add_trace(go.Scatter(
                x=edge_x, y=edge_y,
                line=dict(width=edge_width, color='#888'),
                hoverinfo='text',
                text=edge_text,
                mode='lines'
            ))
            
            # Add nodes
            fig.add_trace(go.Scatter(
                x=node_x, y=node_y,
                mode='markers',
                hoverinfo='text',
                text=node_text,
                marker=dict(
                    showscale=False,
                    color=node_color,
                    size=node_size,
                    line=dict(width=2, color='#000')
                )
            ))
            
            # Update layout
            fig.update_layout(
                title='AS Relationship Graph', # Removed UK specific text
                titlefont_size=16,
                showlegend=False,
                hovermode='closest',
                margin=dict(b=20, l=5, r=5, t=40),
                xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
                yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
                width=1000,
                height=800
            )
            
            # Save if requested
            if save_path:
                fig.write_html(save_path)
                self.logger.info(f"AS relationship graph saved to {save_path}")
            
            return fig
        except Exception as e:
            self.logger.error(f"Error plotting AS relationships: {e}")
            return None
    
    def plot_uk_prefix_activity(self, df: pd.DataFrame, save_path: Optional[str] = None) -> go.Figure:
        """
        Plot activity related to UK critical prefixes.
        
        Parameters:
        - df: DataFrame with BGP updates
        - save_path: Path to save the visualization (HTML format)
        
        Returns:
        - Plotly figure object
        """
        if df.empty or 'prefix' not in df.columns or 'timestamp' not in df.columns:
            return None
            
        try:
            # Filter to only updates involving critical prefixes
            uk_prefix_updates = df[df['prefix'].apply(is_critical_prefix)].copy()
            
            if uk_prefix_updates.empty:
                self.logger.warning("No updates involving UK critical prefixes found")
                return None
            
            # Group by hour and prefix
            uk_prefix_updates['hour'] = uk_prefix_updates['timestamp'].dt.floor('H')
            activity = uk_prefix_updates.groupby(['hour', 'prefix']).size().reset_index(name='count')
            
            # Sort by time
            activity = activity.sort_values('hour')
            
            # Create heatmap
            fig = px.density_heatmap(
                activity,
                x='hour',
                y='prefix',
                z='count',
                title='UK Critical Prefix Activity Over Time',
                labels={'hour': 'Time', 'prefix': 'Prefix', 'count': 'Update Count'},
                color_continuous_scale='Viridis'
            )
            
            # Update layout
            fig.update_layout(
                xaxis_title='Time',
                yaxis_title='Prefix',
                width=1000,
                height=600,
                yaxis={'categoryorder': 'total ascending'}
            )
            
            # Save if requested
            if save_path:
                fig.write_html(save_path)
                self.logger.info(f"UK prefix activity plot saved to {save_path}")
            
            return fig
        except Exception as e:
            self.logger.error(f"Error plotting UK prefix activity: {e}")
            return None
    
    def generate_security_report(self, results: Dict[str, Any], 
                                out_file: Optional[str] = None) -> str:
        """
        Generate a security report from analysis results.
        
        Parameters:
        - results: Dictionary of analysis results
        - out_file: Path to save the HTML report
        
        Returns:
        - HTML report content
        """
        if not results:
            return "<h1>No data available for report</h1>"
            
        try:
            # Start HTML content
            html = []
            html.append("""
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>BGP Security Report</title>
                <style>
                    body { font-family: Arial, sans-serif; margin: 20px; color: #333; }
                    h1 { color: #0066cc; border-bottom: 2px solid #0066cc; padding-bottom: 10px; }
                    h2 { color: #0066cc; margin-top: 30px; border-bottom: 1px solid #ccc; padding-bottom: 5px; }
                    table { border-collapse: collapse; width: 100%; margin: 15px 0; }
                    th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
                    th { background-color: #f2f2f2; }
                    tr:nth-child(even) { background-color: #f9f9f9; }
                    .alert { color: white; background-color: #ff6666; padding: 10px; border-radius: 5px; }
                    .warning { color: white; background-color: #ffcc00; padding: 10px; border-radius: 5px; }
                    .info { color: white; background-color: #66ccff; padding: 10px; border-radius: 5px; }
                    .uk-highlight { background-color: #ffffcc; }
                </style>
            </head>
            <body>
                <h1>BGP Security Report for UK Telecom</h1>
                <p>Generated: """ + datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + """</p>
            """)
            
            # Summary section
            html.append("<h2>Executive Summary</h2>")
            
            # Check for suspicious activities
            suspicious_count = results.get('suspicious_update_count', 0)
            
            if suspicious_count > 0:
                html.append(f"""
                <div class="alert">
                    <strong>Alert:</strong> {suspicious_count} suspicious BGP updates detected.
                    This may indicate attempted hijacking or route leaks.
                </div>
                """)
            
            # Check for more-specific announcements
            more_specific_count = results.get('more_specific_prefix_count', 0)
            
            if more_specific_count > 0:
                html.append(f"""
                <div class="warning">
                    <strong>Warning:</strong> {more_specific_count} more-specific prefix announcements detected.
                    These should be investigated as they could be legitimate or hijacking attempts.
                </div>
                """)
            
            # UK telecom activity
            uk_count = 0
            if 'uk_telecom_as_activity' in results:
                uk_count = sum(results['uk_telecom_as_activity'].values())
            
            critical_count = results.get('critical_prefix_update_count', 0)
            
            html.append(f"""
            <div class="info">
                <strong>UK Telecom Activity:</strong> {uk_count} BGP updates involving UK telecom ASNs.
                <br>
                <strong>Critical Infrastructure:</strong> {critical_count} updates affecting critical UK prefixes.
            </div>
            """)
            
            # Suspicious Updates
            if suspicious_count > 0 and 'suspicious_samples' in results:
                html.append("<h2>Suspicious Activities</h2>")
                html.append("<table>")
                html.append("<tr><th>Time</th><th>Prefix</th><th>AS Path</th><th>Reason</th></tr>")
                
                for sample in results['suspicious_samples']:
                    html.append("<tr>")
                    html.append(f"<td>{sample.get('timestamp', '')}</td>")
                    html.append(f"<td>{sample.get('prefix', '')}</td>")
                    html.append(f"<td>{sample.get('as_path', '')}</td>")
                    html.append(f"<td>{sample.get('alert_reasons', '')}</td>")
                    html.append("</tr>")
                
                html.append("</table>")
            
            # Critical Prefix Activity
            if critical_count > 0 and 'critical_prefix_samples' in results:
                html.append("<h2>Critical UK Prefix Activity</h2>")
                html.append("<table>")
                html.append("<tr><th>Time</th><th>Prefix</th><th>Origin AS</th></tr>")
                
                for sample in results['critical_prefix_samples']:
                    html.append("<tr class='uk-highlight'>")
                    html.append(f"<td>{sample.get('timestamp', '')}</td>")
                    html.append(f"<td>{sample.get('prefix', '')}</td>")
                    html.append(f"<td>{sample.get('origin_as', '')}</td>")
                    html.append("</tr>")
                
                html.append("</table>")
            
            # AS Path Analysis
            if 'top_origin_asns' in results:
                html.append("<h2>Top Origin ASNs</h2>")
                html.append("<table>")
                html.append("<tr><th>ASN</th><th>Count</th><th>UK Telecom</th></tr>")
                
                for asn, count in results['top_origin_asns'].items():
                    if asn in UK_TELECOM_ASNS:
                        uk_flag = "Yes"
                        class_attr = "class='uk-highlight'"
                    else:
                        uk_flag = "No"
                        class_attr = ""
                        
                    html.append(f"<tr {class_attr}>")
                    html.append(f"<td>AS{asn}</td>")
                    html.append(f"<td>{count}</td>")
                    html.append(f"<td>{uk_flag}</td>")
                    html.append("</tr>")
                
                html.append("</table>")
            
            # Unusual Path Lengths
            if 'unusual_path_length_count' in results and results['unusual_path_length_count'] > 0:
                html.append("<h2>Unusual AS Path Lengths</h2>")
                html.append(f"<p>{results['unusual_path_length_count']} updates with unusually long AS paths detected.</p>")
                
                if 'unusual_path_samples' in results:
                    html.append("<table>")
                    html.append("<tr><th>Time</th><th>Prefix</th><th>AS Path</th></tr>")
                    
                    for sample in results['unusual_path_samples']:
                        html.append("<tr>")
                        html.append(f"<td>{sample.get('timestamp', '')}</td>")
                        html.append(f"<td>{sample.get('prefix', '')}</td>")
                        html.append(f"<td>{sample.get('as_path', '')}</td>")
                        html.append("</tr>")
                    
                    html.append("</table>")
            
            # More Specific Prefixes
            if 'more_specific_prefix_count' in results and results['more_specific_prefix_count'] > 0:
                html.append("<h2>More-Specific Prefixes</h2>")
                html.append(f"<p>{results['more_specific_prefix_count']} more-specific prefix announcements detected.</p>")
                
                if 'more_specific_samples' in results:
                    html.append("<table>")
                    html.append("<tr><th>Time</th><th>Prefix</th><th>Origin AS</th></tr>")
                    
                    for sample in results['more_specific_samples']:
                        html.append("<tr>")
                        html.append(f"<td>{sample.get('timestamp', '')}</td>")
                        html.append(f"<td>{sample.get('prefix', '')}</td>")
                        html.append(f"<td>{sample.get('origin_as', '')}</td>")
                        html.append("</tr>")
                    
                    html.append("</table>")
            
            # UK Telecom AS Activity
            if 'uk_telecom_as_activity' in results:
                html.append("<h2>UK Telecom AS Activity</h2>")
                html.append("<table>")
                html.append("<tr><th>ASN</th><th>Count</th></tr>")
                
                for asn, count in sorted(results['uk_telecom_as_activity'].items(), key=lambda x: x[1], reverse=True):
                    html.append("<tr>")
                    html.append(f"<td>AS{asn}</td>")
                    html.append(f"<td>{count}</td>")
                    html.append("</tr>")
                
                html.append("</table>")
            
            # Close HTML
            html.append("</body></html>")
            
            report = "\n".join(html)
            
            # Save if requested
            if out_file:
                with open(out_file, 'w') as f:
                    f.write(report)
                self.logger.info(f"Security report saved to {out_file}")
            
            return report
        except Exception as e:
            self.logger.error(f"Error generating security report: {e}")
            return f"<h1>Error generating report: {e}</h1>"
