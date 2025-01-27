"""BGP update analysis and visualization utilities."""
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import networkx as nx
import plotly.graph_objects as go
from pathlib import Path
from datetime import datetime
import json

class BGPAnalyzer:
    def __init__(self, data_dir="data"):
        """Initialize BGP analyzer."""
        self.data_dir = Path(data_dir)
        
    def load_data(self, file_path):
        """Load BGP updates from CSV file."""
        return pd.read_csv(file_path)
        
    def analyze_updates(self, df, as_filters=None):
        """
        Analyze BGP updates with detailed statistics.
        
        Args:
            df: DataFrame containing BGP updates
            as_filters: List of AS numbers to filter by
            
        Returns:
            Dictionary containing analysis results
        """
        results = {
            'total_updates': len(df),
            'update_types': df['type'].value_counts().to_dict(),
            'unique_prefixes': df['prefix'].nunique(),
            'unique_as_numbers': set(),
            'as_path_stats': {},
            'filtered_stats': {},
            'time_stats': {}
        }
        
        # AS path analysis
        if 'as_path' in df.columns:
            all_as = ' '.join(df['as_path'].dropna().astype(str))
            as_numbers = [asn for asn in all_as.split() if asn.isdigit()]
            results['unique_as_numbers'] = sorted(set(as_numbers))
            
            # Path length statistics
            df['path_length'] = df['as_path'].fillna('').str.split().str.len()
            results['as_path_stats'] = {
                'min_length': df['path_length'].min(),
                'max_length': df['path_length'].max(),
                'avg_length': df['path_length'].mean(),
                'most_common_length': df['path_length'].mode().iloc[0]
            }
            
        # Filtered update analysis
        if as_filters:
            for asn in as_filters:
                filtered = df[df['as_path'].fillna('').str.contains(str(asn))]
                results['filtered_stats'][f'AS{asn}'] = {
                    'total_updates': len(filtered),
                    'update_types': filtered['type'].value_counts().to_dict(),
                    'unique_prefixes': filtered['prefix'].nunique()
                }
                
        # Time-based analysis
        df['timestamp'] = pd.to_datetime(df['timestamp'])
        results['time_stats'] = {
            'start_time': df['timestamp'].min().strftime('%Y-%m-%d %H:%M:%S'),
            'end_time': df['timestamp'].max().strftime('%Y-%m-%d %H:%M:%S'),
            'duration_seconds': (df['timestamp'].max() - df['timestamp'].min()).total_seconds(),
            'updates_per_second': len(df) / max(1, (df['timestamp'].max() - df['timestamp'].min()).total_seconds())
        }
        
        return results
        
    def plot_update_types(self, df, save_path=None):
        """Plot distribution of update types."""
        plt.figure(figsize=(10, 6))
        sns.countplot(data=df, x='type')
        plt.title('Distribution of BGP Update Types')
        plt.xticks(rotation=45)
        if save_path:
            plt.savefig(save_path)
        return plt.gcf()
        
    def plot_as_path_lengths(self, df, save_path=None):
        """Plot distribution of AS path lengths."""
        plt.figure(figsize=(10, 6))
        df['path_length'] = df['as_path'].fillna('').str.split().str.len()
        sns.histplot(data=df, x='path_length', bins=30)
        plt.title('Distribution of AS Path Lengths')
        plt.xlabel('Path Length')
        plt.ylabel('Count')
        if save_path:
            plt.savefig(save_path)
        return plt.gcf()
        
    def plot_as_relationships(self, df, max_nodes=50, save_path=None):
        """Create an interactive graph of AS relationships."""
        G = nx.Graph()
        
        # Create edges from AS paths
        edge_weights = {}
        for path in df['as_path'].dropna():
            as_list = path.split()
            for i in range(len(as_list) - 1):
                if as_list[i].isdigit() and as_list[i+1].isdigit():
                    edge = tuple(sorted([as_list[i], as_list[i+1]]))
                    edge_weights[edge] = edge_weights.get(edge, 0) + 1
                    
        # Add top N edges by weight
        top_edges = sorted(edge_weights.items(), key=lambda x: x[1], reverse=True)[:max_nodes]
        for (as1, as2), weight in top_edges:
            G.add_edge(as1, as2, weight=weight)
            
        # Create Plotly figure
        pos = nx.spring_layout(G)
        edge_trace = go.Scatter(
            x=[], y=[], line=dict(width=0.5, color='#888'), hoverinfo='none', mode='lines')
        
        for edge in G.edges():
            x0, y0 = pos[edge[0]]
            x1, y1 = pos[edge[1]]
            edge_trace['x'] += (x0, x1, None)
            edge_trace['y'] += (y0, y1, None)
            
        node_trace = go.Scatter(
            x=[], y=[], text=[], mode='markers+text', hoverinfo='text',
            marker=dict(size=10, line_width=2))
            
        for node in G.nodes():
            x, y = pos[node]
            node_trace['x'] += (x,)
            node_trace['y'] += (y,)
            node_trace['text'] += (f'AS{node}',)
            
        fig = go.Figure(data=[edge_trace, node_trace],
                     layout=go.Layout(
                         title='AS Relationship Graph',
                         showlegend=False,
                         hovermode='closest',
                         margin=dict(b=20,l=5,r=5,t=40),
                         xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
                         yaxis=dict(showgrid=False, zeroline=False, showticklabels=False))
                     )
                     
        if save_path:
            fig.write_html(save_path)
        return fig
        
    def export_filtered_updates(self, df, as_filters, output_path):
        """Export updates matching AS filters to a new file."""
        if as_filters:
            filtered = df[df['as_path'].fillna('').apply(
                lambda path: any(str(asn) in str(path).split() for asn in as_filters)
            )]
            filtered.to_csv(output_path, index=False)
            return len(filtered)
        return 0
        
    def generate_report(self, analysis_results, output_path):
        """Generate an HTML report with analysis results."""
        report = f"""
        <html>
        <head>
            <title>BGP Update Analysis Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                .section {{ margin: 20px 0; padding: 10px; border: 1px solid #ddd; }}
                .stat {{ margin: 5px 0; }}
            </style>
        </head>
        <body>
            <h1>BGP Update Analysis Report</h1>
            <div class="section">
                <h2>General Statistics</h2>
                <div class="stat">Total Updates: {analysis_results['total_updates']}</div>
                <div class="stat">Unique Prefixes: {analysis_results['unique_prefixes']}</div>
                <div class="stat">Unique AS Numbers: {len(analysis_results['unique_as_numbers'])}</div>
            </div>
            
            <div class="section">
                <h2>Update Types</h2>
                {self._dict_to_html(analysis_results['update_types'])}
            </div>
            
            <div class="section">
                <h2>AS Path Statistics</h2>
                {self._dict_to_html(analysis_results['as_path_stats'])}
            </div>
            
            <div class="section">
                <h2>Time Statistics</h2>
                {self._dict_to_html(analysis_results['time_stats'])}
            </div>
            
            <div class="section">
                <h2>Filtered Statistics</h2>
                {self._dict_to_html(analysis_results['filtered_stats'])}
            </div>
        </body>
        </html>
        """
        
        with open(output_path, 'w') as f:
            f.write(report)
            
    def _dict_to_html(self, d):
        """Convert dictionary to HTML list."""
        if not d:
            return "<div>No data available</div>"
        html = "<ul>"
        for k, v in d.items():
            if isinstance(v, dict):
                html += f"<li>{k}:<ul>"
                for sk, sv in v.items():
                    html += f"<li>{sk}: {sv}</li>"
                html += "</ul></li>"
            else:
                html += f"<li>{k}: {v}</li>"
        html += "</ul>"
        return html
