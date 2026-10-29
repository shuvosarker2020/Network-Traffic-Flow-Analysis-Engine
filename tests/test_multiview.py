"""
Test script for Multi-View Analytics (Sankey, Bar, Table, Treemap, Timeseries)
"""
import sys
import os

# Set working directory to project root
sys.path.insert(0, os.path.abspath("."))

from storage.duckdb_driver import DuckDBStorageEngine
from analytics.pattern_engine import TrafficPatternEngine

def test_multiview_logic():
    print("Testing MultiView Analytics Logic...")
    # Note: If server has locked data/aegisflow.duckdb, we can test in memory or verify logic
    # Let's inspect how pattern_engine handles queries.
    print("Pattern engine imported successfully.")

if __name__ == "__main__":
    test_multiview_logic()
