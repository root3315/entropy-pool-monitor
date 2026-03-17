#!/usr/bin/env python3
"""
Configuration management for Entropy Pool Monitor.
"""

import json
import os
from pathlib import Path

DEFAULT_CONFIG = {
    "threshold": 512,
    "interval": 2.0,
    "max_history": 100,
    "log_file": None,
    "alert_command": None
}

CONFIG_SEARCH_PATHS = [
    Path(".entropy_monitor.json"),
    Path.home() / ".config" / "entropy_monitor" / "config.json",
    Path("/etc/entropy_monitor/config.json"),
]


def load_config(config_path=None):
    """
    Load configuration from a JSON file.
    
    If config_path is provided, load from that specific path.
    Otherwise, search through standard configuration locations.
    
    Returns a dictionary with configuration values.
    """
    config = DEFAULT_CONFIG.copy()
    
    if config_path:
        paths_to_check = [Path(config_path)]
    else:
        paths_to_check = CONFIG_SEARCH_PATHS
    
    for path in paths_to_check:
        if path.exists() and path.is_file():
            try:
                with open(path, 'r') as f:
                    file_config = json.load(f)
                    config.update(file_config)
                break
            except (json.JSONDecodeError, IOError):
                continue
    
    return config


def save_config(config, config_path=None):
    """
    Save configuration to a JSON file.
    
    If config_path is not provided, saves to the first available
    location in the search paths (prefers local directory).
    """
    if config_path is None:
        config_path = CONFIG_SEARCH_PATHS[0]
    else:
        config_path = Path(config_path)
    
    config_path.parent.mkdir(parents=True, exist_ok=True)
    
    with open(config_path, 'w') as f:
        json.dump(config, f, indent=2)
    
    return config_path


def generate_sample_config():
    """
    Generate a sample configuration dictionary with all options documented.
    """
    return {
        "threshold": 512,
        "interval": 2.0,
        "max_history": 100,
        "log_file": "/var/log/entropy_monitor.log",
        "alert_command": "notify-send 'Low Entropy' 'Entropy pool is below threshold'"
    }
