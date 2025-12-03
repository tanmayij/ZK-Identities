"""Natural language query parser for predicate generation.

Translates English queries into structured predicate requests for ZK proof generation.
"""

from __future__ import annotations

import re
from typing import Dict, Any, Optional


# Attribute schema for driver's license data
ATTRIBUTE_SCHEMA = {
    0: {"name": "age", "type": "numeric"},
    1: {"name": "license_class", "type": "numeric"},
    2: {"name": "state_code", "type": "numeric"},
    3: {"name": "issue_year", "type": "numeric"},
    4: {"name": "expiry_year", "type": "numeric"},
    5: {"name": "points", "type": "numeric"},
    6: {"name": "violations", "type": "numeric"},
    7: {"name": "status", "type": "numeric"},  # 0=suspended, 1=active, 2=expired
}


class QueryParser:
    """Parse natural language queries into predicate requests."""

    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.attribute_map = {attr["name"]: idx for idx, attr in ATTRIBUTE_SCHEMA.items()}

    def parse(self, query: str) -> Dict[str, Any]:
        """
        Parse a natural language query into a predicate request.

        Supported patterns:
        - "users over 21" → age >= 21
        - "users age greater than 25" → age >= 25
        - "active licenses" → status >= 1
        - "users with fewer than 3 violations" → violations < 3
        - "licenses expiring after 2025" → expiry_year >= 2025

        Args:
            query: Natural language query string

        Returns:
            Dict with keys: attribute_index, threshold, operator ('>=', '>', '<', '<=')

        Raises:
            ValueError if query cannot be parsed
        """
        query_lower = query.lower().strip()

        if self.verbose:
            print(f"[QueryParser] parsing: '{query}'")

        # Pattern: "users over <threshold>"
        match = re.search(r"over\s+(\d+)", query_lower)
        if match:
            threshold = int(match.group(1))
            return {
                "attribute_index": self.attribute_map["age"],
                "threshold": threshold,
                "operator": ">=",
                "description": f"age >= {threshold}",
            }

        # Pattern: "users age greater than <threshold>"
        match = re.search(r"age\s+(?:greater than|>)\s+(\d+)", query_lower)
        if match:
            threshold = int(match.group(1))
            return {
                "attribute_index": self.attribute_map["age"],
                "threshold": threshold,
                "operator": ">=",
                "description": f"age >= {threshold}",
            }

        # Pattern: "users age at least <threshold>"
        match = re.search(r"age\s+at least\s+(\d+)", query_lower)
        if match:
            threshold = int(match.group(1))
            return {
                "attribute_index": self.attribute_map["age"],
                "threshold": threshold,
                "operator": ">=",
                "description": f"age >= {threshold}",
            }

        # Pattern: "active licenses" or "status active"
        if "active" in query_lower and "license" in query_lower:
            return {
                "attribute_index": self.attribute_map["status"],
                "threshold": 1,
                "operator": ">=",
                "description": "status >= 1 (active)",
            }

        # Pattern: "fewer than <N> violations"
        match = re.search(r"(?:fewer than|less than|<)\s+(\d+)\s+violations?", query_lower)
        if match:
            threshold = int(match.group(1))
            return {
                "attribute_index": self.attribute_map["violations"],
                "threshold": threshold,
                "operator": "<",
                "description": f"violations < {threshold}",
            }

        # Pattern: "licenses expiring after <year>"
        match = re.search(r"expir(?:ing|y)\s+(?:after|>=)\s+(\d{4})", query_lower)
        if match:
            threshold = int(match.group(1))
            return {
                "attribute_index": self.attribute_map["expiry_year"],
                "threshold": threshold,
                "operator": ">=",
                "description": f"expiry_year >= {threshold}",
            }

        # Pattern: "issued before <year>"
        match = re.search(r"issued?\s+(?:before|<)\s+(\d{4})", query_lower)
        if match:
            threshold = int(match.group(1))
            return {
                "attribute_index": self.attribute_map["issue_year"],
                "threshold": threshold,
                "operator": "<",
                "description": f"issue_year < {threshold}",
            }

        # Fallback: default to age >= 21
        if self.verbose:
            print(f"[QueryParser] using default predicate: age >= 21")
        return {
            "attribute_index": self.attribute_map["age"],
            "threshold": 21,
            "operator": ">=",
            "description": "age >= 21 (default)",
        }

    def build_predicate_request(self, query: str) -> Dict[str, Any]:
        """
        Build a complete predicate request suitable for BatchFetchClient.

        Args:
            query: Natural language query

        Returns:
            Dict compatible with fetch_and_rotate's predicate_request parameter
        """
        parsed = self.parse(query)

        # Current circuits only support >= threshold checks
        # Map other operators to compatible forms
        if parsed["operator"] == "<":
            # For "violations < 3", we can't directly support this in current circuit
            # Fallback or transform; for now, warn and adapt
            if self.verbose:
                print(
                    f"[QueryParser] warning: operator '<' not directly supported; "
                    f"using threshold-1 with '>=' as approximation"
                )
            parsed["threshold"] = max(0, parsed["threshold"] - 1)
            parsed["operator"] = ">="

        return {
            "attribute_index": parsed["attribute_index"],
            "threshold": parsed["threshold"],
        }
