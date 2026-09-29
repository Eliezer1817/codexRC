"""
codexRC - Pipeline Orchestrator
Controls the flow between modules (nodes).
"""

from typing import Dict, Any, Optional, Callable
from dataclasses import dataclass, field
from enum import Enum
import time


class NodeStatus(Enum):
    PENDING = "pending"
    RUNNING = "running"
    SUCCESS = "success"
    FAILED = "failed"
    SKIPPED = "skipped"


@dataclass
class NodeResult:
    name: str
    status: NodeStatus
    data: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None
    duration: float = 0.0


class Pipeline:
    """
    Simple sequential pipeline with status tracking.
    Designed so a visual frontend can show each node and its connections.
    """

    def __init__(self):
        self.nodes: Dict[str, Callable] = {}
        self.order: list[str] = []
        self.results: Dict[str, NodeResult] = {}
        self.context: Dict[str, Any] = {}

    def add_node(self, name: str, func: Callable, position: Optional[int] = None):
        self.nodes[name] = func
        if position is not None:
            self.order.insert(position, name)
        else:
            self.order.append(name)

    def run(self, initial_context: Optional[Dict[str, Any]] = None) -> Dict[str, NodeResult]:
        if initial_context:
            self.context.update(initial_context)

        for name in self.order:
            result = NodeResult(name=name, status=NodeStatus.RUNNING)
            self.results[name] = result
            start = time.time()

            try:
                output = self.nodes[name](self.context)
                if isinstance(output, dict):
                    self.context.update(output)
                    result.data = output
                result.status = NodeStatus.SUCCESS
            except Exception as e:
                result.status = NodeStatus.FAILED
                result.error = str(e)

            result.duration = round(time.time() - start, 3)
            self.results[name] = result

            # Stop pipeline on failure (can be changed later)
            if result.status == NodeStatus.FAILED:
                break

        return self.results

    def get_status(self) -> Dict[str, Any]:
        return {
            "nodes": {
                name: {
                    "status": r.status.value,
                    "duration": r.duration,
                    "error": r.error,
                    "data_keys": list(r.data.keys()) if r.data else [],
                }
                for name, r in self.results.items()
            },
            "context_keys": list(self.context.keys()),
        }
