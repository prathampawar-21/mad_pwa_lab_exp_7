"""Classification-aware mesh routing."""

from dataclasses import dataclass
from typing import Optional


@dataclass
class Route:
    """A route to a destination node."""
    destination: str
    next_hop: str
    hop_count: int
    classification_level: int
    path: list[str]


class MeshRouter:
    """Routes messages through the mesh respecting classification boundaries."""

    def __init__(self, local_node_id: str) -> None:
        self.local_node_id = local_node_id
        self._routes: dict[str, Route] = {}

    def add_route(
        self,
        destination: str,
        next_hop: str,
        hop_count: int,
        classification_level: int = 0,
        path: Optional[list[str]] = None,
    ) -> Route:
        """Add or update a route."""
        route = Route(
            destination=destination,
            next_hop=next_hop,
            hop_count=hop_count,
            classification_level=classification_level,
            path=path or [self.local_node_id, destination],
        )
        existing = self._routes.get(destination)
        if existing is None or hop_count < existing.hop_count:
            self._routes[destination] = route
        return route

    def find_route(
        self,
        destination: str,
        max_classification: Optional[int] = None,
    ) -> Optional[Route]:
        """Find a route to a destination."""
        route = self._routes.get(destination)
        if route is None:
            return None
        if max_classification is not None and route.classification_level > max_classification:
            return None
        return route

    def remove_route(self, destination: str) -> None:
        """Remove a route."""
        self._routes.pop(destination, None)

    def get_all_routes(self) -> list[Route]:
        """Get all known routes."""
        return list(self._routes.values())
