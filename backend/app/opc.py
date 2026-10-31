# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""OPC UA client — the backend's authorized control path to the plant.

Reads live process state from the gateway at a few Hz for the animation, and
issues approved control writes (the recovery actions) over the same legitimate
OPC UA path the HMI would use. Node ids mirror docs/TAGMAP.md.
"""

from __future__ import annotations

from asyncua import Client, ua

from . import config, profile


class OpcClient:
    """Thin async wrapper holding one persistent connection. The tag->NodeId map
    and namespace come from the deployment profile (profile.opcua_nodes()), so the
    control path is scenario-agnostic — no hardcoded device tags live here."""

    def __init__(self, endpoint: str | None = None):
        self.endpoint = endpoint or config.OPC_ENDPOINT
        self._client: Client | None = None
        self._idx: int | None = None
        self._ns_uri: str | None = None
        self._nodes: dict[str, str] = {}

    async def connect(self) -> None:
        m = profile.opcua_nodes()
        self._ns_uri = m["namespace_uri"]
        self._nodes = m["nodes"]
        self._client = Client(self.endpoint)
        await self._client.connect()
        self._idx = await self._client.get_namespace_index(self._ns_uri)

    async def disconnect(self) -> None:
        if self._client is not None:
            try:
                await self._client.disconnect()
            finally:
                self._client = None

    def _node(self, tag: str):
        return self._client.get_node(ua.NodeId(self._nodes[tag], self._idx))

    async def read_state(self) -> dict:
        state = {}
        for tag in self._nodes:
            state[tag] = await self._node(tag).read_value()
        return state

    async def write_real(self, tag: str, value: float) -> None:
        await self._node(tag).write_value(ua.Variant(float(value), ua.VariantType.Float))

    async def write_bool(self, tag: str, value: bool) -> None:
        await self._node(tag).write_value(ua.Variant(bool(value), ua.VariantType.Boolean))
