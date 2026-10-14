"""Shared test helpers. Engine adapters take an httpx.AsyncClient, so tests
inject httpx.MockTransport — no real network, no extra deps."""
import httpx


def make_client(handler) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))
