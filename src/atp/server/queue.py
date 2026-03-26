"""Message queue — async wrapper around the synchronous MessageStore."""

from atp.core.message import ATPMessage
from atp.storage.messages import MessageStore, MessageStatus, StoredMessage


class MessageQueue:
    def __init__(self, message_store: MessageStore):
        self._store = message_store

    async def enqueue(self, message: ATPMessage, status: MessageStatus = MessageStatus.QUEUED) -> int:
        """Enqueue message via store. Return id."""
        return self._store.enqueue(message, status)

    async def get_pending(self, limit: int = 50) -> list[StoredMessage]:
        """Get pending deliveries from store."""
        return self._store.get_pending_deliveries(limit)

    async def get_for_agent(self, agent_id: str, limit: int = 50, after_id: int | None = None) -> list[StoredMessage]:
        """Get delivered messages for an agent."""
        return self._store.get_messages_for_agent(agent_id, limit, after_id)
