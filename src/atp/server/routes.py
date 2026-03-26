"""HTTP route handlers for the ATP server."""

import json
import sqlite3
import time
import logging

from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from atp.core.message import ATPMessage
from atp.core.identity import AgentID
from atp.core.errors import MessageFormatError
from atp.storage.messages import MessageStatus

logger = logging.getLogger("atp.server")


async def handle_message(request: Request) -> JSONResponse:
    """POST /.well-known/atp/v1/message

    Validates, verifies, and enqueues an incoming ATP message.
    """
    server = request.app.state.server

    try:
        # 1. Read body, check size
        body = await request.body()
        if len(body) > server.config.max_message_size:
            return JSONResponse(
                status_code=400,
                content={"error": "Message too large", "max_size": server.config.max_message_size},
            )

        # 2. Parse ATPMessage
        try:
            body_str = body.decode("utf-8")
            message = ATPMessage.from_json(body_str)
        except (MessageFormatError, json.JSONDecodeError, UnicodeDecodeError) as exc:
            return JSONResponse(
                status_code=400,
                content={"error": "Invalid message format", "details": str(exc)},
            )

        # 3. Source IP
        source_ip = request.client.host if request.client else "0.0.0.0"

        # 4. Sender domain
        try:
            sender_domain = AgentID.parse(message.from_id).domain
        except MessageFormatError as exc:
            return JSONResponse(
                status_code=400,
                content={"error": "Invalid sender ID", "details": str(exc)},
            )

        # 5. ATS verify
        ats_result = await server.ats_verifier.verify(sender_domain, source_ip)
        server.metrics.record_ats(ats_result.status)
        if ats_result.status == "FAIL":
            return JSONResponse(
                status_code=403,
                content={
                    "error": "ATS validation failed",
                    "error_code": ats_result.error_code,
                    "matched_directive": ats_result.matched_directive,
                },
            )

        # 6. ATK verify
        atk_result = await server.atk_verifier.verify(message)
        server.metrics.record_atk(atk_result.passed)
        if not atk_result.passed:
            return JSONResponse(
                status_code=403,
                content={
                    "error": "ATK verification failed",
                    "error_code": atk_result.error_code,
                    "error_message": atk_result.error_message,
                },
            )

        # 7. Replay check
        if not server.replay_guard.check(message.nonce, message.timestamp):
            server.metrics.record_replay_blocked()
            return JSONResponse(
                status_code=400,
                content={"error": "Replay detected"},
            )

        # 8. Route decision
        try:
            to_domain = AgentID.parse(message.to_id).domain
        except MessageFormatError as exc:
            return JSONResponse(
                status_code=400,
                content={"error": "Invalid recipient ID", "details": str(exc)},
            )

        server.metrics.record_message_received()

        if to_domain == server.config.domain:
            # Local delivery
            await server.queue.enqueue(message, MessageStatus.DELIVERED)
            server.metrics.record_local_delivery()
        else:
            # Remote: queue for delivery manager
            await server.queue.enqueue(message, MessageStatus.QUEUED)
            server.metrics.record_forwarded()

        # 9. Accepted
        return JSONResponse(
            status_code=202,
            content={"status": "accepted", "nonce": message.nonce, "timestamp": int(time.time())},
        )

    except Exception as exc:
        logger.error(f"Unexpected error handling message: {exc}", exc_info=True)
        return JSONResponse(
            status_code=500,
            content={"error": "Internal server error"},
        )


async def handle_recv(request: Request) -> JSONResponse:
    """GET /.well-known/atp/v1/messages

    Retrieve delivered messages for an agent.
    """
    server = request.app.state.server

    agent_id = request.query_params.get("agent_id")
    if not agent_id:
        return JSONResponse(
            status_code=400,
            content={"error": "Missing required parameter: agent_id"},
        )

    limit_str = request.query_params.get("limit", "50")
    try:
        limit = int(limit_str)
    except ValueError:
        limit = 50

    after_id_str = request.query_params.get("after_id")
    after_id = None
    if after_id_str is not None:
        try:
            after_id = int(after_id_str)
        except ValueError:
            pass

    stored_messages = await server.queue.get_for_agent(agent_id, limit, after_id)

    messages = []
    for sm in stored_messages:
        try:
            msg = ATPMessage.from_json(sm.message_json)
            messages.append(msg.to_dict())
        except Exception:
            pass

    return JSONResponse(content={"messages": messages, "count": len(messages)})


async def handle_capabilities(request: Request) -> JSONResponse:
    """GET /.well-known/atp/v1/capabilities"""
    server = request.app.state.server
    return JSONResponse({
        "version": "1.0",
        "capabilities": ["message"],
        "protocols": ["atp/1"],
        "max_payload_size": server.config.max_message_size,
    })


async def handle_health(request: Request) -> JSONResponse:
    """GET /.well-known/atp/v1/health"""
    server = request.app.state.server
    return JSONResponse({
        "status": "healthy",
        "domain": server.config.domain,
        "version": "1.0.0a1",
    })


async def handle_stats(request: Request) -> JSONResponse:
    """GET /.well-known/atp/v1/stats
    Returns server metrics + queue status from DB.
    """
    server = request.app.state.server
    metrics = server.metrics.to_dict()

    # Add queue counts from database
    store = server.queue._store
    # Query counts by status
    conn = sqlite3.connect(str(store._db_path))
    cursor = conn.execute(
        "SELECT status, COUNT(*) FROM messages GROUP BY status"
    )
    queue_counts = dict(cursor.fetchall())
    conn.close()

    metrics["queue"] = {
        "queued": queue_counts.get("queued", 0),
        "delivering": queue_counts.get("delivering", 0),
        "delivered": queue_counts.get("delivered", 0),
        "failed": queue_counts.get("failed", 0),
        "bounced": queue_counts.get("bounced", 0),
    }

    # Add agent list
    conn = sqlite3.connect(str(store._db_path))
    cursor = conn.execute(
        "SELECT DISTINCT to_id FROM messages WHERE status = 'delivered'"
    )
    metrics["agents"] = [row[0] for row in cursor.fetchall()]
    conn.close()

    metrics["domain"] = server.config.domain

    return JSONResponse(metrics)


async def handle_inspect(request: Request) -> JSONResponse:
    """GET /.well-known/atp/v1/inspect?nonce=<nonce>
    Returns detailed status of a specific message.
    """
    server = request.app.state.server
    nonce = request.query_params.get("nonce")
    if not nonce:
        return JSONResponse({"error": "Missing 'nonce' parameter"}, status_code=400)

    stored = server.queue._store.get_by_nonce(nonce)
    if not stored:
        return JSONResponse({"error": f"Message {nonce} not found"}, status_code=404)

    result = {
        "nonce": stored.nonce,
        "from": stored.from_id,
        "to": stored.to_id,
        "status": stored.status.value,
        "created_at": stored.created_at,
        "updated_at": stored.updated_at,
        "retry_count": stored.retry_count,
        "next_retry_at": stored.next_retry_at,
        "error": stored.error,
    }
    return JSONResponse(result)


def get_routes() -> list[Route]:
    return [
        Route("/.well-known/atp/v1/message", handle_message, methods=["POST"]),
        Route("/.well-known/atp/v1/messages", handle_recv, methods=["GET"]),
        Route("/.well-known/atp/v1/capabilities", handle_capabilities, methods=["GET"]),
        Route("/.well-known/atp/v1/health", handle_health, methods=["GET"]),
        Route("/.well-known/atp/v1/stats", handle_stats, methods=["GET"]),
        Route("/.well-known/atp/v1/inspect", handle_inspect, methods=["GET"]),
    ]
