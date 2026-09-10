"""Событийная шина: Kafka (prod), SQLite (локальный мульти-процесс) или in-memory (тесты).

Интерфейс:
  bus.start() / bus.stop()
  await bus.publish(topic, key, payload: dict)   # payload keyed as str
  bus.subscribe(topic, handler)                   # handler(topic, key, payload)
"""
import asyncio
import json
import logging
import sqlite3
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Awaitable, Callable

from shared.config import BUS_POLL_S, DB_PATH, EVENT_BUS, KAFKA_BOOTSTRAP

logger = logging.getLogger(__name__)

Handler = Callable[[str, str, dict], Awaitable[None]]

TOPICS = [
    "documents.uploaded",
    "document.parsed",
    "document.analyzed",
    "security.assessed",
    "report.ready",
    "reply.generated",
    "audit.events",
    "documents.failed",   # DLQ при исчерпании ретраев внешних сервисов (ТЗ 4.2)
]


class EventBus(ABC):
    @abstractmethod
    async def start(self): ...

    @abstractmethod
    async def stop(self): ...

    @abstractmethod
    async def publish(self, topic: str, key: str, payload: dict) -> None: ...

    @abstractmethod
    def subscribe(self, topic: str, handler: Handler) -> None: ...


class MemoryEventBus(EventBus):
    """Процессная шина: детерминирована (publish ждёт обработчиков). Для dev/CI."""

    def __init__(self):
        self._subscribers: dict[str, list[Handler]] = {}

    async def start(self):
        pass

    async def stop(self):
        pass

    def subscribe(self, topic: str, handler: Handler) -> None:
        subs = self._subscribers.setdefault(topic, [])
        if handler not in subs:
            subs.append(handler)

    async def publish(self, topic: str, key: str, payload: dict) -> None:
        for handler in list(self._subscribers.get(topic, [])):
            try:
                await handler(topic, key, payload)
            except Exception:
                logger.exception("Memory bus handler failed on %s key=%s", topic, key)


class SqliteEventBus(EventBus):
    """Межпроцессная шина на SQLite (локальный запуск без Kafka/Redis).

    Сообщения пишутся в bus_message; каждый топик имеет курсор (bus_cursor),
    который подписчик продвигает после обработки. Курсор создаётся при первой
    подписке как INSERT OR IGNORE на максимальный id → рестарт воркера не
    переигрывает уже обработанное, а сообщения, пришедшие пока воркер был
    остановлен, доставляются после его перезапуска.
    """

    _SCHEMA = [
        """CREATE TABLE IF NOT EXISTS bus_message (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            topic TEXT NOT NULL,
            msg_key TEXT,
            payload TEXT NOT NULL,
            created_at TEXT NOT NULL)""",
        """CREATE TABLE IF NOT EXISTS bus_cursor (
            topic TEXT PRIMARY KEY,
            last_id INTEGER NOT NULL DEFAULT 0)""",
    ]

    def __init__(self, db_path: str | Path | None = None, poll_s: float | None = None):
        self._db_path = str(db_path or DB_PATH)
        self._poll_s = poll_s if poll_s is not None else BUS_POLL_S
        self._subscribers: dict[str, list[Handler]] = {}
        self._tasks: list[asyncio.Task] = []
        self._conn: sqlite3.Connection | None = None
        self._loop: asyncio.AbstractEventLoop | None = None

    def _ensure_conn(self) -> sqlite3.Connection:
        if self._conn is None:
            conn = sqlite3.connect(self._db_path, check_same_thread=False)
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA busy_timeout=5000")
            for stmt in self._SCHEMA:
                conn.execute(stmt)
            conn.commit()
            self._conn = conn
        return self._conn

    def _init_cursor(self, topic: str) -> None:
        conn = self._ensure_conn()
        row = conn.execute("SELECT MAX(id) FROM bus_message WHERE topic=?", (topic,)).fetchone()
        max_id = row[0] if row and row[0] is not None else 0
        conn.execute("INSERT OR IGNORE INTO bus_cursor (topic, last_id) VALUES (?, ?)",
                     (topic, max_id))
        conn.commit()

    async def start(self):
        self._loop = asyncio.get_event_loop()
        self._ensure_conn()
        for topic in list(self._subscribers):
            self._tasks.append(self._loop.create_task(self._poll(topic)))

    async def stop(self):
        for task in self._tasks:
            task.cancel()
        for task in self._tasks:
            try:
                await task
            except (asyncio.CancelledError, Exception):
                pass
        self._tasks = []
        if self._conn is not None:
            self._conn.close()
            self._conn = None
        self._loop = None

    def subscribe(self, topic: str, handler: Handler) -> None:
        subs = self._subscribers.setdefault(topic, [])
        if handler not in subs:
            subs.append(handler)
        self._init_cursor(topic)

    async def publish(self, topic: str, key: str, payload: dict) -> None:
        if self._conn is None:
            await self.start()
        encoded = json.dumps(payload, ensure_ascii=False, default=str)
        now = datetime_now_iso()
        await self._loop.run_in_executor(None, self._insert, topic, key, encoded, now)

    def _insert(self, topic: str, key: str, encoded: str, now: str) -> None:
        conn = self._ensure_conn()
        conn.execute(
            "INSERT INTO bus_message (topic, msg_key, payload, created_at) VALUES (?, ?, ?, ?)",
            (topic, key, encoded, now))
        conn.commit()

    async def _poll(self, topic: str, batch: int = 100) -> None:
        while True:
            try:
                await self._deliver(topic, batch)
            except Exception:
                logger.exception("sqlite bus poll failed topic=%s", topic)
            await asyncio.sleep(self._poll_s)

    async def _deliver(self, topic: str, batch: int) -> None:
        def _fetch():
            conn = self._ensure_conn()
            cur = conn.execute("SELECT last_id FROM bus_cursor WHERE topic=?", (topic,)).fetchone()
            last = cur[0] if cur else 0
            rows = conn.execute(
                "SELECT id, msg_key, payload FROM bus_message WHERE topic=? AND id>? "
                "ORDER BY id LIMIT ?", (topic, last, batch)).fetchall()
            return last, [(r[0], r[1], r[2]) for r in rows]

        def _advance(max_id: int) -> None:
            conn = self._ensure_conn()
            conn.execute("INSERT INTO bus_cursor (topic, last_id) VALUES (?, ?) "
                         "ON CONFLICT(topic) DO UPDATE SET last_id = excluded.last_id",
                         (topic, max_id))
            conn.commit()

        last, rows = await self._loop.run_in_executor(None, _fetch)
        if not rows:
            return
        max_id = last
        for rid, key, payload in rows:
            max_id = max(max_id, rid)
            try:
                data = json.loads(payload) if payload else {}
            except Exception:
                data = {}
            for handler in list(self._subscribers.get(topic, [])):
                try:
                    await handler(topic, key or "", data)
                except Exception:
                    logger.exception("sqlite bus handler failed on %s key=%s", topic, key)
        await self._loop.run_in_executor(None, _advance, max_id)


def datetime_now_iso() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat()


class KafkaEventBus(EventBus):
    """Kafka-шина через aiokafka. Сообщения сериализуются в JSON."""

    def __init__(self, bootstrap: str = KAFKA_BOOTSTRAP):
        self._bootstrap = bootstrap
        self._producer = None
        self._consumers: list[asyncio.Task] = []
        self._started = False

    async def start(self):
        from aiokafka import AIOKafkaProducer
        self._producer = AIOKafkaProducer(
            bootstrap_servers=self._bootstrap,
            value_serializer=lambda v: json.dumps(v, ensure_ascii=False, default=str).encode("utf-8"),
        )
        await self._producer.start()
        self._started = True

    async def stop(self):
        for task in self._consumers:
            task.cancel()
        for task in self._consumers:
            try:
                await task
            except (asyncio.CancelledError, Exception):
                pass
        self._consumers = []
        if self._producer:
            await self._producer.stop()
            self._producer = None

    def subscribe(self, topic: str, handler: Handler) -> None:
        loop = asyncio.get_event_loop()
        task = loop.create_task(self._run_consumer(topic, handler))
        self._consumers.append(task)

    async def _run_consumer(self, topic: str, handler: Handler):
        from aiokafka import AIOKafkaConsumer
        consumer = AIOKafkaConsumer(
            topic,
            bootstrap_servers=self._bootstrap,
            auto_offset_reset="earliest",
            enable_auto_commit=True,
            group_id=f"fstec-{topic}-consumer",
            value_deserializer=lambda b: json.loads(b.decode("utf-8")),
        )
        await consumer.start()
        try:
            async for msg in consumer:
                try:
                    key = msg.key.decode("utf-8") if isinstance(msg.key, bytes) else str(msg.key)
                    await handler(topic, key, msg.value or {})
                except Exception:
                    logger.exception("Kafka handler failed topic=%s", topic)
        finally:
            await consumer.stop()

    async def publish(self, topic: str, key: str, payload: dict) -> None:
        if not self._started:
            await self.start()
        await self._producer.send(topic, key=key.encode("utf-8"), value=payload)
        await self._producer.flush()


_bus: EventBus | None = None


def get_event_bus() -> EventBus:
    global _bus
    if _bus is None:
        mode = EVENT_BUS
        if mode == "kafka":
            _bus = KafkaEventBus()
        elif mode == "sqlite":
            _bus = SqliteEventBus()
        else:
            _bus = MemoryEventBus()
    return _bus


async def publish(topic: str, key: str, payload: dict) -> None:
    await get_event_bus().publish(topic, key, payload)