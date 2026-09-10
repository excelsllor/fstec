"""Общие хелперы запуска воркеров (подписка + удержание цикла)."""
import asyncio
import logging
from typing import Mapping

from shared.bus import EventBus, Handler

logger = logging.getLogger(__name__)


def register_handlers(bus: EventBus, handlers: Mapping[str, Handler]) -> None:
    for topic, handler in handlers.items():
        bus.subscribe(topic, handler)


async def serve_forever(bus: EventBus):
    """Держит цикл событий после подписки (Kafka-режим). Для memory-режима не нужен."""
    await bus.start()
    logger.info("Worker started on %s bus", type(bus).__name__)
    await asyncio.Event().wait()


def configure_logging(level: int = logging.INFO):
    logging.basicConfig(level=level, format="%(asctime)s %(levelname)s %(name)s: %(message)s")