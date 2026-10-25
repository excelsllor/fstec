# Финальные быстрые замеры — 2026-10-25

Конфигурация: SHA dedupe, reference для hacker, merged analyze+extract для hacker/other,
BERT IoC + regex без LLM-IoC для hacker, LLM-IoC для vulnerability, `plan_reply max_tokens=2500`.

| Сценарий | p50 | p95 | max | Throughput | Ошибки |
|---|---:|---:|---:|---:|---:|
| 3 hacker, 3 параллельно | **50.7 с** | 50.7 с | 52.7 с | 203.6 док/ч | 0 |
| 8 hacker, 8 параллельно | **89.2 с** | 119.8 с | 136.1 с | 211.1 док/ч | 0 |

Vulnerability: 9-152 — 96 с, 9-148 — 117 с.

Качество:
- 9-148: набор IoC совпал со старым, без лишних;
- 9-152: ни один старый IoC не потерян; `red-soft.ru` есть в тексте;
- 9-104/107/113: расхождения только `86.com` у 9-107, он есть в тексте;
- BERT-ложные значения вроде `http2decompressor.de` отфильтрованы по тексту (проверка с границами токена).

Сырые данные: `speed_quick_final_2026-10-25.json`,
`speed_quick_8concurrency_final_2026-10-25.json`.
