#!/bin/bash
echo "=== Запуск ФСТЭК Сервис (dev режим) ==="

DIR="$(cd "$(dirname "$0")" && pwd)"

echo "[1/2] Запуск backend (FastAPI)..."
gnome-terminal -- bash -c "cd '$DIR/backend' && python -m uvicorn app.main:app --host 127.0.0.1 --port 8765 --reload; read" &

echo "[2/2] Запуск frontend (Vite)..."
gnome-terminal -- bash -c "cd '$DIR/frontend' && npm run dev; read" &

echo ""
echo "Backend: http://127.0.0.1:8765"
echo "Frontend: http://localhost:5173"
echo ""
