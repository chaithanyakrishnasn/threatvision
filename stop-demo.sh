#!/bin/bash
pkill -f "uvicorn app.main:app" 2>/dev/null || true
pkill -f "next dev" 2>/dev/null || true
pkill -f "next-server" 2>/dev/null || true
docker compose -f /home/krishna/threatvision/docker-compose.yml stop 2>/dev/null || true
echo "ThreatVision stopped."
