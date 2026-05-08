# ═══════════════════════════════════════════════════════════════════════════
# Dockerfile  —  CfA Software Health Monitor
# ═══════════════════════════════════════════════════════════════════════════
#
# WHAT IS A DOCKERFILE?
# A Dockerfile is a recipe — a text file with step-by-step instructions
# for building a Docker IMAGE.
#
# WHAT IS A DOCKER IMAGE?
# An image is a snapshot of a complete environment: operating system,
# installed software, files, and configuration. Think of it like a
# template or blueprint that never changes.
#
# WHAT IS A DOCKER CONTAINER?
# A container is a RUNNING instance of an image.
# Image = recipe/blueprint (static)
# Container = the actual running thing (dynamic)
#
# You can run 10 containers from the same image — all identical.
#
# WHY DOCKER?
# "It works on my machine" → Docker solves this.
# Container runs identically on your laptop, test server, production server.
# Every dependency is packaged inside the container.
# Isolation: one container can't affect another.
# This is what the job description means by "containerization platforms"
# ═══════════════════════════════════════════════════════════════════════════


# ── INSTRUCTION 1: FROM ────────────────────────────────────────────────────────
FROM python:3.11-slim
# FROM sets the BASE IMAGE — the starting point for our container.
#
# python:3.11-slim breaks down as:
#   python      = the official Python image from Docker Hub (hub.docker.com)
#   3.11        = use Python version 3.11 specifically
#                 (pinning versions prevents surprises when 3.12 releases)
#   -slim       = a minimal Debian Linux base with just Python installed
#                 Regular "python:3.11" is ~900MB, slim is ~125MB
#                 Smaller images = faster to download, less attack surface
#
# WHAT IS DOCKER HUB?
# Docker Hub is a registry (library) of pre-built images.
# Like PyPI for Python packages, but for entire environments.
# Every image comes FROM a base image — it's a chain of layers.


# ── INSTRUCTION 2: LABEL ──────────────────────────────────────────────────────
LABEL maintainer="Anjali Pandiri <anjali.pandiri@outlook.com>"
LABEL description="CfA Software Health Monitor — IT SysAdmin Demo Project"
LABEL version="1.0.0"
# LABEL adds metadata to the image (like comments, but machine-readable).
# These don't affect behavior — they help humans and tools identify images.
# docker inspect <image> shows these labels.


# ── INSTRUCTION 3: ENV ────────────────────────────────────────────────────────
ENV PYTHONDONTWRITEBYTECODE=1
# PYTHONDONTWRITEBYTECODE=1 prevents Python from writing .pyc (compiled) files
# .pyc files are bytecode caches — useful locally but waste space in containers

ENV PYTHONUNBUFFERED=1
# PYTHONUNBUFFERED=1 forces Python to output stdout/stderr immediately
# Without this, print() and logging output can be delayed inside containers
# With this, you see logs in REAL TIME as the app runs

ENV FLASK_APP=app.py
# FLASK_APP tells Flask which file is the main application
# Used by "flask run" command internally


# ── INSTRUCTION 4: WORKDIR ────────────────────────────────────────────────────
WORKDIR /app
# WORKDIR sets the working directory INSIDE the container.
# All subsequent commands run FROM /app.
# If /app doesn't exist, Docker creates it automatically.
#
# This is like doing: cd /app
# But it also affects COPY, ADD, RUN, CMD, ENTRYPOINT instructions.
#
# Convention: /app is the standard working directory for web applications.


# ── INSTRUCTION 5: COPY requirements.txt ─────────────────────────────────────
COPY requirements.txt .
# COPY <source_on_host> <destination_in_container>
# Here: copy requirements.txt from our project folder into /app/
# The "." means "current directory" = /app (because of WORKDIR)
#
# WHY COPY requirements.txt SEPARATELY?
# Docker CACHES each instruction as a layer.
# If requirements.txt hasn't changed, Docker reuses the cached pip install.
# If we copied all files first, EVERY code change would re-run pip install.
# This is a critical Docker optimization pattern called LAYER CACHING.


# ── INSTRUCTION 6: RUN pip install ────────────────────────────────────────────
RUN pip install --no-cache-dir -r requirements.txt
# RUN executes a shell command during image BUILD (not when container starts).
# Used for: installing packages, creating directories, running setup scripts.
#
# pip install: Python's package installer
# --no-cache-dir: don't save downloaded packages to disk
#                 reduces image size by not keeping installation cache
# -r requirements.txt: install all packages listed in the file
#
# Each RUN instruction creates a new IMAGE LAYER.
# Layers are cached and reused between builds.


# ── INSTRUCTION 7: COPY application code ──────────────────────────────────────
COPY . .
# Copy ALL remaining files from our project directory into /app/
# First "." = source (the directory containing this Dockerfile on host)
# Second "." = destination (the WORKDIR = /app in container)
#
# WHY AFTER pip install?
# See Layer Caching explanation above.
# Code changes frequently, dependencies change rarely.
# By installing dependencies before copying code, we get faster rebuilds.


# ── INSTRUCTION 8: RUN — Create directories ───────────────────────────────────
RUN mkdir -p /app/logs /app/db
# Create the directories our app needs.
# -p means "create parent directories too, don't fail if already exists"
#
# /app/logs = where our log files go
# /app/db   = where SQLite database file lives


# ── INSTRUCTION 9: EXPOSE ─────────────────────────────────────────────────────
EXPOSE 5000
# EXPOSE documents that this container listens on port 5000.
# This is DOCUMENTATION ONLY — it doesn't actually open the port.
#
# The actual port mapping happens when you RUN the container:
# docker run -p 5000:5000 ...
# That says: "map host port 5000 TO container port 5000"
#
# WHAT IS A PORT?
# Ports are like apartment numbers — the IP address gets you to the building
# (computer), but the port gets you to the right apartment (service).
# HTTP=80, HTTPS=443, SSH=22, Postgres=5432, Flask=5000


# ── INSTRUCTION 10: HEALTHCHECK ───────────────────────────────────────────────
HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:5000/api/health')"
# HEALTHCHECK tells Docker HOW to verify the container is working.
# Docker orchestration (Kubernetes, Docker Swarm) uses this to manage services.
#
# --interval=30s    = check every 30 seconds
# --timeout=10s     = consider failed if no response within 10 seconds
# --start-period=15s= give the app 15 seconds to start before checking
# --retries=3       = mark "unhealthy" only after 3 consecutive failures
#
# CMD python -c "..." = run this Python one-liner as the health check
# urllib.request.urlopen = make an HTTP GET request to our /api/health endpoint
# If the request succeeds → healthy. If exception → unhealthy.


# ── INSTRUCTION 11: CMD ───────────────────────────────────────────────────────
CMD ["python", "app.py"]
# CMD defines the DEFAULT command to run when the container STARTS.
# (RUN runs during BUILD; CMD runs when you start the container)
#
# ["python", "app.py"] is called "exec form" — preferred because:
# 1. Python process becomes PID 1 directly (gets OS signals like SIGTERM)
# 2. No shell overhead or quoting issues
#
# Alternative shell form: CMD python app.py
# Exec form is better practice for production containers.
#
# You can OVERRIDE CMD when running:
# docker run myapp python -m pytest  (runs tests instead of app)
