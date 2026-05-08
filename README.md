# CfA Software Health Monitor
## IT Specialist Portfolio Project — Smithsonian Astrophysical Observatory

### Quick Start (3 steps)
```bash
# 1. Start the containers
docker-compose up -d

# 2. Wait ~5 seconds for startup, then run the admin demo
python scripts/admin.py

# 3. Open browser: http://localhost:5000
```

### Project Structure
```
sysadmin_project/
├── app/
│   └── app.py              # Flask application (enterprise software monitor)
├── scripts/
│   └── admin.py            # Python automation script (SysAdmin workflows)
├── data/
│   ├── db/                 # SQLite database (auto-created)
│   └── logs/               # Application logs (auto-created)
├── Dockerfile              # Container recipe
├── docker-compose.yml      # Multi-service orchestration
└── requirements.txt        # Python dependencies
```

### Skills Demonstrated
| Job Requirement | How Demonstrated |
|---|---|
| Software installation/config | Flask app configured via environment variables |
| Python scripting/automation | admin.py automates health checks, patching, reporting |
| Docker containerization | Dockerfile + docker-compose.yml |
| Database management | SQLite with proper schema, migrations, CRUD |
| REST API / authentication | Token-based auth with SHA-256 hashed storage |
| Security controls | RBAC simulation, audit logging, vulnerability scan |
| ITIL / change management | Audit trail for every administrative action |
| Documentation | Exhaustively commented code + README |
| Monitoring | Real-time CPU/memory/disk metrics via psutil |
