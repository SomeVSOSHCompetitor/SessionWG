Пример конфигурационного файла docker-compose.yml для развёртывания проекта

```yaml
services:
  api:
    env_file:
      - .env
    image: ghcr.io/somevsoshcompetitor/sessionwg:latest
    user: "10001:10001"
    restart: unless-stopped
    environment:
      WG_WGCTL_SOCKET: /run/wgctl/wgctl.sock
      WG_WGCTL_TOKEN: ${WG_WGCTL_TOKEN}
      WG_DATABASE_URL: postgresql+psycopg2://postgres:password@db:5432/wg
    volumes:
      - wgctl_sock:/run/wgctl:rw
    depends_on:
      wgctl:
        condition: service_started
      db:
        condition: service_healthy
    ports:
      - 8000:8000

  wgctl:
    image: ghcr.io/somevsoshcompetitor/wgctl:latest
    restart: unless-stopped
    network_mode: "host"
    cap_add:
      - NET_ADMIN
    cap_drop:
      - ALL
    security_opt:
      - no-new-privileges:true
    read_only: true
    tmpfs:
      - /tmp
      - /run
    environment:
      WG_INTERFACE: wg0
      WGCTL_SOCKET: /run/wgctl/wgctl.sock
      WGCTL_TOKEN: ${WG_WGCTL_TOKEN}
    volumes:
      - wgctl_sock:/run/wgctl:rw

  db:
    image: postgres:16
    restart: unless-stopped
    environment:
      POSTGRES_DB: wg
      POSTGRES_USER: postgres
      POSTGRES_PASSWORD: password
    volumes:
      - db_data:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U myuser -d mydb"]
      interval: 10s
      timeout: 5s
      retries: 5
      start_period: 30s

volumes:
  wgctl_sock:
  db_data:
```
