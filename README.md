Example docker-compose.yml to deploy this service with wgctl (each repository dir needs to be put in a dir with this docker-compose)

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
      WG_DATABASE_URL: postgresql+psycopg2://postgres:password@pg_test:5432/wg
    volumes:
      - wgctl_sock:/run/wgctl:rw
    depends_on:
      - wgctl
      - pg_test

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

  pg_test:
    image: postgres:16
    restart: unless-stopped
    environment:
      POSTGRES_DB: wg
      POSTGRES_USER: postgres
      POSTGRES_PASSWORD: password
    volumes:
      - pg_test_data:/var/lib/postgresql/data

volumes:
  wgctl_sock:
  pg_test_data:
```
