# RepoShield — Run Doc

Vite + React frontend served by an Express backend (`server.ts`) in a single process.

## Reproduce artifacts (fresh checkout)

1. Install dependencies with npm:
   ```
   npm install
   ```
2. Copy env files from the main checkout (`C:\Users\Neetu Jain\Desktop\RepoShield`):
   - `.env` — contains `GROQ_API_KEY` and `GITHUB_TOKEN` (never commit or paste values).
   - `.env.example` is the documented template.
3. No build step is required for dev (`npm run dev` runs `tsx server.ts` directly, which serves both the API and the Vite app on the same port).

## Run the server

```
npm run dev
```

- Default port: **3000** (hardcoded in `server.ts`). If busy, free it or adapt the port in `server.ts`.
- Health check: `curl http://127.0.0.1:3000/api/health` → `{"status":"ok",...}`
- Root `http://127.0.0.1:3000/` serves the React app (HTTP 200).

### Detached start (Windows, Freebuff preview)

```powershell
powershell -NoProfile -Command "(Start-Process -FilePath 'npm.cmd' -ArgumentList 'run','dev' -RedirectStandardOutput '<log>' -RedirectStandardError '<log>.err' -WindowStyle Hidden -PassThru).Id"
```

Note: `Start-Process` returns the `npm.cmd` shim's pid, which may exit before printing; the real listener is a child `node.exe` process — find it with
`netstat -ano | findstr ":3000.*LISTENING"` and verify with `Get-Process -Id <pid>`.

## Useful checks

- `npm run lint` — TypeScript typecheck (tsc --noEmit)
- `npm run test:unit` — unit suite (25 tests)
- `npm run build` — production build (Vite client + esbuild server bundle to `dist/server.cjs`)
- `npm start` — run the production bundle
