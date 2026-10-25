# Frontend -- Mikrotik WireGuard Manager

Framework7 PWA (SPA) that consumes the REST API from `../backend`. See the
root [README.md](../README.md) for the full architecture overview.

## Running

```bash
npm install --legacy-peer-deps
npm run dev      # http://localhost:5173
```

Set `VITE_API_BASE_URL` (see `.env.example`) so the frontend knows the
backend's address. Default: `http://localhost:8080`.

## Production Build

```bash
npm run build     # outputs to www/, ready to be served by any static server (see nginx.conf)
```

## Structure

```
src/
  app.f7            app shell: left panel menu + main view
  js/
    app.js          entry point, initializes Framework7
    routes.js       route list + requireAuth/requireAdmin guards
    store.js        session state (token, username, admin), persisted in localStorage
    api.js          fetch() wrapper to the backend, injects the Authorization header, handles 401
  pages/            one .f7 file per page
```

## Adding a New Page

1. Create `src/pages/name.f7` (look at another page for the pattern).
2. Import it and register its path in `src/js/routes.js`.
3. If it should appear in the left panel menu, register a `core.MenuGroup`/
   `core.MenuItem` for it on the backend side (see `backend/README.md` --
   the menu is fetched dynamically from `/auth/session/menu`, not
   hardcoded in `app.f7`).
4. Call the API via `import api from '../js/api.js'` -- `api.get(path)` /
   `api.post(path, body)` both already handle the Authorization header and
   unwrap the `{status, code, message, data, datas}` envelope.
