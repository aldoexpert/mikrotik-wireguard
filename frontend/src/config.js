// API base URL.
// - Dev  : empty string → same-origin, Vite proxy forwards to localhost:8200
// - Prod : set VITE_API_BASE_URL at build time (frontend/.env or docker-compose.yaml)
//          e.g. https://mywg.example.com/api  or  http://192.168.1.10:8080
const config = {
  apiBaseUrl: import.meta.env.VITE_API_BASE_URL || '',
  appName: 'Mikrotik WireGuard Manager',
};

export default config;
