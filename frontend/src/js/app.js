import Framework7 from 'framework7/bundle';
import 'framework7/css/bundle';
import 'framework7-icons/css/framework7-icons.css';
import 'material-icons/iconfont/material-icons.css';

import '../css/app.css';

import routes from './routes.js';
import store from './store.js';
import App from '../app.f7';

const app = new Framework7({
  name: 'Mikrotik WireGuard Manager',
  theme: 'auto',
  colors: { primary: '#2563eb' },

  el: '#app',
  component: App,
  store,
  routes,

  serviceWorker: process.env.NODE_ENV === 'production' ? { path: '/service-worker.js' } : {},

  on: {
    init() {
      this.views.create('.view-main', {
        url: '/',
        browserHistory: true,
        browserHistoryRoot: '',
      });
    },
  },
});

window.app = app;
