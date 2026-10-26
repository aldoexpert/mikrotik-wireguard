import store from './store.js';

import LoginPage from '../pages/login.f7';
import ClientsPage from '../pages/clients.f7';
import ClientFormPage from '../pages/client-form.f7';
import InterfacesPage from '../pages/interfaces.f7';
import InterfaceFormPage from '../pages/interface-form.f7';
import MikrotikPage from '../pages/mikrotik.f7';
import UsersPage from '../pages/users.f7';
import UserFormPage from '../pages/user-form.f7';
import ProfilePage from '../pages/profile.f7';
import StatusPage from '../pages/status.f7';
import WolPage from '../pages/wol.f7';
import WolFormPage from '../pages/wol-form.f7';
import AboutPage from '../pages/about.f7';
import NotFoundPage from '../pages/404.f7';

// requireAuth redirects to /login/ when there is no session token.
// requireAdmin additionally requires the admin flag.
function requireAuth({ resolve, reject }) {
  if (store.getters.isLoggedIn.value) {
    resolve();
  } else {
    reject();
    this.navigate('/login/', { reloadAll: true });
  }
}

function requireAdmin({ resolve, reject, router }) {
  if (store.getters.isLoggedIn.value && store.getters.isAdmin.value) {
    resolve();
  } else if (!store.getters.isLoggedIn.value) {
    reject();
    router.navigate('/login/', { reloadAll: true });
  } else {
    reject();
    router.navigate('/', { reloadAll: true });
  }
}

const routes = [
  { path: '/login/', component: LoginPage },
  { path: '/', component: ClientsPage, beforeEnter: requireAuth },
  { path: '/clients/new/', component: ClientFormPage, beforeEnter: requireAuth },
  { path: '/clients/:id/edit/', component: ClientFormPage, beforeEnter: requireAuth },
  { path: '/status/', component: StatusPage, beforeEnter: requireAuth },
  { path: '/interfaces/', component: InterfacesPage, beforeEnter: requireAdmin },
  { path: '/interfaces/new/', component: InterfaceFormPage, beforeEnter: requireAdmin },
  { path: '/interfaces/:id/edit/', component: InterfaceFormPage, beforeEnter: requireAdmin },
  { path: '/mikrotik/', component: MikrotikPage, beforeEnter: requireAdmin },
  { path: '/users/', component: UsersPage, beforeEnter: requireAdmin },
  { path: '/users/new/', component: UserFormPage, beforeEnter: requireAdmin },
  { path: '/users/:username/edit/', component: UserFormPage, beforeEnter: requireAdmin },
  { path: '/profile/', component: ProfilePage, beforeEnter: requireAuth },
  { path: '/wol/', component: WolPage, beforeEnter: requireAuth },
  { path: '/wol/new/', component: WolFormPage, beforeEnter: requireAuth },
  { path: '/about/', component: AboutPage },
  { path: '(.*)', component: NotFoundPage },
];

export default routes;
