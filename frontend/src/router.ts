import { createRouter, createWebHistory } from 'vue-router';
import LandingView from './views/LandingView.vue';
import { useAuth } from './auth/useAuth';

export const router = createRouter({
  history: createWebHistory(),
  routes: [
    { path: '/', name: 'home', component: LandingView },
    {
      path: '/admin/logs',
      name: 'audit-logs',
      component: () => import('./views/AuditLogsView.vue'),
      meta: { requiresRole: 'ce.cloudengineer' },
    },
    { path: '/:pathMatch(.*)*', redirect: '/' },
  ],
});

router.beforeEach((to) => {
  const required = to.meta.requiresRole as string | undefined;
  if (!required) return true;
  const { roles, isAuthenticated } = useAuth();
  if (!isAuthenticated.value) return { name: 'home' };
  if (!roles.value.includes(required)) return { name: 'home' };
  return true;
});
