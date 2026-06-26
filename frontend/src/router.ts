import { createRouter, createWebHistory } from 'vue-router';
import LandingView from './views/LandingView.vue';
import { useAuth } from './auth/useAuth';

export const router = createRouter({
  history: createWebHistory(),
  routes: [
    { path: '/', redirect: { name: 'console-status' } },
    {
      path: '/welcome',
      name: 'home',
      component: LandingView,
      beforeEnter: () => {
        const { roles } = useAuth();
        return roles.value.includes('ce.cloudengineer') ? { name: 'console-status' } : true;
      },
    },
    { path: '/admin/logs', redirect: { name: 'console-status' } },
    {
      path: '/console',
      component: () => import('./ssumgmt/SsuMgmtLayout.vue'),
      meta: { requiresRole: 'ce.cloudengineer' },
      children: [
        { path: '', name: 'console-status', component: () => import('./views/OverviewView.vue') },
        { path: 'alerts', name: 'console-alerts', component: () => import('./views/AlertsView.vue') },
        { path: 'query', name: 'console-query', component: () => import('./views/QueryView.vue') },
        { path: 'graph', name: 'console-graph', component: () => import('./views/GraphView.vue') },
        { path: 'actors', name: 'console-actors', component: () => import('./views/ActorsView.vue') },
        { path: 'inspect/:id?', name: 'console-inspect', component: () => import('./views/EntityView.vue') },
      ],
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
