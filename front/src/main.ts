import { store } from '@state/store';
import { router, navLink } from '@router';
import { $ } from '@utils';

// Import page components
import { DashboardPage } from '@pages/dashboard';
import { NetworkPage } from '@pages/network';
import { FirewallPage } from '@pages/firewall';
import { NatPage } from '@pages/nat';
import { RoutingPage } from '@pages/routing';
import { ToolsPage } from '@pages/tools';
import { AuditPage } from '@pages/audit';
import { SettingsPage } from '@pages/settings';

// Import component styles
import './styles/main.css';

/**
 * Generate nav group label HTML
 */
function navGroup(label: string): string {
  return `<div class="nav-group-label">${label}</div>`;
}

/**
 * Initialize sidebar navigation
 */
function initSidebar(): void {
  const navEl = $('#nav-items');
  if (!navEl) return;

  navEl.innerHTML = `
    ${navGroup('Overview')}
    ${navLink('/', '▣', 'Dashboard', 'dashboard')}

    ${navGroup('Interfaces')}
    ${navLink('/network', '◯', 'Interfaces', 'network')}

    ${navGroup('Networking')}
    ${navLink('/routing', '↗', 'Routing', 'routing')}
    ${navLink('/nat', '↔', 'NAT', 'nat')}

    ${navGroup('Firewall')}
    ${navLink('/firewall', '▓', 'Firewall', 'firewall')}

    ${navGroup('Tools')}
    ${navLink('/tools', '⚒', 'Diagnostics', 'tools')}

    ${navGroup('Logs')}
    ${navLink('/audit', '◈', 'Audit Log', 'audit')}

    ${navGroup('System')}
    ${navLink('/settings', '⚙', 'Settings', 'settings')}
  `;
}

/**
 * Initialize header with user info and logout
 */
function initHeader(): void {
  const logoutBtn = $('#logout-btn');
  logoutBtn?.addEventListener('click', () => {
    // Clear auth state
    store.setState({ isAuthenticated: false, tokenExpiresAt: null });
    // Redirect to login (implement login page separately)
    window.location.reload();
  });
}

/**
 * Initialize the application
 */
async function init(): Promise<void> {
  // Initialize UI
  initSidebar();
  initHeader();

  // Initialize router with routes
  router.registerAll([
    {
      path: '/',
      name: 'dashboard',
      title: 'Dashboard',
      component: () => {
        const page = new DashboardPage('#app-content');
        page.init();
      },
    },
    {
      path: '/network',
      name: 'network',
      title: 'Network',
      component: () => {
        const page = new NetworkPage('#app-content');
        page.init();
      },
    },
    {
      path: '/firewall',
      name: 'firewall',
      title: 'Firewall',
      component: () => {
        const page = new FirewallPage('#app-content');
        page.init();
      },
    },
    {
      path: '/nat',
      name: 'nat',
      title: 'NAT',
      component: () => {
        const page = new NatPage('#app-content');
        page.init();
      },
    },
    {
      path: '/routing',
      name: 'routing',
      title: 'Routing',
      component: () => {
        const page = new RoutingPage('#app-content');
        page.init();
      },
    },
    {
      path: '/tools',
      name: 'tools',
      title: 'Tools',
      component: () => {
        const page = new ToolsPage('#app-content');
        page.init();
      },
    },
    {
      path: '/audit',
      name: 'audit',
      title: 'Audit Log',
      component: () => {
        const page = new AuditPage('#app-content');
        page.init();
      },
    },
    {
      path: '/settings',
      name: 'settings',
      title: 'Settings',
      component: () => {
        const page = new SettingsPage('#app-content');
        page.init();
      },
    },
  ]);

  router.setDefault('/');
  router.init();
}

// Initialize when DOM is ready
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', init);
} else {
  init();
}

// Expose store for debugging (remove in production)
if (import.meta.env.DEV) {
  (window as Window & { __store?: typeof store }).__store = store;
}
