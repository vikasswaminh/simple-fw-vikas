import { store } from '@state/store';

/**
 * Route definition
 */
export interface Route {
  path: string;
  name: string;
  component: () => Promise<void> | void;
  title: string;
}

/**
 * Simple router for SPA navigation
 */
class Router {
  private routes: Map<string, Route>;
  private currentRoute: Route | null;
  private defaultRoute: string;

  constructor() {
    this.routes = new Map();
    this.currentRoute = null;
    this.defaultRoute = '/';

    // Handle browser back/forward
    window.addEventListener('popstate', () => {
      this.handleRoute(window.location.pathname);
    });

    // Handle link clicks
    document.addEventListener('click', (e) => {
      const target = e.target as HTMLElement;
      const link = target.closest('a[data-navigate]') as HTMLAnchorElement;

      if (link) {
        e.preventDefault();
        const path = link.getAttribute('href');
        if (path) {
          this.navigate(path);
        }
      }
    });
  }

  /**
   * Register a route
   */
  register(route: Route): void {
    this.routes.set(route.path, route);
  }

  /**
   * Register multiple routes
   */
  registerAll(routes: Route[]): void {
    routes.forEach(route => this.register(route));
  }

  /**
   * Set default route
   */
  setDefault(path: string): void {
    this.defaultRoute = path;
  }

  /**
   * Navigate to a route
   */
  navigate(path: string, replace = false): void {
    if (replace) {
      window.history.replaceState(null, '', path);
    } else {
      window.history.pushState(null, '', path);
    }
    this.handleRoute(path);
  }

  /**
   * Get current route path
   */
  getCurrentPath(): string {
    return this.currentRoute?.path ?? window.location.pathname;
  }

  /**
   * Handle route change
   */
  private async handleRoute(path: string): Promise<void> {
    const route = this.routes.get(path) ?? this.routes.get(this.defaultRoute);

    if (!route) {
      console.error(`Route not found: ${path}`);
      return;
    }

    this.currentRoute = route;

    // Update page title
    document.title = `${route.title} | QuickFW`;

    // Update store state
    store.setState({ currentPage: route.name });

    // Execute route component
    try {
      await route.component();
    } catch (error) {
      console.error(`Route error (${route.path}):`, error);
    }

    // Highlight active nav item
    this.updateActiveNav(route.name);
  }

  /**
   * Update active navigation item
   */
  private updateActiveNav(routeName: string): void {
    document.querySelectorAll('.nav-item').forEach(el => {
      el.classList.toggle('active', el.getAttribute('data-route') === routeName);
    });
  }

  /**
   * Initialize router
   */
  init(): void {
    this.handleRoute(window.location.pathname);
  }
}

// Singleton instance
export const router = new Router();

/**
 * Generate navigation link HTML
 */
export function navLink(path: string, icon: string, label: string, routeName: string): string {
  return `
    <a href="${path}" data-navigate class="nav-item" data-route="${routeName}">
      <span class="nav-icon">${icon}</span>
      <span class="nav-label">${label}</span>
    </a>
  `;
}
