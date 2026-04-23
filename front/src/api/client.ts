import { z } from 'zod';

// Endpoints in endpoints.ts already include the '/api/' prefix, so keep the
// base empty. A non-empty base here double-prefixed every call to
// /api/api/... — the server's SPA fallback then returned index.html,
// producing "Unexpected token '<'" on JSON.parse in the dashboard.
const API_BASE = '';

/** Read a cookie value from document.cookie (browser-only). */
function readCookie(name: string): string | null {
  if (typeof document === 'undefined') return null;
  const needle = `${name}=`;
  for (const part of document.cookie.split(';')) {
    const trimmed = part.trim();
    if (trimmed.startsWith(needle)) return trimmed.slice(needle.length);
  }
  return null;
}

interface ApiError {
  status: number;
  message: string;
  data?: unknown;
}

class ApiErrorClass extends Error implements ApiError {
  status: number;
  data?: unknown;

  constructor(status: number, message: string, data?: unknown) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.data = data;
  }
}

class ApiClient {
  private baseUrl: string;
  private defaultHeaders: Record<string, string>;

  constructor(baseUrl: string = API_BASE) {
    this.baseUrl = baseUrl;
    this.defaultHeaders = {
      'Content-Type': 'application/json',
      Accept: 'application/json',
    };
  }

  private async request<T>(
    endpoint: string,
    options: RequestInit = {},
    schema?: z.ZodType<T>
  ): Promise<T> {
    const url = `${this.baseUrl}${endpoint}`;

    // Double-submit CSRF: read the non-HttpOnly quickfw_csrf cookie set on
    // login, send it back as X-CSRF-Token on every mutating request. The
    // backend verifies header == cookie (see auth.rs csrf_check).
    const method = (options.method || 'GET').toUpperCase();
    const mutating = method !== 'GET' && method !== 'HEAD' && method !== 'OPTIONS';
    const extraHeaders: Record<string, string> = {};
    if (mutating) {
      const csrf = readCookie('quickfw_csrf');
      if (csrf) extraHeaders['X-CSRF-Token'] = csrf;
    }

    const response = await fetch(url, {
      ...options,
      headers: {
        ...this.defaultHeaders,
        ...extraHeaders,
        ...options.headers,
      },
    });

    // Handle non-OK responses
    if (!response.ok) {
      let errorData: unknown;
      try {
        errorData = await response.json();
      } catch {
        errorData = await response.text();
      }

      throw new ApiErrorClass(
        response.status,
        typeof errorData === 'string' ? errorData : response.statusText,
        errorData
      );
    }

    // Parse JSON response
    const data = (await response.json()) as unknown;

    // Validate with Zod schema if provided
    if (schema) {
      try {
        return schema.parse(data);
      } catch (validationError) {
        if (validationError instanceof z.ZodError) {
          console.error('API Response validation failed:', validationError.errors);
          throw new ApiErrorClass(
            500,
            `Invalid API response: ${validationError.errors.map(e => e.message).join(', ')}`,
            validationError.errors
          );
        }
        throw validationError;
      }
    }

    return data as T;
  }

  /**
   * GET request
   */
  async get<T>(endpoint: string, schema?: z.ZodType<T>): Promise<T> {
    return this.request<T>(endpoint, { method: 'GET' }, schema);
  }

  /**
   * POST request
   */
  async post<T>(
    endpoint: string,
    body: unknown,
    schema?: z.ZodType<T>
  ): Promise<T> {
    return this.request<T>(
      endpoint,
      {
        method: 'POST',
        body: JSON.stringify(body),
      },
      schema
    );
  }

  /**
   * PUT request
   */
  async put<T>(
    endpoint: string,
    body: unknown,
    schema?: z.ZodType<T>
  ): Promise<T> {
    return this.request<T>(
      endpoint,
      {
        method: 'PUT',
        body: JSON.stringify(body),
      },
      schema
    );
  }

  /**
   * DELETE request
   */
  async delete<T>(endpoint: string, schema?: z.ZodType<T>): Promise<T> {
    return this.request<T>(endpoint, { method: 'DELETE' }, schema);
  }

  /**
   * Check if API is available
   */
  async healthCheck(): Promise<boolean> {
    try {
      await this.get('/api/health');
      return true;
    } catch {
      return false;
    }
  }
}

// Export singleton instance
export const api = new ApiClient();

// Export error class for type checking
export { ApiErrorClass as ApiError };
