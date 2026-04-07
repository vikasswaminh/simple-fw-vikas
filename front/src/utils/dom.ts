/**
 * DOM manipulation utilities
 */

/**
 * Create an element with optional class and content
 */
export function createElement(
  tag: string,
  className?: string,
  content?: string | HTMLElement | HTMLElement[]
): HTMLElement {
  const element = document.createElement(tag);

  if (className) {
    element.className = className;
  }

  if (content != null) {
    if (typeof content === 'string') {
      element.innerHTML = content;
    } else if (Array.isArray(content)) {
      content.forEach(child => element.appendChild(child));
    } else {
      element.appendChild(content);
    }
  }

  return element;
}

/**
 * Query selector with type safety
 */
export function $<T extends HTMLElement>(selector: string, parent: ParentNode = document): T | null {
  return parent.querySelector(selector) as T | null;
}

/**
 * Query selector all with type safety
 */
export function $$<T extends HTMLElement>(selector: string, parent: ParentNode = document): T[] {
  return Array.from(parent.querySelectorAll(selector)) as T[];
}

/**
 * Add event listener with automatic cleanup
 */
export function on<T extends EventTarget>(
  target: T,
  event: string,
  handler: EventListener,
  options?: AddEventListenerOptions
): () => void {
  target.addEventListener(event, handler, options);
  return () => target.removeEventListener(event, handler, options);
}

/**
 * Debounce function calls
 */
export function debounce<T extends (...args: unknown[]) => unknown>(
  fn: T,
  ms: number
): (...args: Parameters<T>) => void {
  let timeoutId: ReturnType<typeof setTimeout> | null = null;

  return (...args: Parameters<T>): void => {
    if (timeoutId) {
      clearTimeout(timeoutId);
    }
    timeoutId = setTimeout(() => fn(...args), ms);
  };
}

/**
 * Throttle function calls
 */
export function throttle<T extends (...args: unknown[]) => unknown>(
  fn: T,
  ms: number
): (...args: Parameters<T>) => void {
  let lastTime = 0;

  return (...args: Parameters<T>): void => {
    const now = Date.now();
    if (now - lastTime >= ms) {
      lastTime = now;
      fn(...args);
    }
  };
}

/**
 * Show/hide element
 */
export function setVisible(element: HTMLElement, visible: boolean): void {
  element.style.display = visible ? '' : 'none';
}

/**
 * Toggle element class
 */
export function toggleClass(element: HTMLElement, className: string, force?: boolean): boolean {
  return element.classList.toggle(className, force);
}

/**
 * Check if element has class
 */
export function hasClass(element: HTMLElement, className: string): boolean {
  return element.classList.contains(className);
}

/**
 * Empty element's children
 */
export function empty(element: HTMLElement): void {
  while (element.firstChild) {
    element.removeChild(element.firstChild);
  }
}

/**
 * Get form data as object
 */
export function getFormData(form: HTMLFormElement): Record<string, string> {
  const formData = new FormData(form);
  const data: Record<string, string> = {};

  formData.forEach((value, key) => {
    data[key] = value.toString();
  });

  return data;
}

/**
 * Set multiple attributes at once
 */
export function setAttributes(element: HTMLElement, attributes: Record<string, string>): void {
  Object.entries(attributes).forEach(([key, value]) => {
    element.setAttribute(key, value);
  });
}

/**
 * Copy text to clipboard
 */
export async function copyToClipboard(text: string): Promise<boolean> {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    // Fallback
    const textarea = document.createElement('textarea');
    textarea.value = text;
    textarea.style.position = 'fixed';
    textarea.style.opacity = '0';
    document.body.appendChild(textarea);
    textarea.select();
    const success = document.execCommand('copy');
    document.body.removeChild(textarea);
    return success;
  }
}

/**
 * Download data as file
 */
export function downloadFile(data: string | Blob, filename: string, type?: string): void {
  const blob = data instanceof Blob ? data : new Blob([data], { type: type || 'text/plain' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

/**
 * Read file as text
 */
export function readFileAsText(file: File): Promise<string> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(reader.result as string);
    reader.onerror = reject;
    reader.readAsText(file);
  });
}

/**
 * Animate element (simple fade in/out)
 */
export function fadeIn(element: HTMLElement, duration = 300): Promise<void> {
  return new Promise(resolve => {
    element.style.opacity = '0';
    element.style.transition = `opacity ${duration}ms`;
    element.style.display = '';

    // Force reflow
    void element.offsetHeight;

    element.style.opacity = '1';

    setTimeout(() => {
      element.style.transition = '';
      resolve();
    }, duration);
  });
}

export function fadeOut(element: HTMLElement, duration = 300): Promise<void> {
  return new Promise(resolve => {
    element.style.transition = `opacity ${duration}ms`;
    element.style.opacity = '0';

    setTimeout(() => {
      element.style.display = 'none';
      element.style.transition = '';
      element.style.opacity = '';
      resolve();
    }, duration);
  });
}
