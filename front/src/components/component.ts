import { $, $$, on } from '@utils';

/**
 * Base Component class
 * Provides lifecycle management and DOM utilities
 */
export abstract class Component<TState = Record<string, unknown>> {
  protected element: HTMLElement;
  protected state: TState;
  protected children: Component[];
  private listeners: Array<() => void>;
  private parent: Component | null;

  constructor(element: HTMLElement | string) {
    this.element = typeof element === 'string' ? $(element)! : element;
    if (!this.element) {
      throw new Error(`Component element not found: ${element}`);
    }

    this.state = {} as TState;
    this.children = [];
    this.listeners = [];
    this.parent = null;
  }

  /**
   * Set component state and trigger render
   */
  setState(newState: Partial<TState>): void {
    const prevState = { ...this.state };
    this.state = { ...this.state, ...newState } as TState;

    // Only render if state actually changed
    if (JSON.stringify(prevState) !== JSON.stringify(this.state)) {
      this.render();
      this.onStateChange?.(newState, prevState);
    }
  }

  /**
   * Get current state
   */
  getState(): Readonly<TState> {
    return this.state;
  }

  /**
   * Add child component
   */
  protected addChild(child: Component): void {
    child.parent = this;
    this.children.push(child);
  }

  /**
   * Remove child component
   */
  protected removeChild(child: Component): void {
    const index = this.children.indexOf(child);
    if (index > -1) {
      this.children[index].destroy();
      this.children.splice(index, 1);
    }
  }

  /**
   * Attach event listener (auto-cleanup on destroy)
   */
  protected attachEvent<T extends EventTarget>(
    target: T,
    event: string,
    handler: EventListener
  ): void {
    this.listeners.push(on(target, event, handler));
  }

  /**
   * Get element by selector within component
   */
  protected $<T extends HTMLElement>(selector: string): T | null {
    return $(selector, this.element);
  }

  /**
   * Get all elements by selector within component
   */
  protected $$<T extends HTMLElement>(selector: string): T[] {
    return $$(selector, this.element);
  }

  /**
   * Create child element
   */
  protected createChild(tag: string, className?: string, content?: string): HTMLElement {
    const child = document.createElement(tag);
    if (className) child.className = className;
    if (content) child.innerHTML = content;
    return child;
  }

  /**
   * Lifecycle: Initialize component
   * Called once when component is created
   */
  abstract init(): void;

  /**
   * Lifecycle: Render component
   * Called whenever state changes
   */
  abstract render(): void;

  /**
   * Lifecycle: Called after state changes (optional)
   */
  protected onStateChange?(_newState: Partial<TState>, _prevState: TState): void;

  /**
   * Lifecycle: Destroy component
   * Clean up event listeners and child components
   */
  destroy(): void {
    // Clean up event listeners
    this.listeners.forEach(unsubscribe => unsubscribe());
    this.listeners = [];

    // Destroy children
    this.children.forEach(child => child.destroy());
    this.children = [];

    // Clear element content
    this.element.innerHTML = '';
  }

  /**
   * Get the root DOM element
   */
  getElement(): HTMLElement {
    return this.element;
  }
}

/**
 * Component decorator for auto-registration
 */
export function defineComponent(tagName: string): (target: new (...args: unknown[]) => Component) => void {
  return function (target: new (...args: unknown[]) => Component): void {
    // Store metadata on the class
    Object.defineProperty(target, '__tagName', {
      value: tagName,
      writable: false,
    });
  };
}
