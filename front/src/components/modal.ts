/**
 * Reusable Modal Dialog Component
 *
 * SECURITY NOTE: options.body and options.footer are rendered as raw HTML.
 * Callers MUST escape any user-controllable data before passing it into body/footer.
 * options.title is escaped automatically.
 */

import { escapeHtml } from '@utils';

export interface ModalOptions {
  title: string;
  body: string;
  footer?: string;
  size?: 'default' | 'lg';
  onClose?: () => void;
  onSubmit?: () => void;
}

let activeModal: HTMLElement | null = null;

function handleEscape(e: KeyboardEvent): void {
  if (e.key === 'Escape' && activeModal) {
    closeModal();
  }
}

/**
 * Open a modal dialog
 */
export function openModal(options: ModalOptions): HTMLElement {
  closeModal(); // Close any existing modal

  const overlay = document.createElement('div');
  overlay.className = 'modal-overlay';
  overlay.innerHTML = `
    <div class="modal ${options.size === 'lg' ? 'modal-lg' : ''}">
      <div class="modal-header">
        <h3 class="modal-title">${escapeHtml(options.title)}</h3>
        <button class="btn-icon modal-close" aria-label="Close">✕</button>
      </div>
      <div class="modal-body">
        ${options.body}
      </div>
      ${options.footer ? `
        <div class="modal-footer">
          ${options.footer}
        </div>
      ` : ''}
    </div>
  `;

  // Close on backdrop click
  overlay.addEventListener('click', (e) => {
    if (e.target === overlay) closeModal();
  });

  // Close button
  const closeBtn = overlay.querySelector('.modal-close');
  closeBtn?.addEventListener('click', () => closeModal());

  // Submit handler
  if (options.onSubmit) {
    const submitBtn = overlay.querySelector('[data-modal-submit]');
    submitBtn?.addEventListener('click', options.onSubmit);
  }

  document.body.appendChild(overlay);
  activeModal = overlay;

  // Store onClose callback
  if (options.onClose) {
    (overlay as HTMLElement & { _onClose?: () => void })._onClose = options.onClose;
  }

  document.addEventListener('keydown', handleEscape);

  // Focus first input
  const firstInput = overlay.querySelector<HTMLInputElement>('input, select, textarea');
  firstInput?.focus();

  return overlay;
}

/**
 * Close the active modal
 */
export function closeModal(): void {
  if (!activeModal) return;

  const onClose = (activeModal as HTMLElement & { _onClose?: () => void })._onClose;
  activeModal.remove();
  activeModal = null;
  document.removeEventListener('keydown', handleEscape);

  if (onClose) onClose();
}

/**
 * Get the active modal element (for reading form values etc.)
 */
export function getModalElement(): HTMLElement | null {
  return activeModal?.querySelector('.modal') ?? null;
}
