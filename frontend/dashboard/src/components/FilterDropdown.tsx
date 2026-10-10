import { useEffect, useLayoutEffect, useId, useRef, type KeyboardEvent } from 'react';
import { Check, ChevronDown } from 'lucide-react';

export interface FilterOption { value: string; label: string; disabled?: boolean }

export function FilterDropdown({ label, caption, value, options, open, onToggle, onClose, onChange }: {
  label: string; caption?: string; value: string; options: FilterOption[]; open: boolean;
  onToggle: () => void; onClose: () => void; onChange: (value: string) => void;
}) {
  const id = useId();
  const root = useRef<HTMLDivElement>(null);
  const trigger = useRef<HTMLButtonElement>(null);
  const menu = useRef<HTMLDivElement>(null);
  useLayoutEffect(() => {
    if (!open) return;
    function fitViewport() {
      const popup = menu.current;
      if (!popup) return;
      popup.style.translate = '0px';
      const box = popup.getBoundingClientRect();
      const offset = box.left < 12 ? 12 - box.left : box.right > innerWidth - 12 ? innerWidth - 12 - box.right : 0;
      popup.style.translate = `${offset}px`;
    }
    fitViewport();
    window.addEventListener('resize', fitViewport);
    return () => window.removeEventListener('resize', fitViewport);
  }, [open]);
  useEffect(() => {
    if (!open) return;
    const selected = menu.current?.querySelector<HTMLButtonElement>('[aria-checked="true"]:not(:disabled)');
    (selected ?? menu.current?.querySelector<HTMLButtonElement>('button:not(:disabled)'))?.focus({ preventScroll: true });
    function outside(event: PointerEvent) { if (!root.current?.contains(event.target as Node)) onClose(); }
    document.addEventListener('pointerdown', outside);
    return () => document.removeEventListener('pointerdown', outside);
  }, [open, onClose]);
  function close() { onClose(); trigger.current?.focus({ preventScroll: true }); }
  function navigate(event: KeyboardEvent) {
    if (event.key === 'Escape') { event.preventDefault(); event.stopPropagation(); close(); return; }
    if (event.key === 'Tab') { close(); return; }
    if (!['ArrowDown', 'ArrowUp', 'Home', 'End'].includes(event.key)) return;
    event.preventDefault();
    const buttons = Array.from(menu.current?.querySelectorAll<HTMLButtonElement>('button:not(:disabled)') ?? []);
    const current = buttons.indexOf(document.activeElement as HTMLButtonElement);
    const next = event.key === 'Home' ? 0 : event.key === 'End' ? buttons.length - 1 : (current + (event.key === 'ArrowDown' ? 1 : -1) + buttons.length) % buttons.length;
    buttons[next]?.focus();
  }
  return <div className="filter-dropdown" ref={root} onBlur={event => { if (!event.currentTarget.contains(event.relatedTarget as Node)) onClose(); }}>
    <button ref={trigger} className="filter-control" aria-label={label} aria-haspopup="menu" aria-expanded={open} aria-controls={open ? id : undefined}
      onClick={onToggle} onKeyDown={event => { if (event.key === 'ArrowDown' || event.key === 'ArrowUp') { event.preventDefault(); if (!open) onToggle(); } }}>
      {caption && <span className="filter-caption">{caption}</span>}<span className="filter-value">{options.find(option => option.value === value)?.label}</span><ChevronDown size={13} aria-hidden="true" />
    </button>
    {open && <div ref={menu} id={id} className="filter-popup" role="menu" aria-label={`${label} options`} onKeyDown={navigate}>
      {options.map(option => <button key={option.value} role="menuitemradio" aria-checked={option.value === value} disabled={option.disabled} tabIndex={-1}
        onClick={() => { onChange(option.value); close(); }}><span>{option.label}</span><Check size={14} aria-hidden="true" className={option.value === value ? '' : 'option-check-hidden'} /></button>)}
    </div>}
  </div>;
}
