const bidi = /[\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069]/g;

export function defangUrl(value: string): string {
  return value.replace(bidi, '').replace(/^https:/i, 'hxxps:').replace(/^http:/i, 'hxxp:').replace(/\.(?!\])/g, '[.]');
}
export function defangText(value: string): string {
  return value.replace(bidi, '').replace(/\b(?:https?:\/\/|hxxps?:\/\/)[^\s<>"']+/gi, match => {
    const punctuation = match.match(/[.,;!?]+$/)?.[0] || '';
    return defangUrl(punctuation ? match.slice(0, -punctuation.length) : match) + punctuation;
  });
}
export function redactAndDefang(value: string): string {
  const url = new URL(value);
  url.hash = '';
  // Demo fixtures never retain query values or email-like path segments.
  for (const key of [...url.searchParams.keys()]) url.searchParams.set(key, 'REDACTED');
  url.pathname = url.pathname.replace(/[^/]*@[^/]*/g, 'REDACTED');
  return defangUrl(url.toString());
}
export function normalizeInput(value: string): string {
  const trimmed = value.trim();
  if (!trimmed || trimmed.length > 4096 || /\s/.test(trimmed) || bidi.test(trimmed)) {
    bidi.lastIndex = 0;
    throw new Error('Enter one HTTP or HTTPS website link, up to 4,096 characters.');
  }
  bidi.lastIndex = 0;
  let url: URL;
  try { url = new URL(/^[a-z][a-z\d+.-]*:/i.test(trimmed) ? trimmed : `https://${trimmed}`); }
  catch { throw new Error('Enter one valid website link, such as example.test/payment.'); }
  if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password || !url.hostname.includes('.')) {
    throw new Error('Use an HTTP or HTTPS link without an embedded username or password.');
  }
  const host = url.hostname.toLowerCase();
  if (host.endsWith('.localhost') || host === 'localhost' || host === '0.0.0.0' || host.startsWith('127.') || host.startsWith('10.') || host.startsWith('192.168.') || /^172\.(1[6-9]|2\d|3[01])\./.test(host) || host.startsWith('169.254.') || host.includes(':') || host.endsWith('.local')) {
    throw new Error('This destination cannot be scanned. Enter a public website address.');
  }
  return url.toString();
}
export function refangForRescan(display: string): string {
  return display.replace(/^hxxps:/i, 'https:').replace(/^hxxp:/i, 'http:').replace(/\[\.\]/g, '.');
}
