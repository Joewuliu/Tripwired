import * as linkify from "linkifyjs";

const HAS_SCHEME = /^[a-z][a-z0-9+.-]*:\/\//i;
const WEB_SCHEME = /^https?:\/\//i;

/** Undo defanging, so a pasted "hxxps://evil[.]example" is still recognised as a link. */
export function refang(text: string): string {
  return text.replace(/hxxp(s?):\/\//gi, "http$1://").replace(/\[\.\]|\(\.\)/g, ".");
}

/**
 * Web links in a message, in order, without duplicates. Links typed without a scheme
 * (ezpass-pay.top/x) get https://. Other schemes (ftp:, file:) are ignored.
 */
export function extractUrls(text: string): string[] {
  const urls: string[] = [];
  for (const link of linkify.find(refang(text))) {
    if (link.type !== "url") continue;
    if (!HAS_SCHEME.test(link.value)) urls.push(`https://${link.value}`);
    else if (WEB_SCHEME.test(link.value)) urls.push(link.href);
  }
  return [...new Set(urls)];
}
