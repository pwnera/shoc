/**
 * Links built from kernel data (rule references, report URLs) are drawn as
 * links only when they are http(s); anything else (`data:`, `file:`, a custom
 * protocol) is drawn as text (SEC-1).
 */
export const safeHref = (url: string): string | undefined => (/^https?:\/\/\S+$/i.test(url.trim()) ? url.trim() : undefined);
