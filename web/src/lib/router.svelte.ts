// Minimal history router: the shell picks a page by pathname.
export const route = $state({ path: location.pathname, query: new URLSearchParams(location.search) });

function sync() {
  route.path = location.pathname;
  route.query = new URLSearchParams(location.search);
}

export function navigate(to: string, replace = false) {
  if (replace) history.replaceState(null, '', to); else history.pushState(null, '', to);
  sync();
  window.scrollTo({ top: 0 });
}

window.addEventListener('popstate', sync);
document.addEventListener('click', (e) => {
  if (e.defaultPrevented || e.button !== 0 || e.metaKey || e.ctrlKey || e.shiftKey || e.altKey) return;
  const a = (e.target as HTMLElement).closest?.('a');
  if (!a || a.target || a.hasAttribute('download')) return;
  const href = a.getAttribute('href');
  if (!href || !href.startsWith('/') || href.startsWith('/api/') || href.startsWith('//')) return;
  e.preventDefault();
  navigate(href);
});
