(() => {
  'use strict';
  const section = document.querySelector('#intel');
  if (!section) return;
  const cards = section.querySelector('#signal-cards');
  const result = section.querySelector('#signal-result');
  const timestamp = section.querySelector('#signal-updated');
  const health = section.querySelector('#signal-health');
  const sourceStatus = section.querySelector('#signal-source-status');
  const search = section.querySelector('#signal-search');
  const refresh = section.querySelector('#signal-refresh');
  const more = section.querySelector('#signal-more');
  const filters = [...section.querySelectorAll('[data-signal-source]')];
  const names = { thn: 'The Hacker News', edb: 'Exploit-DB', kev: 'CISA KEV', aikido: 'Aikido Blog', netsec: 'Reddit r/netsec', devto: 'DEV Community', wiz: 'Wiz Blog', securityweek: 'SecurityWeek', bleeping: 'BleepingComputer', wired: 'WIRED Security', sophos: 'Sophos Blog' };
  const labels = { thn: 'SECURITY NEWS', edb: 'PUBLIC EXPLOIT', kev: 'EXPLOITED CVE', aikido: 'SECURITY BLOG', netsec: 'COMMUNITY POST', devto: 'DEVELOPER POST', wiz: 'SECURITY BLOG', securityweek: 'SECURITY NEWS', bleeping: 'SECURITY NEWS', wired: 'SECURITY NEWS', sophos: 'SECURITY BLOG' };
  let snapshot;
  let active = 'all';
  let limit = 6;
  let pending = false;
  let searchTimer;
  let lastChecked = 0;

  function node(tag, className, text) {
    const element = document.createElement(tag);
    if (className) element.className = className;
    if (text !== undefined) element.textContent = String(text);
    return element;
  }
  function safeUrl(value) {
    try {
      const url = new URL(value);
      return url.protocol === 'https:' && !url.username && !url.password ? url.href : null;
    } catch { return null; }
  }
  function formatDate(value, dayOnly = false) {
    const date = new Date(value);
    if (!Number.isFinite(date.getTime())) return 'Date unavailable';
    return new Intl.DateTimeFormat('en-GB', { day: '2-digit', month: 'short', year: 'numeric', ...(!dayOnly ? { hour: '2-digit', minute: '2-digit' } : {}), timeZone: 'UTC' }).format(date) + (dayOnly ? '' : ' UTC');
  }
  function validate(data) {
    if (data?.schema_version !== 1 || !Array.isArray(data.items) || !Array.isArray(data.sources)) throw new Error('Invalid feed');
    return {
      generated_at: data.generated_at,
      sources: data.sources.filter(source => source && Object.hasOwn(names, source.id)),
      items: data.items.filter(item => item && Object.hasOwn(names, item.source) && typeof item.title === 'string' && safeUrl(item.url) && Number.isFinite(Date.parse(item.published_at))).slice(0, 200)
    };
  }
  function makeCard(item) {
    const article = node('article', 'signal-card');
    article.dataset.source = item.source;
    const top = node('div', 'signal-card-top');
    top.append(node('span', 'signal-type', labels[item.source]), node('span', 'signal-card-source', names[item.source]));
    const heading = node('h3');
    const link = node('a', '', item.title.slice(0, 240));
    link.href = safeUrl(item.url);
    link.target = '_blank';
    link.rel = 'noopener noreferrer';
    link.append(node('span', 'signal-link-arrow', '↗'), node('span', 'sr-only', ' (opens in a new tab)'));
    heading.append(link);
    const details = node('div', 'signal-details');
    const cves = Array.isArray(item.cves) ? item.cves.filter(cve => /^CVE-\d{4}-\d{4,10}$/.test(cve)).slice(0, 3) : [];
    cves.forEach(cve => details.append(node('span', 'signal-cve', cve)));
    if (item.source === 'kev' && item.ransomware === true) details.append(node('span', 'signal-ransomware', 'Ransomware: known'));
    const bottom = node('div', 'signal-card-bottom');
    const date = node('time', '', formatDate(item.published_at, item.date_precision === 'day'));
    date.dateTime = item.published_at;
    bottom.append(node('span', '', item.source === 'kev' ? 'Added to KEV' : 'Published'), date);
    article.append(top, heading, details, bottom);
    return article;
  }
  function render() {
    const query = search.value.trim().toLowerCase();
    const entries = snapshot.items.filter(item => (active === 'all' || item.source === active) && [item.title, item.vendor, item.product, ...(Array.isArray(item.cves) ? item.cves : [])].filter(Boolean).join(' ').toLowerCase().includes(query));
    cards.replaceChildren();
    entries.slice(0, limit).forEach(item => cards.append(makeCard(item)));
    if (!entries.length) cards.append(node('p', 'signal-empty', 'No matching headlines. Try a different CVE, vendor, topic, or source.'));
    more.hidden = entries.length <= limit;
    result.textContent = entries.length ? `Showing ${Math.min(limit, entries.length)} of ${entries.length} entries` : 'No matching entries';
  }
  function showFreshness() {
    const checked = snapshot.sources.filter(source => source.status === 'ok' && Date.now() - Date.parse(source.last_success_at) < 3 * 60 * 60 * 1000).length;
    const total = Object.keys(names).length;
    health.textContent = checked === total ? `${checked} / ${total} SOURCES SYNCED` : `${checked} / ${total} SOURCES FRESH`;
    health.dataset.fresh = String(checked === total);
    const successes = snapshot.sources.map(source => Date.parse(source.last_success_at)).filter(Number.isFinite);
    timestamp.textContent = successes.length ? `Last sync: ${formatDate(Math.max(...successes))}` : 'Last sync: unavailable';
    sourceStatus.textContent = snapshot.sources.map(source => `${names[source.id]}: ${source.status === 'ok' && Date.now() - Date.parse(source.last_success_at) < 3 * 60 * 60 * 1000 ? 'synced' : source.status === 'unavailable' ? 'unavailable' : 'cached / older snapshot'}`).join(' · ');
  }
  async function load() {
    if (pending) return;
    pending = true;
    refresh.disabled = true;
    section.setAttribute('aria-busy', 'true');
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 10000);
    try {
      const response = await fetch(`./security-feed.json?check=${Math.floor(Date.now() / 600000)}`, { cache: 'no-store', signal: controller.signal, credentials: 'same-origin' });
      if (!response.ok) throw new Error('Feed unavailable');
      const raw = await response.text();
      if (raw.length > 750000) throw new Error('Oversized feed');
      snapshot = validate(JSON.parse(raw));
      showFreshness();
      render();
      lastChecked = Date.now();
    } catch (error) {
      console.warn('[security-feed] Refresh failed:', error.message);
      health.textContent = snapshot ? 'CACHED SNAPSHOT' : 'FEED UNAVAILABLE';
      health.dataset.fresh = 'false';
      if (snapshot) {
        result.textContent = 'Refresh failed; keeping the last loaded headlines.';
      } else {
        cards.replaceChildren(node('p', 'signal-empty', 'The feed could not be loaded. Use the source links below or try Refresh again.'));
        timestamp.textContent = 'Last sync: unavailable';
        sourceStatus.textContent = 'Source status could not be checked.';
        result.textContent = 'No snapshot available';
        more.hidden = true;
      }
    } finally {
      clearTimeout(timeout);
      pending = false;
      refresh.disabled = false;
      section.setAttribute('aria-busy', 'false');
    }
  }
  filters.forEach(button => button.addEventListener('click', () => {
    active = button.dataset.signalSource;
    limit = 6;
    filters.forEach(filter => filter.setAttribute('aria-pressed', String(filter === button)));
    if (snapshot) render();
  }));
  search.addEventListener('input', () => {
    clearTimeout(searchTimer);
    searchTimer = setTimeout(() => { limit = 6; if (snapshot) render(); }, 150);
  });
  more.addEventListener('click', () => { limit += 6; if (snapshot) render(); });
  refresh.addEventListener('click', load);
  document.addEventListener('visibilitychange', () => {
    if (!document.hidden && Date.now() - lastChecked > 600000) load();
  });
  setInterval(() => { if (!document.hidden) load(); }, 600000);
  load();
})();
