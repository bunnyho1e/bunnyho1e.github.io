'use strict';

document.documentElement.classList.add('js');

const menuButton = document.querySelector('.menu-toggle');
const navigation = document.querySelector('#site-nav');
function closeMenu() {
  menuButton.setAttribute('aria-expanded', 'false');
  menuButton.setAttribute('aria-label', 'Open navigation');
  navigation.classList.remove('is-open');
}
menuButton.addEventListener('click', () => {
  const open = menuButton.getAttribute('aria-expanded') !== 'true';
  menuButton.setAttribute('aria-expanded', String(open));
  menuButton.setAttribute('aria-label', open ? 'Close navigation' : 'Open navigation');
  navigation.classList.toggle('is-open', open);
});
navigation.querySelectorAll('a').forEach(link => link.addEventListener('click', closeMenu));
document.addEventListener('keydown', event => {
  if (event.key === 'Escape' && menuButton.getAttribute('aria-expanded') === 'true') {
    closeMenu();
    menuButton.focus();
  }
});

const collections = {
  red: { repository: 'RedTeaming', count: 252, categories: 15 },
  blue: { repository: 'BlueTeaming', count: 410, categories: 20 }
};
const tabs = [...document.querySelectorAll('[data-collection]')];
const panel = document.querySelector('#collection-panel');
const cloneCommand = document.querySelector('#clone-command');
const copyButton = document.querySelector('#copy-command');
const status = document.querySelector('#copy-status');
let copiedTimer;

function selectCollection(tab) {
  const id = tab.dataset.collection;
  const collection = collections[id];
  if (!collection) return;
  tabs.forEach(item => {
    const selected = item === tab;
    item.setAttribute('aria-selected', String(selected));
    item.tabIndex = selected ? 0 : -1;
  });
  panel.setAttribute('aria-labelledby', tab.id);
  document.querySelector('.workbench').dataset.active = id;
  document.querySelector('#source-count').textContent = collection.count;
  document.querySelector('#category-count').textContent = collection.categories;
  const link = document.querySelector('#collection-link');
  link.href = `https://github.com/bunnyho1e/${collection.repository}`;
  link.setAttribute('aria-label', `Open ${collection.repository} on GitHub (opens in a new tab)`);
  cloneCommand.textContent = `git clone https://github.com/bunnyho1e/${collection.repository}.git`;
  clearTimeout(copiedTimer);
  copyButton.classList.remove('copied');
  copyButton.querySelector('.copy-label').textContent = 'Copy';
  copyButton.setAttribute('aria-label', 'Copy clone command');
  status.textContent = `${collection.repository} selected. ${collection.count} sources in ${collection.categories} categories.`;
}
tabs.forEach((tab, index) => {
  tab.addEventListener('click', () => selectCollection(tab));
  tab.addEventListener('keydown', event => {
    let next;
    if (event.key === 'ArrowRight') next = tabs[(index + 1) % tabs.length];
    if (event.key === 'ArrowLeft') next = tabs[(index - 1 + tabs.length) % tabs.length];
    if (event.key === 'Home') next = tabs[0];
    if (event.key === 'End') next = tabs[tabs.length - 1];
    if (next) {
      event.preventDefault();
      selectCollection(next);
      next.focus();
    }
  });
});

copyButton.addEventListener('click', async () => {
  try {
    if (!navigator.clipboard?.writeText) throw new Error('Clipboard unavailable');
    await navigator.clipboard.writeText(cloneCommand.textContent);
    copyButton.classList.add('copied');
    copyButton.querySelector('.copy-label').textContent = 'Copied';
    copyButton.setAttribute('aria-label', 'Clone command copied');
    status.textContent = 'Clone command copied to clipboard.';
    clearTimeout(copiedTimer);
    copiedTimer = setTimeout(() => {
      copyButton.classList.remove('copied');
      copyButton.querySelector('.copy-label').textContent = 'Copy';
      copyButton.setAttribute('aria-label', 'Copy clone command');
    }, 2400);
  } catch {
    const selection = window.getSelection();
    const range = document.createRange();
    range.selectNodeContents(cloneCommand);
    selection?.removeAllRanges();
    selection?.addRange(range);
    status.textContent = 'The command is selected. Use your device’s Copy action.';
    copyButton.setAttribute('aria-label', 'Command selected — copy it using your device');
  }
});

document.querySelector('#copyright-year').textContent = new Date().getFullYear();

if ('IntersectionObserver' in window) {
  const links = [...navigation.querySelectorAll('a')];
  const observer = new IntersectionObserver(entries => {
    for (const entry of entries) {
      if (!entry.isIntersecting) continue;
      links.forEach(link => {
        if (link.hash === `#${entry.target.id}`) link.setAttribute('aria-current', 'location');
        else link.removeAttribute('aria-current');
      });
    }
  }, { rootMargin: '-15% 0px -55% 0px', threshold: 0 });
  document.querySelectorAll('main section[id]').forEach(section => observer.observe(section));
}
