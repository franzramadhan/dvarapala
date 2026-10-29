import { afterEach } from 'vitest';
import { cleanup } from '@solidjs/testing-library';
import { resetAll } from '../history';

// index.html carries these in the real page; jsdom starts blank.
document.documentElement.lang = 'en';
document.title = 'Dvarapala';

afterEach(() => {
  cleanup();
  resetAll();
  document.documentElement.setAttribute('data-theme', 'light');
});
