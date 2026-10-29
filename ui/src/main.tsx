import { render } from 'solid-js/web';
import './app.css';
import { App, createQueryClient } from './App';
import { createAppRouter } from './router';
import { initTheme } from './theme';

initTheme();
render(() => <App router={createAppRouter()} client={createQueryClient()} />, document.getElementById('root') as HTMLElement);
