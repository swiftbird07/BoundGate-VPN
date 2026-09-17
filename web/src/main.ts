import { mount } from 'svelte';
import './app.css';
import App from './App.svelte';

// UI work without a control plane: `npm run dev` and open /?demo (src/dev/demo.ts).
if (import.meta.env.DEV) (await import('./dev/demo')).installDemo();

export default mount(App, { target: document.getElementById('app')! });
