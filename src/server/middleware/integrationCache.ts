import { defineEventHandler, getRequestURL, setHeader } from 'h3';

export default defineEventHandler((event) => {
  const path = getRequestURL(event).pathname;
  if (path === '/api/v1' || path.startsWith('/api/v1/'))
    setHeader(event, 'Cache-Control', 'no-store');
});
