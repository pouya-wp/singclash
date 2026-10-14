// Local entry point (npm run dev / npm start). On Vercel, api/index.js is used instead.
import app from './src/app.js';
import { getConfig, STORAGE } from './src/config-store.js';

const PORT = Number(process.env.PORT) || 3000;
const HOST = process.env.HOST || '0.0.0.0';

await getConfig(); // creates config.json with a fresh token on first run

app.listen(PORT, HOST, () => {
  console.log(`SingClash panel:  http://localhost:${PORT}`);
  console.log(`Settings stored:  ${STORAGE}`);
  if (!process.env.PANEL_PASSWORD) console.log('Tip: set PANEL_PASSWORD to protect the panel with a password.');
});
