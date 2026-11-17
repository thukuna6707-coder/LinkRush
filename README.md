# LinkRush

A Node.js website that resolves ordinary HTTP redirect chains server-side and displays the resulting destination without opening the submitted link in another tab.

## Run locally
- Node.js 20+
- `npm start`
- Open `http://localhost:3000`

## Deploy to Railway
1. Create a GitHub repository and upload the contents of this folder.
2. Create a Railway project and deploy the repository.
3. Railway detects Node.js and runs `npm start`.
4. Open the generated public domain.

## Important limitations
- This is a redirect inspector, not a CAPTCHA bypass tool.
- CAPTCHA, login, JavaScript-heavy ad pages, cookies, and interactive verification cannot be generically completed by this backend.
- When a shortener requires a human step, complete it through that service's own supported page. This app does not extract, forge, relay, or replay CAPTCHA tokens.
- Some services block automated server requests or prohibit automated access. Respect their terms and rate limits.

## Safety
The resolver only accepts HTTP(S), checks DNS results against private/reserved IP ranges, pins requests to a validated IP, limits redirects, applies timeouts, and caps response bodies. It does not forward user cookies or authorization headers.
