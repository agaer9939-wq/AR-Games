# AR GAMES

An English-language gaming landing page with user accounts stored in a local SQLite database. The games collection is intentionally empty until real titles are ready to be added.

## Run locally

Requires Node.js 22.5 or later.

1. Copy `.env.example` to `.env`.
2. Set `SMTP_USER` to your sending email and `SMTP_PASS` to its SMTP password. For Gmail, use a Google App Password (not your regular account password); enable 2-Step Verification and create an App Password in your Google Account.
3. Update `SMTP_FROM` if you want a different sender name/address. Keep `.env` private; it is excluded from Git.
4. Run `npm.cmd start` and open `http://localhost:3000`.

New accounts are not created until the user enters the 6-digit code delivered to their email. Codes expire after 10 minutes, allow up to five attempts, and can be resent after 60 seconds. If SMTP is not configured or delivery fails, registration displays an error and does not create an account.

Accounts, favorites, sessions, and pending email verifications are stored in `ar-games.sqlite` beside the server. Change `PORT` or `DB_PATH` to customize the port or database location.

The server uses random sessions in `HttpOnly` cookies and stores passwords as salted `scrypt` hashes. In production, set `NODE_ENV=production` and run the service behind HTTPS.
