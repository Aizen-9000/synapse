# Synapse Auth Server

Handles user accounts, Razorpay subscriptions, and JWT license tokens.
Runs on port 9000, completely separate from the agent runtime (port 8000).

---

## Setup

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Configure environment
cp .env.example .env
# Edit .env with your Razorpay keys and JWT secret

# 3. Start server
python main.py
# Docs at http://localhost:9000/docs
# Signup page at http://localhost:9000
```

---

## Razorpay Setup (do this before launching)

1. Create account at https://dashboard.razorpay.com
2. Go to Settings → API Keys → Generate test key
3. Add RAZORPAY_KEY_ID and RAZORPAY_KEY_SECRET to .env
4. Create two subscription plans in the Razorpay dashboard:
   - Basic: ₹299/month
   - Pro: ₹599/month
5. Copy the plan IDs to PLAN_BASIC_ID and PLAN_PRO_ID in .env
6. Set up webhook in Razorpay dashboard:
   - URL: https://yourdomain.com/webhook/razorpay
   - Events: subscription.charged, subscription.halted, subscription.cancelled
7. Copy webhook secret to RAZORPAY_WEBHOOK_SECRET in .env

---

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| POST | /auth/signup | Create account |
| POST | /auth/login | Get JWT token |
| POST | /auth/create-subscription | Create Razorpay subscription |
| GET | /license/validate | Check token validity (client calls every 24h) |
| POST | /license/refresh | Refresh expiring token |
| POST | /license/revoke | Admin: revoke a token |
| POST | /webhook/razorpay | Razorpay payment events |
| GET | / | Signup webpage |

---

## Client Integration

In the desktop app, the LicenseGate component:
1. Checks localStorage for a stored token on launch
2. Validates token signature + expiry locally (works offline)
3. Hits /license/validate every 24 hours
4. Refreshes token when 7 days remain before expiry
5. Locks the UI if the license is revoked or expired

To activate: rename `src/main-with-license.jsx` to `src/main.jsx`

---

## Deployment

For production, deploy to any VPS (DigitalOcean, Railway, Render):

```bash
# With a reverse proxy (nginx) handling HTTPS
uvicorn main:app --host 0.0.0.0 --port 9000

# Update AUTH_SERVER in LicenseGate.jsx and web/index.html
# to point to your deployed URL
```

The auth server is the ONLY thing you need to keep running.
Everything else (inference, tools, memory, P2P) runs on user devices.
Monthly cost: ~$5-20 depending on VPS tier.

---

## Logout (client side)

Users can log out via `Ctrl + Shift + L` in the desktop app.
This clears the stored token and shows the license entry screen.
