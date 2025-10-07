# Advanced CORS Proxy for Vercel

A simple GET-only CORS proxy built with Node.js for Vercel.  
Crafted by [BIZ FACTORY](https://t.me/bizft)

---

### Features
- GET requests with streaming support
- Blocks private/internal IPs
- Optional cookie & Authorization forwarding
- In-memory rate limiting
- Full CORS headers

---

### Usage
GET https://your-app.vercel.app/api/proxy?url=https://example.com

Optional:
- Forward cookies: `&allowCookies=1`
- Forward Authorization header: `&auth=1`

---

### Deployment

[![Deploy to Vercel](https://vercel.com/button)](https://vercel.com/new/clone?repository-url=https://github.com/Cynoxofficial/cors-proxy-bypass-bizft)

Credit: Crafted by [BIZ FACTORY](https://t.me/bizft)
