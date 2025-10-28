// api/proxy.js
import { createProxyMiddleware } from "http-proxy-middleware";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import express from "express";
import morgan from "morgan";
import jwt from "jsonwebtoken";
import { WHITELIST } from "../lib/whitelist.js";
import { verifyToken } from "../lib/jwt.js";

const app = express();

// ====================
// セキュリティ設定
// ====================
app.use(helmet({ contentSecurityPolicy: false }));
app.disable("x-powered-by");

// ====================
// ログ
// ====================
app.use(morgan(process.env.NODE_ENV === "production" ? "combined" : "dev"));

// ====================
// レート制限
// ====================
app.use(rateLimit({
  windowMs: 10 * 60 * 1000,
  max: 200,
  standardHeaders: true,
  legacyHeaders: false,
}));

// ====================
// JWT認証
// ====================
app.use((req, res, next) => {
  if (!verifyToken(req.headers.authorization)) {
    return res.status(401).json({ error: "Invalid or missing token" });
  }
  next();
});

// ====================
// ドメイン検証
// ====================
app.use((req, res, next) => {
  const target = req.query.url || req.headers["x-target-url"];
  if (!target) return res.status(400).json({ error: "Missing target URL" });

  try {
    const { hostname } = new URL(target);
    const allowed = WHITELIST.some(d => hostname === d || hostname.endsWith(`.${d}`));
    if (!allowed) {
      return res.status(403).json({ error: `Domain '${hostname}' not allowed` });
    }
    req.target = target;
    next();
  } catch {
    return res.status(400).json({ error: "Invalid URL format" });
  }
});

// ====================
// プロキシ処理
// ====================
app.use(
  "/",
  createProxyMiddleware({
    changeOrigin: true,
    secure: true,
    followRedirects: true,
    logLevel: "warn",
    onProxyReq: (proxyReq, req) => {
      const url = new URL(req.target);
      proxyReq.path = url.pathname + url.search;
      proxyReq.removeHeader("cookie");
      proxyReq.removeHeader("referer");
      proxyReq.removeHeader("origin");
    },
    onProxyRes: (proxyRes) => {
      delete proxyRes.headers["set-cookie"];
      delete proxyRes.headers["x-powered-by"];
    },
    router: req => req.target,
  })
);

export default app;
