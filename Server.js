// Server.js
import express from "express";
import helmet from "helmet";
import morgan from "morgan";
import rateLimit from "express-rate-limit";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";
import { createProxyMiddleware } from "http-proxy-middleware";

dotenv.config();

const app = express();

// ====================
// ✅ ホワイトリスト
// ====================
const WHITELIST = [
  "api.example.com",
  "assets.example.com",
  "cdn.example.com",
  "api.openai.com",
  "maps.googleapis.com",
  "fonts.googleapis.com",
  "fonts.gstatic.com",
  "raw.githubusercontent.com",
  "githubusercontent.com",
  "api.github.com",
  "firebase.googleapis.com",
  "firestore.googleapis.com",
  "storage.googleapis.com",
  "jsonplaceholder.typicode.com",
  "dummyjson.com",
  ...(process.env.EXTRA_WHITELIST?.split(",") || []),
];

// ====================
// ✅ セキュリティ設定
// ====================
app.use(helmet({ contentSecurityPolicy: false }));
app.disable("x-powered-by");

// ====================
// ✅ ログ
// ====================
app.use(morgan(process.env.NODE_ENV === "production" ? "combined" : "dev"));

// ====================
// ✅ Rate Limiter
// ====================
app.use(rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 300,
  standardHeaders: true,
  legacyHeaders: false,
}));

// ====================
// ✅ JWT 認証
// ====================
const authenticateJWT = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader?.startsWith("Bearer ")) {
    return res.status(401).json({ error: "Missing or invalid Authorization header" });
  }
  const token = authHeader.split(" ")[1];
  try {
    jwt.verify(token, process.env.JWT_SECRET || "default_secret");
    next();
  } catch {
    return res.status(403).json({ error: "Invalid or expired token" });
  }
};

// ====================
// ✅ ドメイン検証
// ====================
const validateDomain = (req, res, next) => {
  const target = req.query.url || req.headers["x-target-url"];
  if (!target) return res.status(400).json({ error: "Missing target URL" });

  try {
    const { hostname } = new URL(target);
    const isAllowed = WHITELIST.some(domain =>
      hostname === domain || hostname.endsWith(`.${domain}`)
    );
    if (!isAllowed) {
      return res.status(403).json({ error: `Domain '${hostname}' not allowed` });
    }
    req.target = target;
    next();
  } catch {
    return res.status(400).json({ error: "Invalid URL format" });
  }
};

// ====================
// ✅ プロキシ設定
// ====================
app.use(
  "/proxy",
  authenticateJWT,
  validateDomain,
  createProxyMiddleware({
    changeOrigin: true,
    secure: true,
    followRedirects: true,
    logLevel: process.env.NODE_ENV === "production" ? "warn" : "debug",
    onProxyReq: (proxyReq, req) => {
      const targetUrl = new URL(req.target);
      proxyReq.path = targetUrl.pathname + targetUrl.search;
      proxyReq.removeHeader("cookie");
      proxyReq.removeHeader("referer");
      proxyReq.removeHeader("origin");
      proxyReq.setHeader("X-Forwarded-For", req.ip);
      proxyReq.setHeader("X-Forwarded-Proto", req.protocol);
    },
    onProxyRes: (proxyRes) => {
      delete proxyRes.headers["set-cookie"];
      delete proxyRes.headers["x-powered-by"];
    },
    router: req => req.target,
  })
);

// ====================
// ✅ 健康チェック & エラー処理
// ====================
app.get("/", (_, res) => res.status(200).send("✅ Secure Proxy Server Running"));
app.use((err, _, res) => {
  console.error("❌ Proxy Error:", err.message);
  res.status(500).json({ error: "Internal server error" });
});

export default app;
