// lib/whitelist.js
export const WHITELIST = [
  "api.openai.com",
  "fonts.googleapis.com",
  "fonts.gstatic.com",
  "raw.githubusercontent.com",
  "githubusercontent.com",
  "api.github.com",
  "maps.googleapis.com",
  "storage.googleapis.com",
  "jsonplaceholder.typicode.com",
  ...(process.env.EXTRA_WHITELIST?.split(",") || []),
];
