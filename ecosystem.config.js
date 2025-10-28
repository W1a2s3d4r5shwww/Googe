// ecosystem.config.js
export default {
  apps: [
    {
      name: "kaihi-proxy",
      script: "./index.js",
      instances: "max",
      exec_mode: "cluster",
      env: {
        NODE_ENV: "production",
        PORT: 3000
      }
    }
  ]
};
