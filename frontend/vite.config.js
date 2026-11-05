import { execSync } from "node:child_process";
import { defineConfig } from "vite";
import { icpBindgen } from "@icp-sdk/bindgen/plugins/vite";

const CANISTER_NAME = "key_exchange";
const ENVIRONMENT = process.env.ICP_ENVIRONMENT || "test";

function getDevServerConfig() {
  let networkStatus;
  try {
    networkStatus = JSON.parse(
      execSync(`icp network status -e ${ENVIRONMENT} --json`, {
        encoding: "utf-8",
        stdio: "pipe",
      }),
    );
  } catch (error) {
    console.error(
      `No network running for environment "${ENVIRONMENT}". Start it and deploy first:\n` +
        `  icp network start ${ENVIRONMENT} -d && icp deploy -e ${ENVIRONMENT}`,
    );
    process.exit(1);
  }

  let canisterId;
  try {
    canisterId = execSync(
      `icp canister status ${CANISTER_NAME} -e ${ENVIRONMENT} -i`,
      { encoding: "utf-8", stdio: "pipe" },
    ).trim();
  } catch {
    console.error(
      `Canister "${CANISTER_NAME}" is not deployed in environment "${ENVIRONMENT}". Deploy it first:\n` +
        `  icp deploy -e ${ENVIRONMENT}`,
    );
    process.exit(1);
  }

  return {
    headers: {
      "Set-Cookie": `ic_env=${encodeURIComponent(
        `ic_root_key=${networkStatus.root_key}&PUBLIC_CANISTER_ID:${CANISTER_NAME}=${canisterId}`,
      )}; SameSite=Lax;`,
    },
    proxy: {
      "/api": { target: networkStatus.api_url, changeOrigin: true },
    },
  };
}

export default defineConfig(({ command }) => ({
  base: "./",
  plugins: [
    icpBindgen({
      didFile: "../key_exchange.did",
      outDir: "./src/bindings",
    }),
  ],
  optimizeDeps: {
    esbuildOptions: { define: { global: "globalThis" } },
  },
  server: command === "serve" ? getDevServerConfig() : undefined,
}));
