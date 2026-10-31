/* global process */
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Documentation site for GitHub Pages: `npm run build:site` -> dist-site/ (index.html, relative asset paths).
export default defineConfig({
    plugins: [react()],
    base: "./",
    define: {
        __APP_VERSION__: JSON.stringify(process.env.npm_package_version),
    },
    build: {
        outDir: "dist-site",
        emptyOutDir: true,
        rollupOptions: { input: "site.html" },
    },
});
