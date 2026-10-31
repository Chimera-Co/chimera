import { StrictMode } from "react";
import { createRoot } from "react-dom/client";

import "bootstrap/dist/css/bootstrap.css";

import SiteApp from "./SiteApp.jsx";
import { initTheme } from "../themes.js";
import { HashRouter } from "react-router-dom";

// The documentation site (GitHub Pages): the console's Home and Docs pages without the console.
// Hash routes, so every docs URL works on a static host without server-side rewrites.
initTheme();

createRoot(document.getElementById("root")).render(
    <StrictMode>
        <HashRouter>
            <SiteApp />
        </HashRouter>
    </StrictMode>,
);
