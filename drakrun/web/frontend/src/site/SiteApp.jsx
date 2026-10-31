import { useEffect } from "react";
import { Link, NavLink, Route, Routes, useLocation } from "react-router-dom";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import {
    faBook,
    faCodeBranch,
    faHouse,
} from "@fortawesome/free-solid-svg-icons";

import "startbootstrap-sb-admin/dist/css/styles.css";
import "../chimera-theme.css";
import "../themes.css";
import "./site.css";
import { ChimeraLogo } from "../ChimeraLogo.jsx";
import { ThemePicker } from "../ThemePicker.jsx";
import HomePage, { REPO_URL } from "../home/HomePage.jsx";
import DocsPage from "../docs/DocsPage.jsx";

function ScrollToTop() {
    const { pathname } = useLocation();
    useEffect(() => {
        window.scrollTo(0, 0);
    }, [pathname]);
    return null;
}

export default function SiteApp() {
    return (
        <div className="chimera-site">
            <ScrollToTop />
            <nav className="sb-topnav navbar navbar-expand chimera-site__nav">
                <Link className="navbar-brand" to="/" title="CHIMERA home">
                    <ChimeraLogo
                        size={34}
                        variant="light"
                        className="chimera-brand-mark"
                    />
                    CHIMERA
                </Link>
                <div className="chimera-site__links">
                    <NavLink to="/" end className="chimera-site__link">
                        <FontAwesomeIcon icon={faHouse} />
                        <span>Home</span>
                    </NavLink>
                    <NavLink to="/docs" className="chimera-site__link">
                        <FontAwesomeIcon icon={faBook} />
                        <span>Docs</span>
                    </NavLink>
                    <a href={REPO_URL} className="chimera-site__link">
                        <FontAwesomeIcon icon={faCodeBranch} />
                        <span>GitHub</span>
                    </a>
                </div>
                <ThemePicker />
            </nav>
            <main className="chimera-site__main">
                <Routes>
                    <Route path="/" element={<HomePage site />} />
                    <Route path="/docs" element={<DocsPage />} />
                    <Route path="/docs/:slug" element={<DocsPage />} />
                    <Route path="*" element={<HomePage site />} />
                </Routes>
            </main>
            <footer className="chimera-site__footer">
                CHIMERA builds on{" "}
                <a href="https://github.com/CERT-Polska/drakvuf-sandbox">
                    DRAKVUF Sandbox
                </a>{" "}
                by CERT Polska and{" "}
                <a href="https://github.com/tklengyel/drakvuf">DRAKVUF</a> by
                Tamas K Lengyel.{" "}
                <a href={REPO_URL}>Source and licence on GitHub</a>.
            </footer>
        </div>
    );
}
