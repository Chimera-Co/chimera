import { expect, it } from "vitest";
import { render, screen, within } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import HomePage from "./HomePage.jsx";
import { PIPELINE_STEPS } from "../docs/diagrams.jsx";
import { PAGES } from "../docs/pages.js";

const home = () =>
    render(
        <MemoryRouter>
            <HomePage />
        </MemoryRouter>,
    );

it("introduces CHIMERA and PERDEDOR with ways into the app", () => {
    home();
    expect(
        screen.getByRole("heading", { level: 1, name: "CHIMERA" }),
    ).toBeInTheDocument();
    expect(
        screen.getByRole("heading", { name: "What CHIMERA is" }),
    ).toBeInTheDocument();
    expect(
        screen.getByRole("heading", { name: "PERDEDOR" }),
    ).toBeInTheDocument();
    expect(
        screen.getByRole("link", { name: /Upload a sample/ }),
    ).toHaveAttribute("href", "/upload");
    expect(screen.getByRole("link", { name: /^Analyses$/ })).toHaveAttribute(
        "href",
        "/",
    );
    expect(
        screen.getByRole("link", { name: /^Documentation$/ }),
    ).toHaveAttribute("href", "/docs");
    expect(
        screen.getByRole("link", { name: /Run a verification scan/ }),
    ).toHaveAttribute("href", "/evasion");
});

it("shows the pipeline from upload to report in order", () => {
    home();
    const steps = within(
        screen.getByRole("list", { name: "Analysis pipeline" }),
    ).getAllByRole("listitem");
    expect(steps).toHaveLength(PIPELINE_STEPS.length);
    expect(
        steps.map(
            (s) => s.querySelector(".chimera-pipeline__name").textContent,
        ),
    ).toEqual([
        "Upload",
        "Static pass",
        "Detonation",
        "Post-processing",
        "Verdict",
        "Threat intel",
        "Report",
    ]);
});

it("links only to documentation pages that exist", () => {
    home();
    const slugs = new Set(PAGES.map((p) => `/docs/${p.slug}`));
    const docLinks = screen
        .getAllByRole("link")
        .map((a) => a.getAttribute("href"))
        .filter((href) => href.startsWith("/docs/"));
    expect(docLinks.length).toBeGreaterThan(0);
    for (const href of docLinks) expect(slugs.has(href), href).toBe(true);
});

it("shows the demo video with a local source and poster", () => {
    home();
    expect(
        screen.getByRole("heading", { name: "See it in action" }),
    ).toBeInTheDocument();
    const video = screen.getByLabelText("CHIMERA platform demo video");
    expect(video).toHaveAttribute("poster", "/chimera-demo-poster.jpg");
    expect(video.querySelector("source")).toHaveAttribute(
        "src",
        "/chimera-demo.mp4",
    );
});

it("documentation-site variant links to GitHub instead of the console", () => {
    render(
        <MemoryRouter>
            <HomePage site />
        </MemoryRouter>,
    );
    expect(screen.queryByRole("link", { name: /Upload a sample/ })).toBeNull();
    expect(screen.queryByRole("link", { name: /^Analyses$/ })).toBeNull();
    expect(
        screen.getByRole("button", { name: /Watch the demo/ }),
    ).toBeInTheDocument();
    expect(
        screen.getByRole("link", { name: /Source on GitHub/ }),
    ).toHaveAttribute("href", "https://github.com/Chimera-Co/chimera");
    expect(
        screen.getByRole("link", { name: /PERDEDOR on GitHub/ }),
    ).toHaveAttribute("href", "https://github.com/Chimera-Co/perdedor");
    expect(
        screen.getByRole("link", { name: /^Documentation$/ }),
    ).toHaveAttribute("href", "/docs");
});
