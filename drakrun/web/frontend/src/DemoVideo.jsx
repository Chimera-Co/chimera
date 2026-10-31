/**
 * The 10-minute platform walkthrough (public/chimera-demo.mp4, 720p, with its poster frame). Served from the
 * console itself and from the documentation site, so it plays offline on the sandbox host too.
 */
export const DEMO_VIDEO = "chimera-demo.mp4";
export const DEMO_POSTER = "chimera-demo-poster.jpg";

export function DemoVideo({ caption = true }) {
    const base = import.meta.env.BASE_URL || "/";
    return (
        <figure className="chimera-demo">
            <video
                className="chimera-demo__video"
                controls
                preload="none"
                playsInline
                poster={`${base}${DEMO_POSTER}`}
                aria-label="CHIMERA platform demo video"
            >
                <source src={`${base}${DEMO_VIDEO}`} type="video/mp4" />
                Your browser cannot play this video.{" "}
                <a href={`${base}${DEMO_VIDEO}`}>Download it</a> instead.
            </video>
            {caption && (
                <figcaption className="chimera-demo__caption">
                    Platform walkthrough (10 min): uploading a sample, the live
                    VM view, the report with its verdict and threat
                    intelligence, static analysis and the evasion self-test.
                </figcaption>
            )}
        </figure>
    );
}
