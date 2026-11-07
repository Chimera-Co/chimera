import { describe, expect, it } from "vitest";
import { formatSandbox, isStaticRecord } from "./formatUtils.js";

describe("formatSandbox", () => {
    it("names the guest OS and VM", () => {
        expect(
            formatSandbox({ options: { guest_os: "linux" }, vm_id: 2 }),
        ).toBe("Debian 12 (Linux) · vm-2");
        expect(
            formatSandbox({ options: { guest_os: "windows" }, vm_id: 1 }),
        ).toBe("Windows 10 · vm-1");
    });

    it("names the Android run and keeps static-only records plain", () => {
        expect(
            formatSandbox({
                options: { guest_os: "android", mode: "combined" },
            }),
        ).toBe("Android 9 (MobSF)");
        expect(
            formatSandbox({
                options: { guest_os: "ios", mode: "static-only" },
            }),
        ).toBe("static only");
    });

    it("treats analyses without guest_os as Windows", () => {
        expect(formatSandbox({ options: {} })).toBe("Windows 10");
    });
});

describe("isStaticRecord", () => {
    it("is true for static-only uploads and every mobile app", () => {
        expect(isStaticRecord({ options: { mode: "static-only" } })).toBe(true);
        expect(
            isStaticRecord({
                options: { mode: "combined", guest_os: "android" },
            }),
        ).toBe(true);
        expect(
            isStaticRecord({
                options: { mode: "combined", guest_os: "windows" },
            }),
        ).toBe(false);
        expect(isStaticRecord({})).toBe(false);
    });
});
