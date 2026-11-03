import { describe, expect, it } from "vitest";

import {
  formatBytes,
  formatDateTime,
  formatDuration,
  formatMs,
  formatNumber,
  formatRelative,
  initials,
  plural,
} from "@/lib/format";

describe("numbers", () => {
  it("groups thousands and handles missing values", () => {
    expect(formatNumber(14923)).toBe("14,923");
    expect(formatNumber(null)).toBe("n/a");
    expect(formatNumber(Number.NaN)).toBe("n/a");
  });
  it("sizes bytes in B, KB and MB", () => {
    expect(formatBytes(812)).toBe("812 B");
    expect(formatBytes(4300)).toBe("4.2 KB");
    expect(formatBytes(12 * 1024 * 1024)).toBe("12 MB");
  });
});

describe("dates", () => {
  const now = new Date("2026-10-28T12:00:00Z");
  it("says how long ago, then falls back to a date", () => {
    expect(formatRelative("2026-10-28T11:59:40Z", now)).toBe("just now");
    expect(formatRelative("2026-10-28T11:55:00Z", now)).toBe("5m ago");
    expect(formatRelative("2026-10-28T09:00:00Z", now)).toBe("3h ago");
    expect(formatRelative("2026-10-26T12:00:00Z", now)).toBe("2d ago");
    expect(formatRelative("2026-09-01T12:00:00Z", now)).toMatch(/Sep 1, 2026/);
    expect(formatRelative(null, now)).toBe("Never");
  });
  it("never throws on bad input", () => {
    expect(formatDateTime("not a date")).toBe("n/a");
    expect(formatDateTime(undefined)).toBe("n/a");
  });
  it("builds avatar initials", () => {
    expect(initials("Avery Chen")).toBe("AC");
    expect(initials("Mei")).toBe("M");
    expect(initials("")).toBe("?");
  });
});

describe("durations and counts", () => {
  it("formats spans from seconds to days", () => {
    expect(formatDuration(45)).toBe("45s");
    expect(formatDuration(240)).toBe("4m");
    expect(formatDuration(5100)).toBe("1h 25m");
    expect(formatDuration(7200)).toBe("2h");
    expect(formatDuration(183_600)).toBe("2d 3h");
    expect(formatDuration(-5)).toBe("0s");
    expect(formatDuration(null)).toBe("n/a");
  });
  it("formats latencies", () => {
    expect(formatMs(320.4)).toBe("320 ms");
    expect(formatMs(1400)).toBe("1.4 s");
    expect(formatMs(undefined)).toBe("n/a");
  });
});

describe("plurals", () => {
  it("counts with the right noun", () => {
    expect(plural(1, "factor")).toBe("1 factor");
    expect(plural(3, "factor")).toBe("3 factors");
    expect(plural(1200, "person", "people")).toBe("1,200 people");
  });
});
