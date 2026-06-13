import React from "react";

function normalizeOs(value) {
  const os = String(value || "").toLowerCase();
  if (os.includes("linux") || os.includes("ubuntu") || os.includes("debian") || os.includes("kali") || os.includes("centos") || os.includes("fedora") || os.includes("red hat") || os.includes("rhel")) {
    return "linux";
  }
  if (os.includes("windows")) return "windows";
  if (os.includes("mac") || os.includes("darwin") || os.includes("os x")) return "mac";
  return "unknown";
}

function LogoGlyph({ kind }) {
  if (kind === "windows") {
    return (
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6">
        <rect x="3" y="3" width="8" height="8" rx="1" />
        <rect x="13" y="3" width="8" height="8" rx="1" />
        <rect x="3" y="13" width="8" height="8" rx="1" />
        <rect x="13" y="13" width="8" height="8" rx="1" />
      </svg>
    );
  }
  if (kind === "linux") {
    return (
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6">
        <rect x="4" y="5" width="16" height="12" rx="2" />
        <path d="M8 14h8" />
        <path d="M7 9h5" />
        <path d="m7 9 2 2-2 2" />
      </svg>
    );
  }
  if (kind === "mac") {
    return (
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6">
        <rect x="5" y="4" width="14" height="12" rx="2" />
        <path d="M9 20h6" />
        <path d="M12 16v4" />
      </svg>
    );
  }
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6">
      <circle cx="12" cy="12" r="8" />
      <path d="M8 12h8" />
      <path d="M12 8v8" />
    </svg>
  );
}

export default function OsLogo({ osName, className = "h-4 w-4", title = "" }) {
  const kind = normalizeOs(osName);
  const tintClass =
    kind === "windows"
      ? "text-os-windows"
      : kind === "linux"
        ? "text-os-linux"
        : kind === "mac"
          ? "text-os-macos"
          : "text-text-tertiary";

  return (
    <span className={`inline-flex items-center justify-center ${className} ${tintClass}`} title={title || osName || "unknown"}>
      <LogoGlyph kind={kind} />
    </span>
  );
}
