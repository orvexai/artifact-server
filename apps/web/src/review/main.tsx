import { StrictMode } from "react";
import { createRoot } from "react-dom/client";

import { installDraftGuard } from "@/components/comments/comment-drafts";

import { ReviewApp } from "./review-app.tsx";
import "../brand/houston/houston-loader-define.ts";
import "../index.css";
import "./review.css";

// Lives for the whole session, above every route: the leave prompt and the
// logout purge must not depend on which screen is mounted.
installDraftGuard();

const initialTheme = readInitialTheme();
document.documentElement.dataset["reviewTheme"] = initialTheme;
document.documentElement.dataset["theme"] = initialTheme === "dawn" ? "light" : "dark";
document.documentElement.classList.toggle("dark", initialTheme === "moon");

const rootElement = document.querySelector("#review-root");

if (!(rootElement instanceof HTMLElement)) {
  throw new Error("Houston Artifacts could not find its root element.");
}

createRoot(rootElement).render(
  <StrictMode>
    <ReviewApp />
  </StrictMode>,
);

function readInitialTheme(): "dawn" | "moon" {
  let savedTheme: string | null = null;
  try {
    savedTheme = window.localStorage.getItem("artifact-review-theme");
  } catch {
    // Storage can be unavailable; continue with the device preference.
  }
  if (savedTheme === "dawn" || savedTheme === "moon") return savedTheme;
  return window.matchMedia("(prefers-color-scheme: dark)").matches ? "moon" : "dawn";
}
