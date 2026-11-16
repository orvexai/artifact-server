(() => {
  let savedTheme = null;
  try {
    savedTheme = window.localStorage.getItem("artifact-review-theme");
  } catch {
    // Storage can be unavailable; continue with the device preference.
  }

  const theme = savedTheme === "dawn" || savedTheme === "moon"
    ? savedTheme
    : window.matchMedia("(prefers-color-scheme: dark)").matches ? "moon" : "dawn";
  const root = document.documentElement;
  root.dataset.reviewTheme = theme;
  root.dataset.theme = theme === "dawn" ? "light" : "dark";
  root.classList.toggle("dark", theme === "moon");
})();
