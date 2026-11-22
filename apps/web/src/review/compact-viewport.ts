import {useEffect, useState} from "react";

export const compactViewportMaxWidth = 720;
export const compactViewportQuery = `(max-width: ${compactViewportMaxWidth}px)`;

export function readCompactViewport(): boolean {
  return window.matchMedia(compactViewportQuery).matches;
}

export function useCompactViewport(): boolean {
  const [compactViewport, setCompactViewport] = useState(readCompactViewport);

  useEffect(() => {
    const mediaQuery = window.matchMedia(compactViewportQuery);
    const update = (): void => setCompactViewport(mediaQuery.matches);

    update();
    mediaQuery.addEventListener("change", update);
    return () => mediaQuery.removeEventListener("change", update);
  }, []);

  return compactViewport;
}
