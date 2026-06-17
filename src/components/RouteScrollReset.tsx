import { useEffect, useRef } from "react";
import { useLocation } from "react-router-dom";

export function RouteScrollReset() {
  const { pathname, hash } = useLocation();
  const previousPathname = useRef(pathname);

  useEffect(() => {
    if (previousPathname.current === pathname) return;
    previousPathname.current = pathname;
    if (hash) return;

    window.requestAnimationFrame(() => {
      window.scrollTo({ top: 0, left: 0, behavior: "auto" });
      document.querySelector<HTMLElement>("[data-app-scroll-container]")?.scrollTo({ top: 0, left: 0, behavior: "auto" });
    });
  }, [hash, pathname]);

  return null;
}
