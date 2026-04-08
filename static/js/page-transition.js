(function () {
  const reduced =
    window.matchMedia &&
    window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  if (reduced) return;

  const html = document.documentElement;
  const body = document.body;
  if (!body) return;

  let overlay = document.getElementById("page-transition-overlay");
  if (!overlay) {
    overlay = document.createElement("div");
    overlay.id = "page-transition-overlay";
    body.appendChild(overlay);
  }

  html.classList.add("has-page-transition", "page-fade-in");

  requestAnimationFrame(() => {
    requestAnimationFrame(() => {
      html.classList.remove("page-fade-in");
    });
  });

  function shouldHandle(link, evt) {
    if (!link) return false;
    if (link.target && link.target !== "_self") return false;
    if (link.hasAttribute("download")) return false;
    if (link.getAttribute("rel") === "external") return false;
    if (evt.metaKey || evt.ctrlKey || evt.shiftKey || evt.altKey) return false;

    const href = link.getAttribute("href") || "";
    if (!href || href.startsWith("#")) return false;

    const url = new URL(link.href, window.location.href);
    if (url.origin !== window.location.origin) return false;
    if (url.href === window.location.href) return false;

    return true;
  }

  document.addEventListener("click", (evt) => {
    const link = evt.target.closest("a[href]");
    if (!shouldHandle(link, evt)) return;

    evt.preventDefault();
    html.classList.add("page-fade-out");

    window.setTimeout(() => {
      window.location.href = link.href;
    }, 190);
  });

  window.addEventListener("pageshow", () => {
    html.classList.remove("page-fade-out");
    html.classList.remove("page-fade-in");
  });
})();
