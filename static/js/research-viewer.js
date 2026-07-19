(function () {
  const params = new URLSearchParams(window.location.search);
  const slugFromQuery = params.get("slug");
  const normalizedSlug = (slugFromQuery || window.location.pathname.split("/").pop().replace(/\.html$/i, "")).trim();

  const headerEl = document.getElementById("report-title");
  const sourceEl = document.getElementById("report-source");
  const bodyEl = document.getElementById("report-body");

  if (!bodyEl) return;

  if (!normalizedSlug) {
    bodyEl.innerHTML = "<p>Slug missing for this report.</p>";
    return;
  }

  const isAbsoluteOrRoot = (value) => /^(?:[a-z]+:)?\/\//i.test(value) || value.startsWith("/");

  const rewriteAssetPath = (base, value) => {
    if (!value || isAbsoluteOrRoot(value) || value.startsWith("#")) {
      return value;
    }

    const clean = value.replace(/^\.\//, "").replace(/^\.\.\//, "");
    return `/research/${base}/${clean}`;
  };

  const parseFrontMatter = (raw) => {
    const match = raw.match(/^---\r?\n([\s\S]*?)\r?\n---\r?\n?/);
    if (!match) return { metadata: {}, content: raw };

    const block = match[1];
    const content = raw.slice(match[0].length);
    const metadata = {};

    block.split("\n").forEach((line) => {
      const index = line.indexOf(":");
      if (index < 0) return;

      const key = line.slice(0, index).trim().toLowerCase();
      const value = line
        .slice(index + 1)
        .trim()
        .replace(/^"|"$/g, "")
        .replace(/^'|'$/g, "");

      if (key) metadata[key] = value;
    });

    return { metadata, content };
  };

  const fallbackMarkdown = (text) => {
    return text
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/\*\*(.+?)\*\*/g, "<strong>$1</strong>")
      .replace(/`([^`]+)`/g, "<code>$1</code>")
      .replace(/\n{2,}/g, "</p><p>")
      .replace(/\n/g, "<br/>");
  };

  const renderMeta = (meta, fallbackId) => {
    const slugId = fallbackId.replace(/_/g, "-").toUpperCase();
    const displayTitle = meta.title || meta.id || slugId;

    if (headerEl) headerEl.textContent = displayTitle;

    if (document && document.title) {
      document.title = `${displayTitle} | research | c4tz`;
    }

    if (sourceEl) {
      if (meta.source) {
        sourceEl.href = meta.source;
        sourceEl.textContent = "View source";
        sourceEl.hidden = false;
      } else {
        sourceEl.removeAttribute("href");
        sourceEl.hidden = true;
      }
    }
  };

  const loadMarkdown = async (postSlug) => {
    const encodedSlug = encodeURIComponent(postSlug);
    const candidates = [
      `/research/${encodedSlug}.md`,
      `${window.location.pathname.replace(/\\/[^/]*$/i, `/${encodedSlug}.md`)}`,
    ];

    for (const candidate of candidates) {
      const response = await fetch(candidate);
      if (response.ok) {
        return response.text();
      }
    }

    throw new Error("Report not found");
  };

  const applyRelativeAssetRewrite = (container, postSlug) => {
    const images = container.querySelectorAll("img");
    images.forEach((image) => {
      image.setAttribute("src", rewriteAssetPath(postSlug, image.getAttribute("src") || ""));
    });

    container.querySelectorAll("a[href]").forEach((link) => {
      const href = link.getAttribute("href");
      const rewritten = rewriteAssetPath(postSlug, href || "");
      link.setAttribute("href", rewritten);
    });
  };

  const renderMarkdown = (markdown, postSlug) => {
    const parsed = parseFrontMatter(markdown);
    const meta = parsed.metadata;
    const fallbackId = postSlug.replace(/_/g, "-").toUpperCase();

    renderMeta(meta, fallbackId);

    const raw = parsed.content || "";
    if (window.marked) {
      bodyEl.innerHTML = window.marked.parse(raw);
    } else {
      bodyEl.innerHTML = `<p>${fallbackMarkdown(raw)}</p>`;
    }

    applyRelativeAssetRewrite(bodyEl, postSlug);
  };

  loadMarkdown(normalizedSlug)
    .then((markdown) => {
      renderMarkdown(markdown, normalizedSlug);
    })
    .catch(() => {
      if (headerEl) headerEl.textContent = normalizedSlug;
      document.title = `${normalizedSlug} | research | c4tz`;
      if (sourceEl) sourceEl.hidden = true;
      bodyEl.innerHTML = "<p>Impossible to load this report.</p>";
    });
})();
