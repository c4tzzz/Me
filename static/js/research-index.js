(function () {
  const mount = document.getElementById("research-list");
  if (!mount) return;

  const api = {
    fallbackFile: "/static/data/research/index.json",
  };

  const githubContext = () => {
    const host = window.location.hostname;
    if (!host.endsWith("github.io")) return null;

    const owner = (
      document.querySelector('meta[name="github-owner"]')?.content ||
      host.replace(".github.io", "")
    ).trim();

    const pathParts = window.location.pathname.split("/").filter(Boolean);
    const repo =
      (document.querySelector('meta[name="github-repo"]')?.content || pathParts[0] || "").trim();

    if (!owner || !repo) return null;
    return { owner, repo };
  };

  const escapeHtml = (value) =>
    String(value || "")
      .replaceAll("&", "&amp;")
      .replaceAll("<", "&lt;")
      .replaceAll(">", "&gt;")
      .replaceAll('"', "&quot;")
      .replaceAll("'", "&#39;");

  const sanitizeSlug = (value, fallback = "") => {
    return String(value || fallback)
      .trim()
      .replace(/\.md$/i, "")
      .replace(/\.html$/i, "");
  };

  const deriveId = (slug) => {
    const normalized = sanitizeSlug(slug).toUpperCase().replace(/_/g, "-");
    return normalized;
  };

  const normalizeType = (value) => String(value || "CVE").trim().toUpperCase();

  const normalizePath = (rawPath, slug) => {
    const path = String(rawPath || "").trim();
    if (!path) return `/research/view.html?slug=${encodeURIComponent(slug)}`;

    const isAbsoluteUrl = /^(?:[a-z]+:)?\/\//i.test(path);
    if (isAbsoluteUrl || path.startsWith("/")) return path;

    if (path.startsWith("view.html?") || path.startsWith("?")) {
      return `/research/${path}`;
    }

    if (/\.md$/i.test(path) || /\.html$/i.test(path)) {
      const fromFile = sanitizeSlug(path.split("/").pop());
      return `/research/view.html?slug=${encodeURIComponent(fromFile || slug)}`;
    }

    return `/research/${path}`;
  };

  const firstParagraphFromBody = (text) => {
    const normalized = String(text || "").replace(/\r/g, "").trim();
    const blocks = normalized.split(/\n{2,}/);

    for (const block of blocks) {
      const cleaned = block
        .replace(/^#+\s*/gm, "")
        .replace(/\[([^\]]+)\]\([^\)]+\)/g, "$1")
        .replace(/`([^`]+)`/g, "$1")
        .replace(/\s+/g, " ")
        .trim();
      if (!cleaned) continue;

      return cleaned.length > 220 ? `${cleaned.slice(0, 217)}...` : cleaned;
    }

    return "Read the report for details.";
  };

  const parseFrontMatter = (raw) => {
    const match = raw.match(/^---\r?\n([\s\S]*?)\r?\n---\r?\n?/);
    if (!match) {
      return { metadata: {}, body: raw };
    }

    const metadata = {};
    match[1].split("\n").forEach((line) => {
      const index = line.indexOf(":");
      if (index < 0) return;
      const key = line.slice(0, index).trim().toLowerCase();
      const val = line
        .slice(index + 1)
        .trim()
        .replace(/^"|"$/g, "")
        .replace(/^'|'$/g, "");
      if (key) metadata[key] = val;
    });

    return {
      metadata,
      body: raw.slice(match[0].length),
    };
  };

  const parseMarkdownMetadata = (raw, defaultSlug) => {
    const parsed = parseFrontMatter(raw);
    const parsedSlug = sanitizeSlug(defaultSlug);

    const entry = {
      slug: parsedSlug,
      id: deriveId(parsedSlug),
      title: deriveId(parsedSlug),
      excerpt: "",
      type: "CVE",
      path: `/research/view.html?slug=${encodeURIComponent(parsedSlug)}`,
    };

    const meta = parsed.metadata;
    Object.entries(meta).forEach(([key, value]) => {
      if (value) entry[key] = value;
    });

    entry.slug = sanitizeSlug(entry.slug || entry.id);
    entry.id = deriveId(entry.id || entry.slug);
    entry.title = entry.title || entry.id;
    entry.excerpt = entry.excerpt || entry.summary || "";
    entry.type = normalizeType(entry.type || (entry.id.startsWith("CVE") ? "CVE" : "RESEARCH"));
    entry.path = normalizePath(entry.path, entry.slug);

    return entry;
  };

  const card = (entry) => {
    const node = document.createElement("a");
    node.className = "card";
    node.href = normalizePath(entry.path, entry.slug);

    const id = entry.id || deriveId(entry.slug);
    const title = entry.title || id;
    const excerpt = entry.excerpt;
    const heading = title === id ? id : `${id} — ${title}`;

    node.innerHTML = `
      <h2>${escapeHtml(heading)}</h2>
      ${excerpt ? `<p>${escapeHtml(excerpt)}</p>` : ""}
    `;

    return node;
  };

  const section = (label, entries) => {
    if (!Array.isArray(entries) || !entries.length) return;

    if (label && String(label).trim().toLowerCase() !== "cve") {
      const heading = document.createElement("p");
      heading.className = "meta";
      heading.textContent = label;
      mount.appendChild(heading);
    }

    const list = document.createElement("section");
    list.className = "list";
    entries.forEach((entry) => list.appendChild(card(entry)));
    mount.appendChild(list);
  };

  const sectionByType = (entries) => {
    const buckets = {
      CVE: [],
      DRAFT: [],
      RESEARCH: [],
    };

    entries.forEach((entry) => {
      const type = normalizeType(entry.type);
      if (type === "CVE" || type === "DRAFT") {
        buckets[type].push(entry);
        return;
      }
      buckets.RESEARCH.push(entry);
    });

    return buckets;
  };

  const sortEntries = (entries) => {
    return entries.sort((left, right) => {
      const lDate = String(left.published || left.date || "");
      const rDate = String(right.published || right.date || "");
      if (lDate && rDate && lDate !== rDate) return rDate.localeCompare(lDate);
      return (left.id || "").localeCompare(right.id || "");
    });
  };

  const render = (entries) => {
    mount.innerHTML = "";
    const grouped = sectionByType(entries);
    section("CVE", grouped.CVE);
    section("Draft", grouped.DRAFT);
    section("Research", grouped.RESEARCH);

    if (!mount.children.length) {
      mount.innerHTML = '<p class="meta">Aucun report disponible.</p>';
    }
  };

  const fromFallbackJson = () => {
    return fetch(api.fallbackFile)
      .then((response) => (response.ok ? response.json() : Promise.reject()))
      .then((payload) => {
        const raw = [
          ...(Array.isArray(payload?.cve) ? payload.cve : []),
          ...(Array.isArray(payload?.draft) ? payload.draft : []),
          ...(Array.isArray(payload?.entries) ? payload.entries : []),
        ];

        const entries = raw.map((item) => {
          const metaSlug = sanitizeSlug(item?.slug || item?.id || item?.title || "");
          const fallbackMarkdown = item?.content ? String(item.content) : "";
          const built = parseMarkdownMetadata(fallbackMarkdown, metaSlug);
          return {
            ...built,
            ...item,
            slug: sanitizeSlug(item?.slug || built.slug),
            type: normalizeType(item?.type || built.type),
          };
        });

        return entries;
      });
  };

  const fromMarkdownDirectory = async () => {
    const ctx = githubContext();
    if (!ctx) return null;

    const response = await fetch(
      `https://api.github.com/repos/${ctx.owner}/${ctx.repo}/contents/research?ref=main`
    );
    if (!response.ok) return null;

    const payload = await response.json();
    if (!Array.isArray(payload)) return null;

    const mdFiles = payload.filter(
      (item) => item?.type === "file" && String(item?.name || "").toLowerCase().endsWith(".md")
    );

    const entries = await Promise.all(
      mdFiles.map(async (file) => {
        const slug = sanitizeSlug(file?.name || "");
        const rawUrl = file?.download_url;

        if (!rawUrl) return parseMarkdownMetadata("", slug);

        try {
          const bodyRes = await fetch(rawUrl);
          const raw = bodyRes.ok ? await bodyRes.text() : "";
          return parseMarkdownMetadata(raw, slug);
        } catch {
          return parseMarkdownMetadata("", slug);
        }
      })
    );

    return sortEntries(entries);
  };

  fromMarkdownDirectory()
    .then((entries) => {
      if (Array.isArray(entries) && entries.length) return entries;
      return fromFallbackJson();
    })
    .then((entries) => {
      if (Array.isArray(entries) && entries.length) {
        render(sortEntries(entries));
      } else {
        mount.innerHTML = '<p class="meta">Aucun report disponible.</p>';
      }
    })
    .catch(() => {
      fromFallbackJson()
        .then((entries) => {
          if (Array.isArray(entries) && entries.length) {
            render(sortEntries(entries));
          } else {
            mount.innerHTML = '<p class="meta">Impossible de charger la liste des reports.</p>';
          }
        })
        .catch(() => {
          mount.innerHTML = '<p class="meta">Impossible de charger la liste des reports.</p>';
        });
    });
})();
