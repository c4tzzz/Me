(function () {
  const REDUCED =
    window.matchMedia &&
    window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  const CAT_BASE = [
    "          )",
    "    )   (    )",
    "  (           (",
    "     _.---._",
    " .-'/\\_/\\  ~~`-. _.------------.",
    "(  ( \"§\" )  ~ ~ )-.___________.'",
    "|`-._  ~ ~  _.-'|",
    "|    `\"\"\"\"\"'    |",
    "|               |",
    "|               |",
    " `-._       _.-'",
    "     `\"\"\"\"\"'"
  ];

  const FIRE_BASE = [
    "    ,.   (   .      )        .      \"",
    "   (\"     )  )'     ,'        )  . (`     '`",
    " .; )  ' (( (\" )    ;(,     ((  (  ;)  \"  )\"",
    " _\"., ,._'_.,)_(..,( . )_  _' )_') (. _..( '.."
  ];

  function clamp(v, min, max) {
    return Math.max(min, Math.min(max, v));
  }

  function parseNumber(v, fallback) {
    const n = Number(v);
    return Number.isFinite(n) ? n : fallback;
  }

  function withUnit(v, fallback) {
    if (!v) return fallback;
    return /[a-z%]+$/i.test(v) ? v : v + "px";
  }

  class AsciiCliBanner {
    constructor(root) {
      this.root = root;
      this.raf = 0;
      this.start = performance.now();
      this.lastFrame = 0;
      this.opts = this.parseOptions();
      this.catWidth = CAT_BASE.reduce((max, line) => Math.max(max, line.length), 0);
      this.fireWidth = this.opts.fireWidth;
      this.frameWidth = Math.max(this.catWidth + 20, this.fireWidth + 30, 76);
      this.fireDrift = 0;
      this.firePalette = " .`'^,:;i!l*+xX$#@";
      this.sway = 0;
      this.swayVel = 0;
      this.fireScale = 1;
      this.nextFireUpdate = 0;
      this.cachedFire = [];
      this.backFireDrift = 0;
      this.backFireScale = 1;
      this.nextBackFireUpdate = 0;
      this.cachedBackFire = [];
      this.eye = "v";
      this.nextEyeSwitch = 0;
      this.eyePool = ["o", "o", "o", "O", "^", "v", "<", ">", ".", "*"];

      this.pre = root.querySelector(".ascii-cli-banner-pre");
      if (!this.pre) {
        this.pre = document.createElement("pre");
        this.pre.className = "ascii-cli-banner-pre";
        root.appendChild(this.pre);
      }

      const fallback = root.querySelector(".ascii-cli-banner-fallback");
      if (fallback) fallback.style.display = "none";
      this.root.classList.add("ascii-ready");

      this.resize();
      this.resizeObs = new ResizeObserver(() => this.resize());
      this.resizeObs.observe(this.root);

      if (REDUCED) {
        this.pre.textContent = this.renderFrame(0);
      } else {
        this.loop = this.loop.bind(this);
        this.raf = requestAnimationFrame(this.loop);
      }
    }

    parseOptions() {
      const ds = this.root.dataset;
      const speed = clamp(parseNumber(ds.speed, 1.0), 0.2, 4);
      const fps = clamp(parseNumber(ds.fps, 24), 6, 60);
      const opacity = clamp(parseNumber(ds.opacity, 0.95), 0, 1);
      const glow = clamp(parseNumber(ds.glow, 0.16), 0, 1);
      const fireHeight = Math.round(clamp(parseNumber(ds.fireHeight, 8), 4, 22));
      const fireWidth = Math.round(clamp(parseNumber(ds.fireWidth, 22), 14, 40));
      const fireShift = clamp(parseNumber(ds.fireShift, -6), -16, 8);
      const size = withUnit(ds.size, "min(42vw, 400px)");
      const color = ds.color || "#d8dce6";

      this.root.style.setProperty("--ascii-banner-size", size);
      this.root.style.setProperty("--ascii-banner-color", color);
      this.root.style.setProperty("--ascii-banner-opacity", String(opacity));
      this.root.style.setProperty("--ascii-banner-glow-blur", (4 + glow * 12).toFixed(2) + "px");
      this.root.style.setProperty("--ascii-banner-glow-alpha", (0.03 + glow * 0.18).toFixed(3));

      return { speed, fps, opacity, fireHeight, fireWidth, fireShift };
    }

    resize() {
      const w = Math.max(280, this.root.clientWidth || 280);
      const fontSize = clamp(w / (this.catWidth * 0.52), 8.4, 16.8);
      this.pre.style.fontSize = fontSize.toFixed(2) + "px";
    }

    catLines(t) {
      if (t >= this.nextEyeSwitch) {
        const mood = Math.random();
        if (mood < 0.14) {
          this.eye = "-";
          this.nextEyeSwitch = t + (0.08 + Math.random() * 0.08) / Math.max(0.45, this.opts.speed);
        } else if (mood < 0.2) {
          this.eye = "_";
          this.nextEyeSwitch = t + (0.08 + Math.random() * 0.08) / Math.max(0.45, this.opts.speed);
        } else {
          this.eye = this.eyePool[Math.floor(Math.random() * this.eyePool.length)];
          this.nextEyeSwitch = t + (0.22 + Math.random() * 0.92) / Math.max(0.45, this.opts.speed);
        }
      }
      const lines = CAT_BASE.map((line) => line.replace("§", this.eye));
      return this.applyBoiling(this.applySteam(lines, t), t);
    }

    applySteam(lines, t) {
      const out = lines.map((line) => line.split(""));
      const steamRows = [0, 1, 2];
      const center = Math.round(this.findPotCenter(lines));
      const plumeBases = [-10, -4, 2, 8];
      const speed = 0.65 + this.opts.speed * 0.35;
      const phase = t * speed;
      const glyphCycle = [")", "(", "'", "`", ")", "("];

      for (const row of steamRows) {
        if (!out[row]) continue;
        for (let i = 0; i < out[row].length; i++) {
          if (out[row][i] !== " ") out[row][i] = " ";
        }
      }

      for (let i = 0; i < plumeBases.length; i++) {
        const base = center + plumeBases[i];
        const lowActive = Math.sin(phase * 1.12 + i * 0.9) > -0.15;
        const midActive = Math.sin(phase * 1.44 + i * 1.1) > -0.24;
        const topActive = Math.sin(phase * 1.8 + i * 1.35) > -0.36;

        const lowCol = base + Math.round(Math.sin(phase + i * 0.7) * 1.2);
        const midCol = lowCol + Math.round(Math.sin(phase * 1.35 + i) * 1.1);
        const topCol = midCol + Math.round(Math.sin(phase * 1.75 + i * 1.2) * 1.0);

        if (lowActive && out[2] && lowCol > 0 && lowCol < out[2].length - 1) {
          out[2][lowCol] = glyphCycle[(i + Math.floor(phase)) % glyphCycle.length];
        }
        if (midActive && out[1] && midCol > 0 && midCol < out[1].length - 1) {
          out[1][midCol] = glyphCycle[(i + 2 + Math.floor(phase * 1.2)) % glyphCycle.length];
        }
        if (topActive && out[0] && topCol > 0 && topCol < out[0].length - 1) {
          out[0][topCol] = glyphCycle[(i + 4 + Math.floor(phase * 1.4)) % glyphCycle.length];
        }
      }

      return out.map((chars) => chars.join(""));
    }

    applyBoiling(lines, t) {
      const out = lines.map((line) => line.split(""));
      const phase = Math.floor(t * 1.6);

      const waterRow = out.findIndex((chars) => {
        const s = chars.join("");
        return s.includes("|") && (s.includes("\"") || s.includes("'") || s.includes("`") || s.includes("~") || s.includes("°"));
      });
      if (waterRow !== -1) {
        const row = out[waterRow];
        const left = row.indexOf("|");
        const right = row.lastIndexOf("|");
        if (left >= 0 && right - left > 2) {
          for (let i = left + 1; i < right; i++) {
            if (row[i] === "\"" || row[i] === "'" || row[i] === "`" || row[i] === "~" || row[i] === "°") {
              row[i] = " ";
            }
          }
          const span = right - left - 1;
          const posA = left + 1 + (phase % span);
          const posB = left + 1 + ((phase + Math.floor(span / 2)) % span);
          row[posA] = "~";
          row[posB] = phase % 3 === 0 ? "°" : "~";
        }
      }

      return out.map((chars) => chars.join(""));
    }

    shiftLine(line, shift) {
      if (!shift) return line;
      if (shift > 0) return " ".repeat(shift) + line;
      return line.slice(Math.min(-shift, line.length));
    }

    scaleLine(line, scale) {
      const safeScale = clamp(scale, 0.72, 1.26);
      const src = line || "";
      const targetLen = Math.max(8, Math.round(src.length * safeScale));
      if (!src.length || targetLen === src.length) return src;
      let out = "";
      for (let i = 0; i < targetLen; i++) {
        const srcIndex = Math.min(src.length - 1, Math.floor(i / safeScale));
        out += src[srcIndex] || " ";
      }
      return out;
    }

    findPotCenter(lines) {
      const centers = [];
      for (const line of lines) {
        const left = line.indexOf("|");
        const right = line.lastIndexOf("|");
        if (left >= 0 && right > left) centers.push((left + right) / 2);
      }
      if (centers.length) {
        const sum = centers.reduce((a, b) => a + b, 0);
        return sum / centers.length;
      }
      const first = lines.find((line) => /\S/.test(line)) || "";
      const l = first.search(/\S/);
      if (l < 0) return Math.max(0, this.catWidth / 2);
      let r = first.length - 1;
      while (r >= 0 && first[r] === " ") r--;
      return (l + Math.max(l, r)) / 2;
    }

    alignLinesToCenter(lines, targetCenter, jitter = 0) {
      return lines.map((line) => {
        const left = line.search(/\S/);
        if (left < 0) return line;
        let right = line.length - 1;
        while (right >= 0 && line[right] === " ") right--;
        const center = (left + Math.max(left, right)) / 2;
        const extra = jitter ? Math.round((Math.random() - 0.5) * jitter) : 0;
        const shift = Math.round(targetCenter - center) + extra;
        return this.shiftLine(line, shift);
      });
    }

    fireLines(t, width, height) {
      const updateInterval = 0.32 / Math.max(0.5, this.opts.speed);
      if (this.cachedFire.length && t < this.nextFireUpdate) {
        return this.cachedFire;
      }
      this.nextFireUpdate = t + updateInterval;

      const flameSpeed = Math.max(0.14, this.opts.speed * 0.32);
      this.fireDrift = clamp(
        this.fireDrift * 0.95 + (Math.random() - 0.5) * (0.55 * flameSpeed),
        -2.4,
        2.4
      );
      this.fireScale = clamp(
        this.fireScale * 0.96 + 0.04 + (Math.random() - 0.5) * 0.022,
        0.89,
        1.12
      );
      const rows = [];
      const pulseBoost = Math.random() < 0.11 ? 1 : 0;
      const extraRows = Math.round((height / 8) * (0.75 + Math.random() * 0.42));
      const targetRows = clamp(4 + extraRows + pulseBoost, 4, Math.min(7, height + 1));
      const widthScale = (0.78 + Math.random() * 0.19) * this.fireScale;

      for (let y = 0; y < targetRows; y++) {
        const src = FIRE_BASE[Math.min(FIRE_BASE.length - 1, y)];
        const rowScale = widthScale + y * (0.01 + Math.random() * 0.01);
        const scaled = this.scaleLine(src, rowScale);
        const chars = scaled.split("");
        for (let i = 0; i < chars.length; i++) {
          const ch = chars[i];
          if (ch === " " || ch === "." || ch === "," || ch === "'" || ch === "`") {
            if (Math.random() < 0.014 + y * 0.006 + Math.random() * 0.009) {
              chars[i] = [".", ",", "'", "`", "(", ")", ";"][Math.floor(Math.random() * 7)];
            }
          }
          if ((ch === "(" || ch === ")" || ch === ";") && Math.random() < 0.012 + y * 0.005 + Math.random() * 0.006) {
            chars[i] = ["(", ")", ";", ".", ","][Math.floor(Math.random() * 5)];
          }
        }
        let line = chars.join("");
        const edgeTrim = Math.max(0, Math.round((1 - this.fireScale) * 4 + (Math.random() < 0.06 ? 1 : 0)));
        if (edgeTrim > 0 && line.length > edgeTrim * 2 + 4) {
          line = line.slice(edgeTrim, line.length - edgeTrim);
        }
        const rowDrift = this.fireDrift + (Math.random() - 0.5) * (0.65 + y * 0.2);
        const shift = Math.round(rowDrift);
        if (shift > 0) line = " ".repeat(shift) + line;
        if (shift < 0) line = line.slice(Math.min(-shift, line.length));
        rows.push(line);
      }
      this.cachedFire = rows;
      return rows;
    }

    backFireLines(t, width, height) {
      const updateInterval = 0.45 / Math.max(0.5, this.opts.speed);
      if (this.cachedBackFire.length && t < this.nextBackFireUpdate) {
        return this.cachedBackFire;
      }
      this.nextBackFireUpdate = t + updateInterval;

      const backSpeed = Math.max(0.06, this.opts.speed * 0.15);
      this.backFireDrift = clamp(
        this.backFireDrift * 0.96 + (Math.random() - 0.5) * (0.35 * backSpeed),
        -1.9,
        1.9
      );
      this.backFireScale = clamp(
        this.backFireScale * 0.98 + 0.02 + (Math.random() - 0.5) * 0.012,
        0.9,
        1.05
      );

      const rows = [];
      const targetRows = clamp(3 + Math.round((height / 10) * (0.56 + Math.random() * 0.34)), 3, 5);
      const widthScale = (0.82 + Math.random() * 0.16) * this.backFireScale;

      for (let y = 0; y < targetRows; y++) {
        const src = FIRE_BASE[Math.min(FIRE_BASE.length - 1, y)];
        const rowScale = widthScale + y * 0.01;
        const scaled = this.scaleLine(src, rowScale);
        const chars = scaled.split("");
        for (let i = 0; i < chars.length; i++) {
          const ch = chars[i];
          if ((ch === " " || ch === "." || ch === ",") && Math.random() < 0.008 + y * 0.003) {
            chars[i] = [".", ",", "`", "'", "(", ")"][Math.floor(Math.random() * 6)];
          }
        }
        let line = chars.join("");
        const rowDrift = this.backFireDrift + (Math.random() - 0.5) * (0.45 + y * 0.15);
        const shift = Math.round(rowDrift);
        if (shift > 0) line = " ".repeat(shift) + line;
        if (shift < 0) line = line.slice(Math.min(-shift, line.length));
        rows.push(line.replace(/[xX$#@]/g, "."));
      }

      this.cachedBackFire = rows;
      return rows;
    }

    overlayFire(base, flames) {
      let out = "";
      const len = Math.max(base.length, flames.length);
      for (let i = 0; i < len; i++) {
        const b = base[i] || " ";
        const f = flames[i] || " ";
        if (f !== " " && (b === " " || b === "." || b === "'" || b === "`")) {
          out += f;
          continue;
        }
        out += b;
      }
      return out;
    }

    overlayBehind(base, flames) {
      let out = "";
      const len = Math.max(base.length, flames.length);
      for (let i = 0; i < len; i++) {
        const b = base[i] || " ";
        const f = flames[i] || " ";
        out += f !== " " && b === " " ? f : b;
      }
      return out;
    }

    renderFrame(t) {
      const catBase = this.catLines(t);
      const cat = [...catBase];
      const sceneCenter = Math.floor(this.frameWidth / 2);
      const potCenter = this.findPotCenter(cat);
      const catShift = sceneCenter - Math.round(potCenter);
      const centeredCat = cat.map((line) => this.shiftLine(line, catShift));

      let fire = this.fireLines(t, this.fireWidth, this.opts.fireHeight);
      fire = this.alignLinesToCenter(fire, sceneCenter, 0);
      let backFire = this.backFireLines(t, this.fireWidth + 10, this.opts.fireHeight);
      backFire = this.alignLinesToCenter(backFire, sceneCenter, 1);
      const overlap = Math.min(4, cat.length, fire.length);
      const overlayStart = Math.max(0, cat.length - overlap);
      const backStart = Math.max(0, centeredCat.length - Math.min(6, backFire.length + 2));
      const fireForOverlay = 0;
      const mergedCat = centeredCat.map((line, idx) => {
        let outLine = line;
        if (idx >= backStart) {
          const backRow = backFire[idx - backStart] || "";
          outLine = this.overlayBehind(outLine, backRow);
        }
        if (idx < overlayStart) return outLine;
        const fireRow = fire[fireForOverlay + (idx - overlayStart)] || "";
        return this.overlayFire(outLine, fireRow);
      });
      const composition = [...mergedCat, ...fire.slice(overlap)];

      const framed = composition.map((line) => {
        if (line.length >= this.frameWidth) return line.slice(0, this.frameWidth);
        return line.padEnd(this.frameWidth, " ");
      });

      return framed.join("\n");
    }

    loop(ts) {
      const frameMs = 1000 / this.opts.fps;
      if (ts - this.lastFrame >= frameMs) {
        this.lastFrame = ts;
        const t = (ts - this.start) / 1000;
        this.pre.textContent = this.renderFrame(t);
        const pulse = 0.94 + 0.06 * Math.sin(t * 0.7);
        this.pre.style.opacity = String(this.opts.opacity * pulse);
      }
      this.raf = requestAnimationFrame(this.loop);
    }

    destroy() {
      if (this.raf) cancelAnimationFrame(this.raf);
      if (this.resizeObs) this.resizeObs.disconnect();
    }
  }

  function initAsciiBanners() {
    document.querySelectorAll("[data-ascii-banner]").forEach((node) => {
      if (node.dataset.asciiBannerReady === "1") return;
      node.dataset.asciiBannerReady = "1";
      new AsciiCliBanner(node);
    });
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", initAsciiBanners, { once: true });
  } else {
    initAsciiBanners();
  }
})();
