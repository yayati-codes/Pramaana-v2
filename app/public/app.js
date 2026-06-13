// Pure presentation: drive the demo's JSON API and render state. All crypto
// (enrollment, Semaphore proofs, on-chain spends) runs server-side in the SDK.

const $ = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => [...root.querySelectorAll(sel)];

async function api(method, path, body) {
  const res = await fetch(path, {
    method,
    headers: body ? { "content-type": "application/json" } : undefined,
    body: body ? JSON.stringify(body) : undefined,
  });
  const data = await res.json();
  if (!res.ok) throw new Error(data.error ?? res.statusText);
  return data;
}

const enrollBtn = $("#enrollBtn");
const enrollOut = $("#enrollOut");
const resetBtn = $("#resetBtn");
const claims = {}; // service -> record

function serviceCard(service) {
  return $(`.service[data-service="${service}"]`);
}

enrollBtn.addEventListener("click", async () => {
  enrollBtn.disabled = true;
  enrollBtn.textContent = "Enrolling…";
  try {
    const r = await api("POST", "/api/enroll");
    enrollOut.classList.remove("hidden");
    enrollOut.innerHTML =
      `<span class="pill ok">Sybil-unique identity minted</span>` +
      `<div class="kv">Φ = <b class="mono">${r.phiShort}</b>` +
      (r.alreadyEnrolled ? ` <span class="muted">(existing — dedup returned the same Φ)</span>` : ``) +
      `</div>`;
    $$(".claimBtn").forEach((b) => (b.disabled = false));
    enrollBtn.textContent = "Enrolled ✓";
  } catch (e) {
    enrollBtn.disabled = false;
    enrollBtn.textContent = "Enroll inside the TEE";
    enrollOut.classList.remove("hidden");
    enrollOut.innerHTML = `<span class="pill block">Error: ${e.message}</span>`;
  }
});

$$(".claimBtn").forEach((btn) => {
  const card = btn.closest(".service");
  const service = card.dataset.service;
  btn.addEventListener("click", async () => {
    btn.disabled = true;
    btn.textContent = "Claiming…";
    try {
      const r = await api("POST", "/api/claim", { service });
      claims[service] = r;
      renderClaim(service, r);
    } catch (e) {
      $(".claimOut", card).innerHTML = `<span class="pill block">Error: ${e.message}</span>`;
    } finally {
      btn.textContent = "Claim again";
      btn.disabled = false;
    }
    renderCorrelation();
  });
});

function renderClaim(service, r) {
  const card = serviceCard(service);
  const pill =
    r.status === "claimed"
      ? `<span class="pill ok">Claimed ✓</span>`
      : `<span class="pill block">Blocked — already claimed (nullifier spent)</span>`;
  $(".claimOut", card).innerHTML =
    `${pill}<div class="kv">nullifier = <b class="mono">${shorten(r.nullifier)}</b></div>`;
}

function renderCorrelation() {
  const a = claims["airdrop-alpha"];
  const b = claims["airdrop-beta"];
  const box = $("#correlation");
  if (!a || !b) {
    box.className = "muted";
    box.textContent = "Claim both airdrops to compare their nullifiers.";
    return;
  }
  const linked = a.nullifier === b.nullifier;
  box.className = "verdict good";
  box.innerHTML =
    `<div class="kv">Alpha nullifier: <b class="mono">${shorten(a.nullifier)}</b></div>` +
    `<div class="kv">Beta&nbsp; nullifier: <b class="mono">${shorten(b.nullifier)}</b></div>` +
    (linked
      ? `<div class="kv"><span class="pill block">Correlated</span></div>`
      : `<div class="kv"><span class="pill ok">No derivable link</span> ` +
        `the two airdrops see unrelated values and cannot tell it is the same human.</div>` +
        `<div class="kv muted">nullifier = H(secret, serviceId); only the group-wide Merkle root is shared, ` +
        `and every member shares it.</div>`);
}

resetBtn.addEventListener("click", async () => {
  await api("POST", "/api/reset");
  location.reload();
});

function shorten(hex) {
  return hex.length > 22 ? `${hex.slice(0, 12)}…${hex.slice(-8)}` : hex;
}

// Restore state on reload.
(async () => {
  try {
    const s = await api("GET", "/api/state");
    if (s.enrollment) {
      enrollBtn.disabled = true;
      enrollBtn.textContent = "Enrolled ✓";
      enrollOut.classList.remove("hidden");
      enrollOut.innerHTML =
        `<span class="pill ok">Sybil-unique identity minted</span>` +
        `<div class="kv">Φ = <b class="mono">${s.enrollment.phiShort}</b></div>`;
      $$(".claimBtn").forEach((b) => (b.disabled = false));
    }
    for (const [service, record] of Object.entries(s.claims ?? {})) {
      claims[service] = record;
      renderClaim(service, record);
    }
    renderCorrelation();
  } catch {
    /* fresh load */
  }
})();
