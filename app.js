// 公開リポジトリ向け強化ロック設定
// パスワード本文やハッシュはコード内に置きません。
// data/encrypted-data.json を、入力パスワードから導出した鍵でAES-GCM復号します。
const ENCRYPTED_DATA_PATH = "./data/encrypted-data.json";
let failedAttempts = 0;

function base64ToBytes(base64){
  const bin = atob(base64);
  return Uint8Array.from(bin, c => c.charCodeAt(0));
}
function bytesToText(bytes){
  return new TextDecoder().decode(bytes);
}
function setAuthMessage(text, isError=true){
  const message = document.getElementById("auth-message");
  if(message){
    message.textContent = text;
    message.style.color = isError ? "var(--danger)" : "var(--accent)";
  }
}
async function wait(ms){ return new Promise(resolve => setTimeout(resolve, ms)); }

async function deriveAesKey(password, saltBytes, iterations){
  const baseKey = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    {name:"PBKDF2"},
    false,
    ["deriveKey"]
  );
  return crypto.subtle.deriveKey(
    {name:"PBKDF2", salt:saltBytes, iterations, hash:"SHA-256"},
    baseKey,
    {name:"AES-GCM", length:256},
    false,
    ["decrypt"]
  );
}

async function decryptEncryptedData(password){
  const res = await fetch(ENCRYPTED_DATA_PATH, {cache:"no-store"});
  if(!res.ok) throw new Error("暗号化データを読み込めませんでした。");
  const encrypted = await res.json();
  if(encrypted.algorithm !== "AES-GCM" || encrypted.kdf !== "PBKDF2-SHA256"){
    throw new Error("対応していない暗号化形式です。");
  }
  const salt = base64ToBytes(encrypted.salt);
  const iv = base64ToBytes(encrypted.iv);
  const ciphertext = base64ToBytes(encrypted.ciphertext);
  const iterations = Number(encrypted.iterations || 310000);
  const key = await deriveAesKey(password, salt, iterations);
  const plainBuffer = await crypto.subtle.decrypt({name:"AES-GCM", iv}, key, ciphertext);
  const payload = JSON.parse(bytesToText(new Uint8Array(plainBuffer)));
  if(!Array.isArray(payload.keywords) || !Array.isArray(payload.relations)){
    throw new Error("復号後データの形式が正しくありません。");
  }
  return payload;
}

function showProtectedApp(){
  const authScreen = document.getElementById("auth-screen");
  const protectedApp = document.getElementById("protected-app");
  document.body.classList.remove("locked");
  if(authScreen) authScreen.style.display = "none";
  if(protectedApp) protectedApp.hidden = false;
}

async function handleAuthSubmit(event){
  event.preventDefault();
  const input = document.getElementById("password-input");
  const button = event.submitter || document.querySelector("#auth-form button[type='submit']");
  const password = input?.value || "";
  if(password.length < 12){
    setAuthMessage("12文字以上のパスワードを入力してください。");
    return;
  }
  try{
    if(button) button.disabled = true;
    const delay = Math.min(2500, failedAttempts * 700);
    if(delay) await wait(delay);
    setAuthMessage("復号中です…", false);
    const payload = await decryptEncryptedData(password);
    state.keywords = payload.keywords;
    state.relations = payload.relations;
    state.selected = state.keywords[0]?.name || null;
    state.mapCenter = state.keywords[0]?.name || null;
    showProtectedApp();
    render();
  }catch(err){
    failedAttempts += 1;
    setAuthMessage("パスワードが違うか、暗号化データを復号できませんでした。");
    if(input){ input.value = ""; input.focus(); }
    console.warn(err);
  }finally{
    if(button) button.disabled = false;
  }
}

function logout(){
  state.keywords = [];
  state.relations = [];
  location.reload();
}

function initAuth(){
  const form = document.getElementById("auth-form");
  form?.addEventListener("submit", handleAuthSubmit);
  document.getElementById("password-input")?.focus();
}

const views = [
  ["top","トップ画面"],
  ["template","JSON追加テンプレート"],
  ["list","キーワード一覧"],
  ["index","人体索引"],
  ["body","人体シルエット"],
  ["substances","物質リンクビュー"],
  ["cross","分野横断ビュー"],
  ["map","関連マップ"],
  ["card","学習カード"],
  ["quiz","小テスト"],
  ["unknown","未理解ビュー"],
  ["nursing","看護につながるビュー"]
];

let state = {
  view: "top",
  keywords: [],
  relations: [],
  filters: {},
  selected: null,
  mapCenter: null,
  mapDepth: 1,
  mapMode: "flow"
};

const app = document.getElementById("app");
const nav = document.getElementById("nav");

function escapeHtml(str=""){
  return String(str).replace(/[&<>"']/g, s => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#039;'}[s]));
}
function asArray(v){ return Array.isArray(v) ? v : (v ? [v] : []); }
function uniq(arr){ return [...new Set(arr.filter(Boolean))]; }
function getKeyword(nameOrId){
  return state.keywords.find(k => k.name === nameOrId || k.id === nameOrId);
}
function getAllSystems(){
  return uniq(state.keywords.flatMap(k => asArray(k.systems || k.system)));
}
function getAllCategories(){
  return uniq(state.keywords.map(k => k.category));
}
function getRelationTypes(){
  return uniq(state.relations.map(r => r.relationType));
}
function getAllTermTypes(){
  return uniq(state.keywords.map(k => k.termType || inferTermType(k)));
}
function getAllSubstanceGroups(){
  return uniq(state.keywords.map(k => k.substanceGroup).filter(Boolean));
}
function inferTermType(k){
  const name = k?.name || "";
  const cat = k?.category || "";
  if(k?.termType) return k.termType;
  if(k?.substanceGroup || cat.includes("物質")) return "物質";
  if(cat.includes("検査") || ["CRP","AST","ALT","BUN","Na","K","Cl","SpO2"].includes(name)) return "検査値";
  if(cat.includes("細胞") || name.endsWith("細胞") || ["好中球","マクロファージ","リンパ球"].includes(name)) return "細胞";
  if(cat.includes("疾患") || cat.includes("腫瘍") || name.includes("症") || name.includes("不全")) return "疾患・病態";
  if(cat.includes("看護") || cat.includes("観察")) return "観察";
  return "概念";
}
function isSubstanceLike(k){
  const t = inferTermType(k);
  return t === "物質" || t === "検査値" || Boolean(k.substanceGroup);
}
function labelUnderstanding(v){
  return ({1:"1：未理解",2:"2：あいまい",3:"3：説明できる",4:"4：問題で使える",5:"5：定着"}[v] || String(v || ""));
}
function labelImportance(v){
  return ({1:"1：低",2:"2：補助",3:"3：標準",4:"4：重要",5:"5：最重要"}[v] || String(v || ""));
}
function setView(view){
  state.view = view;
  render();
  window.scrollTo({top:0, behavior:"smooth"});
}
function setSelected(name){
  state.selected = name;
  state.view = "card";
  render();
}
function setMapCenter(name){
  state.mapCenter = name;
  state.view = "map";
  render();
}

function renderNav(){
  nav.innerHTML = views.map(([id,label]) =>
    `<button class="tab ${state.view===id?"active":""}" onclick="setView('${id}')">${label}</button>`
  ).join("") + `<button class="tab" onclick="logout()">ロック</button>`;
}

function render(){
  renderNav();
  const map = {
    top: renderTop,
    template: renderTemplate,
    list: renderList,
    index: renderIndex,
    body: renderBodyAtlas,
    substances: renderSubstances,
    cross: renderCrossLinks,
    map: renderMap,
    card: renderCard,
    quiz: renderQuiz,
    unknown: renderUnknown,
    nursing: renderNursing
  };
  app.innerHTML = (map[state.view] || renderTop)();
  if(state.view === "map") drawMap();
}

function renderTop(){
  const systems = ["基礎レイヤー","呼吸器","循環器","消化器","腎泌尿器","神経","運動器","内分泌","感染免疫","腫瘍","看護観察","検査","修復"];
  const unknown = state.keywords.filter(k => Number(k.understanding) <= 2).length;
  const nursing = state.keywords.filter(k => (k.nursingObservation || "").trim()).length;
  const check = state.keywords.filter(k => k.checkTag).length;
  return `<section class="panel">
    <div class="grid cols-2">
      <div>
        <p class="eyebrow">体全体から探す</p>
        <h2>人体をカテゴリで俯瞰し、必要な時だけ関連マップでつなげます。</h2>
        <p class="muted">サイト内で直接保存せず、<strong>data/encrypted-data.json</strong> を正本として管理します。平文JSONは公開リポジトリに置きません。</p>
        <div class="stats">
          <div class="stat"><strong>${state.keywords.length}</strong><span>キーワード</span></div>
          <div class="stat"><strong>${state.relations.length}</strong><span>関連づけ</span></div>
          <div class="stat"><strong>${unknown}</strong><span>未理解</span></div>
          <div class="stat"><strong>${nursing}</strong><span>看護につながる</span></div>
          <div class="stat"><strong>${check}</strong><span>要確認</span></div>
        </div>
        <p style="margin-top:18px">
          <button class="btn primary" onclick="setView('list')">キーワード一覧へ</button>
          <button class="btn" onclick="setView('body')">人体シルエットへ</button>
          <button class="btn" onclick="setView('substances')">物質リンクへ</button>
          <button class="btn" onclick="setView('cross')">分野横断へ</button>
          <button class="btn" onclick="setView('template')">JSONテンプレートへ</button>
        </p>
      </div>
      <div class="grid cols-2">
        ${systems.map(s => {
          const count = state.keywords.filter(k => asArray(k.systems || k.system).includes(s) || k.category === s).length;
          return `<div class="category-card" onclick="state.filters.system='${s}';setView('index')">
            <h3>${s}</h3><p class="muted">${count}件</p>
          </div>`;
        }).join("")}
      </div>
    </div>
  </section>`;
}

function renderFilters(prefix="list"){
  const cats = getAllCategories();
  const systems = getAllSystems();
  const termTypes = getAllTermTypes();
  const groups = getAllSubstanceGroups();
  return `<div class="controls filters-extended">
    <input id="${prefix}-q" placeholder="キーワード検索" value="${escapeHtml(state.filters.q || "")}" oninput="state.filters.q=this.value;render()" />
    <select onchange="state.filters.category=this.value;render()">
      <option value="">カテゴリすべて</option>
      ${cats.map(c => `<option ${state.filters.category===c?"selected":""}>${escapeHtml(c)}</option>`).join("")}
    </select>
    <select onchange="state.filters.system=this.value;render()">
      <option value="">器官系すべて</option>
      ${systems.map(s => `<option ${state.filters.system===s?"selected":""}>${escapeHtml(s)}</option>`).join("")}
    </select>
    <select onchange="state.filters.termType=this.value;render()">
      <option value="">種類すべて</option>
      ${termTypes.map(t => `<option ${state.filters.termType===t?"selected":""}>${escapeHtml(t)}</option>`).join("")}
    </select>
    <select onchange="state.filters.substanceGroup=this.value;render()">
      <option value="">物質ジャンルすべて</option>
      ${groups.map(g => `<option ${state.filters.substanceGroup===g?"selected":""}>${escapeHtml(g)}</option>`).join("")}
    </select>
    <select onchange="state.filters.checkTag=this.value;render()">
      <option value="">要確認タグすべて</option>
      <option ${state.filters.checkTag==="要確認"?"selected":""}>要確認</option>
    </select>
  </div>`;
}

function filteredKeywords(source=state.keywords){
  const q = (state.filters.q || "").toLowerCase();
  return source.filter(k => {
    const text = [k.name,k.reading,k.category,asArray(k.systems).join(","),k.shortDescription,k.detailDescription,k.relatedSubstances,k.relatedDiseases,k.relatedTests,k.nursingObservation,k.substanceGroup,k.plainName,k.bridge].join(" ").toLowerCase();
    const okQ = !q || text.includes(q);
    const okCat = !state.filters.category || k.category === state.filters.category;
    const okSys = !state.filters.system || asArray(k.systems || k.system).includes(state.filters.system) || k.category === state.filters.system;
    const okType = !state.filters.termType || inferTermType(k) === state.filters.termType;
    const okGroup = !state.filters.substanceGroup || k.substanceGroup === state.filters.substanceGroup;
    const okTag = !state.filters.checkTag || k.checkTag === state.filters.checkTag;
    return okQ && okCat && okSys && okType && okGroup && okTag;
  });
}

function renderList(){
  const rows = filteredKeywords();
  return `<section class="panel">
    <h2>キーワード一覧ビュー</h2>
    <p class="muted">JSONに登録されているキーワードを表形式で確認します。</p>
    ${renderFilters("list")}
    <div class="table-wrap"><table>
      <thead><tr>
        <th>キーワード</th><th>読み方</th><th>カテゴリ</th><th>器官系</th><th>理解度</th><th>重要度</th><th>要確認</th><th>看護で見ること</th>
      </tr></thead>
      <tbody>
      ${rows.map(k => `<tr>
        <td><button class="keyword-link" onclick="setSelected('${escapeHtml(k.name)}')">${escapeHtml(k.name)}</button></td>
        <td>${escapeHtml(k.reading)}</td>
        <td>${escapeHtml(k.category)}<br><span class="chip small">${escapeHtml(inferTermType(k))}</span>${k.substanceGroup?`<span class="chip small substance">${escapeHtml(k.substanceGroup)}</span>`:""}</td>
        <td>${asArray(k.systems).map(s=>`<span class="chip">${escapeHtml(s)}</span>`).join(" ")}</td>
        <td>${labelUnderstanding(k.understanding)}</td>
        <td>${labelImportance(k.importance)}</td>
        <td>${k.checkTag?`<span class="chip check">${escapeHtml(k.checkTag)}</span>`:""}</td>
        <td>${escapeHtml(k.nursingObservation || "")}</td>
      </tr>`).join("")}
      </tbody>
    </table></div>
  </section>`;
}

function renderIndex(){
  const rows = filteredKeywords();
  const groups = {};
  rows.forEach(k => {
    const keys = asArray(k.systems || k.system);
    if(!keys.length) keys.push(k.category || "未分類");
    keys.forEach(s => {
      if(!groups[s]) groups[s] = [];
      groups[s].push(k);
    });
  });
  return `<section class="panel">
    <h2>人体索引ビュー</h2>
    <p class="muted">器官系ごとにキーワードをグループ表示します。</p>
    ${renderFilters("index")}
    <div class="grid cols-2">
      ${Object.entries(groups).map(([name, items]) => `<div class="card">
        <h3>${escapeHtml(name)} <span class="muted">${items.length}件</span></h3>
        <div class="chips">
          ${items.map(k => `<button class="chip keyword-link" onclick="setSelected('${escapeHtml(k.name)}')">${escapeHtml(k.name)} ${k.checkTag?'<span class="chip check">要確認</span>':''}</button>`).join("")}
        </div>
      </div>`).join("") || `<div class="empty">該当するキーワードがありません。</div>`}
    </div>
  </section>`;
}


function relationClass(type=""){
  if(type.includes("原因") || type.includes("病態")) return "cause";
  if(type.includes("結果") || type.includes("症状")) return "result";
  if(type.includes("構成")) return "component";
  if(type.includes("検査")) return "test";
  if(type.includes("看護")) return "nursing";
  if(type.includes("抑制")) return "inhibit";
  if(type.includes("活性")) return "activate";
  if(type.includes("比較")) return "compare";
  return "related";
}
function relationLabel(type=""){
  const cls = relationClass(type);
  return ({cause:"原因・病態", result:"結果・症状", component:"構成要素", test:"検査", nursing:"看護観察", inhibit:"抑制", activate:"活性化", compare:"比較", related:"関連"}[cls] || "関連");
}
function directRelations(name){
  return state.relations.filter(r => r.source === name || r.target === name);
}
function relationSummary(name){
  const rels = directRelations(name);
  const incoming = rels.filter(r => r.target === name);
  const outgoing = rels.filter(r => r.source === name);
  const tests = rels.filter(r => relationClass(r.relationType) === "test" || inferTermType(getKeyword(r.source === name ? r.target : r.source) || {}) === "検査値");
  const nursing = rels.filter(r => relationClass(r.relationType) === "nursing" || inferTermType(getKeyword(r.source === name ? r.target : r.source) || {}) === "観察");
  const toLine = (r, dir) => {
    const other = dir === "in" ? r.source : r.target;
    return `${other}（${r.relationType}）`;
  };
  return {
    incoming: incoming.map(r => toLine(r,"in")),
    outgoing: outgoing.map(r => toLine(r,"out")),
    tests: tests.map(r => r.source === name ? r.target : r.source),
    nursing: nursing.map(r => r.source === name ? r.target : r.source)
  };
}
function renderRelationSummary(name){
  const s = relationSummary(name);
  return `<div class="relation-summary-grid">
    ${info("前に来やすいもの / 上流", uniq(s.incoming).slice(0,12).join("、") || "未登録")}
    ${info("後に来やすいもの / 下流", uniq(s.outgoing).slice(0,12).join("、") || "未登録")}
    ${info("よく一緒に見る検査", uniq(s.tests).slice(0,12).join("、") || "未登録")}
    ${info("看護観察につながるもの", uniq(s.nursing).slice(0,12).join("、") || "未登録")}
  </div>`;
}
function renderRelationLegend(){
  const items = [
    ["cause","原因・病態"], ["result","結果・症状"], ["component","構成要素"],
    ["test","検査"], ["nursing","看護観察"], ["inhibit","抑制"], ["compare","比較"], ["related","関連"]
  ];
  return `<div class="relation-legend" aria-label="関係タイプの凡例">
    <strong>凡例</strong>
    ${items.map(([cls,label])=>`<span><i class="legend-line ${cls}"></i>${label}</span>`).join("")}
  </div>`;
}

function renderCard(){
  const selected = getKeyword(state.selected) || state.keywords[0];
  if(!selected) return `<section class="panel"><p>キーワードがありません。</p></section>`;
  const idx = state.keywords.findIndex(k => k.name === selected.name);
  const prev = state.keywords[idx-1]?.name;
  const next = state.keywords[idx+1]?.name;
  return `<section class="panel">
    <div class="detail-title">
      <div>
        <p class="eyebrow">${escapeHtml(selected.category)} / ${asArray(selected.systems).join("・")}</p>
        <h2>${escapeHtml(selected.name)}</h2>
        <p class="kana">${escapeHtml(selected.reading || "")}</p>
      </div>
      <div class="chips">
        <span class="chip">${labelUnderstanding(selected.understanding)}</span>
        <span class="chip">${labelImportance(selected.importance)}</span>
        ${selected.checkTag?`<span class="chip check">${escapeHtml(selected.checkTag)}</span>`:""}
      </div>
    </div>
    <div class="grid cols-2" style="margin-top:20px">
      ${info("種類・ジャンル", `${inferTermType(selected)}${selected.substanceGroup ? " / " + selected.substanceGroup : ""}${selected.plainName ? "\nやさしい言い換え：" + selected.plainName : ""}`)}
      ${selected.bridge ? info("分野とのつながり", selected.bridge) : ""}
      ${info("一言説明", selected.shortDescription)}
      ${info("詳しい説明", selected.detailDescription)}
      ${info("原因", selected.cause)}
      ${info("起こること", selected.event)}
      ${info("結果", selected.result)}
      ${info("看護で見ること", selected.nursingObservation)}
      ${info("関係する細胞", selected.relatedCells)}
      ${info("関係する物質", selected.relatedSubstances)}
      ${info("関係する疾患", selected.relatedDiseases)}
      ${info("関係する検査", selected.relatedTests)}
      ${info("関連キーワード", asArray(selected.relatedKeywords).join("、"))}
      ${info("メモ・参照元", `${selected.memo || ""}\n${selected.source || ""}`)}
    </div>
    <h3 class="subheading">前後関係</h3>
    ${renderRelationSummary(selected.name)}
    <p style="margin-top:18px">
      <button class="btn" ${!prev?"disabled":""} onclick="setSelected('${escapeHtml(prev || selected.name)}')">前へ</button>
      <button class="btn primary" onclick="setMapCenter('${escapeHtml(selected.name)}')">関連マップで見る</button>
      <button class="btn" ${!next?"disabled":""} onclick="setSelected('${escapeHtml(next || selected.name)}')">次へ</button>
    </p>
  </section>`;
}
function info(title, body){
  return `<div class="info-block"><h4>${escapeHtml(title)}</h4><p>${escapeHtml(body || "未入力")}</p></div>`;
}

function renderMap(){
  const center = getKeyword(state.mapCenter) || state.keywords[0];
  const cats = getAllCategories();
  const systems = getAllSystems();
  const types = getRelationTypes();
  const summary = center ? relationSummary(center.name) : {incoming:[], outgoing:[], tests:[], nursing:[]};
  const details = center ? `<div class="side-card map-side"><h3>${escapeHtml(center.name)}</h3><p>${escapeHtml(center.shortDescription || "")}</p>
    <div class="mini-flow">
      <div><strong>上流</strong><p>${escapeHtml(uniq(summary.incoming).slice(0,6).join("、") || "未登録")}</p></div>
      <div><strong>下流</strong><p>${escapeHtml(uniq(summary.outgoing).slice(0,6).join("、") || "未登録")}</p></div>
    </div>
    <h4>関係する細胞/物質/疾患/検査</h4><p>${escapeHtml([center.relatedCells,center.relatedSubstances,center.relatedDiseases,center.relatedTests].filter(Boolean).join(" / "))}</p>
    <h4>看護で見ること</h4><p>${escapeHtml(center.nursingObservation || "")}</p>
    <button class="btn primary" onclick="setSelected('${escapeHtml(center.name)}')">学習カードで開く</button></div>` : "";
  return `<section class="panel map-panel">
    <h2>関連マップビュー</h2>
    <p class="muted">矢印は source → target の向きです。フロー型では「どこから来て、どこへつながるか」を上流/下流で表示します。</p>
    <div class="controls map-controls">
      <select onchange="state.mapCenter=this.value;render()">
        ${state.keywords.map(k => `<option ${center && center.name===k.name?"selected":""}>${escapeHtml(k.name)}</option>`).join("")}
      </select>
      <select onchange="state.mapMode=this.value;render()">
        <option value="flow" ${state.mapMode==="flow"?"selected":""}>フロー型：上流 → 中心 → 下流</option>
        <option value="radial" ${state.mapMode==="radial"?"selected":""}>放射型：周辺を俯瞰</option>
      </select>
      <select onchange="state.mapDepth=Number(this.value);render()">
        ${[1,2,3].map(d => `<option value="${d}" ${state.mapDepth===d?"selected":""}>${d}階層まで</option>`).join("")}
      </select>
      <select onchange="state.filters.mapType=this.value;render()"><option value="">関係タイプすべて</option>${types.map(t=>`<option ${state.filters.mapType===t?"selected":""}>${escapeHtml(t)}</option>`).join("")}</select>
    </div>
    <div class="controls two">
      <select onchange="state.filters.mapCategory=this.value;render()"><option value="">カテゴリすべて</option>${cats.map(c=>`<option ${state.filters.mapCategory===c?"selected":""}>${escapeHtml(c)}</option>`).join("")}</select>
      <select onchange="state.filters.mapSystem=this.value;render()"><option value="">器官系すべて</option>${systems.map(s=>`<option ${state.filters.mapSystem===s?"selected":""}>${escapeHtml(s)}</option>`).join("")}</select>
    </div>
    <div class="map-layout enhanced">
      <div class="map-stage"><svg id="relationSvg" role="img" aria-label="関連マップ"></svg>${renderRelationLegend()}</div>
      ${details}
    </div>
  </section>`;
}

function relationPassesFilters(r){
  if(state.filters.mapType && r.relationType !== state.filters.mapType) return false;
  const a = getKeyword(r.source), b = getKeyword(r.target);
  const targets = [a,b].filter(Boolean);
  if(state.filters.mapCategory && !targets.some(k => k.category === state.filters.mapCategory)) return false;
  if(state.filters.mapSystem && !targets.some(k => asArray(k.systems || k.system).includes(state.filters.mapSystem))) return false;
  if(state.filters.mapImportance && !targets.some(k => String(k.importance) === String(state.filters.mapImportance))) return false;
  return true;
}
function buildGraph(centerName, depth){
  const nodes = new Map();
  const edges = [];
  const queue = [{name:centerName, level:0}];
  nodes.set(centerName, {name:centerName, level:0});
  while(queue.length){
    const cur = queue.shift();
    if(cur.level >= depth) continue;
    state.relations.forEach(r => {
      if(!relationPassesFilters(r)) return;
      let next = null;
      if(r.source === cur.name) next = r.target;
      else if(r.target === cur.name) next = r.source;
      if(!next) return;
      const k = getKeyword(next);
      if(!k) return;
      edges.push(r);
      if(!nodes.has(next)){
        nodes.set(next, {name:next, level:cur.level+1});
        queue.push({name:next, level:cur.level+1});
      }
    });
  }
  return {nodes:[...nodes.values()], edges:uniqEdges(edges)};
}
function uniqEdges(edges){
  const seen = new Set();
  return edges.filter(e => {
    const key = `${e.source}→${e.target}→${e.relationType}`;
    if(seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}
function drawMap(){
  const svg = document.getElementById("relationSvg");
  if(!svg) return;
  const center = state.mapCenter || state.keywords[0]?.name;
  if(state.mapMode === "radial") return drawRadialMap(svg, center);
  return drawFlowMap(svg, center);
}
function svgDefs(){
  const defs = [`<defs>`];
  ["cause","result","component","test","nursing","inhibit","activate","compare","related"].forEach(cls => {
    defs.push(`<marker id="arrow-${cls}" markerWidth="10" markerHeight="10" refX="9" refY="3" orient="auto" markerUnits="strokeWidth"><path d="M0,0 L0,6 L9,3 z" class="arrow-fill ${cls}"></path></marker>`);
  });
  defs.push(`</defs>`);
  return defs.join("");
}
function drawFlowMap(svg, center){
  const direct = state.relations.filter(r => (r.source === center || r.target === center) && relationPassesFilters(r));
  const incoming = direct.filter(r => r.target === center).slice(0,12);
  const outgoing = direct.filter(r => r.source === center).slice(0,12);
  const width = svg.clientWidth || 980, height = 760;
  svg.setAttribute("viewBox", `0 0 ${width} ${height}`);
  if(!center){ svg.innerHTML = `<text x="${width/2}" y="${height/2}" text-anchor="middle" fill="#657084">キーワードがありません</text>`; return; }
  const cx = width/2, cy = height/2;
  const positions = new Map();
  positions.set(center, {x:cx,y:cy, role:"center"});
  const leftX = Math.max(110, width*0.18), rightX = Math.min(width-110, width*0.82);
  const spread = Math.min(560, height-180);
  incoming.forEach((r,i)=>{
    const y = cy - spread/2 + (incoming.length===1 ? spread/2 : spread*i/(incoming.length-1));
    positions.set(r.source, {x:leftX,y, role:"up"});
  });
  outgoing.forEach((r,i)=>{
    const y = cy - spread/2 + (outgoing.length===1 ? spread/2 : spread*i/(outgoing.length-1));
    positions.set(r.target, {x:rightX,y, role:"down"});
  });
  const headers = `<text class="flow-header" x="${leftX}" y="54" text-anchor="middle">上流：原因・前提</text><text class="flow-header" x="${cx}" y="54" text-anchor="middle">中心</text><text class="flow-header" x="${rightX}" y="54" text-anchor="middle">下流：結果・検査・看護</text>`;
  const edgeEls = direct.map(r => {
    const a = positions.get(r.source), b = positions.get(r.target);
    if(!a || !b) return "";
    const cls = relationClass(r.relationType);
    const mx = (a.x+b.x)/2, my = (a.y+b.y)/2;
    return `<line class="edge ${cls}" x1="${a.x}" y1="${a.y}" x2="${b.x}" y2="${b.y}" marker-end="url(#arrow-${cls})"></line>
      <text class="edge-label ${cls}" x="${mx}" y="${my-10}" text-anchor="middle">${escapeHtml(r.relationType)}</text>`;
  }).join("");
  const nodeEls = [...positions.entries()].map(([name,p]) => nodeSvg(name,p, name===center, p.role)).join("");
  svg.innerHTML = svgDefs() + headers + edgeEls + nodeEls;
}
function drawRadialMap(svg, center){
  const graph = buildGraph(center, state.mapDepth);
  const width = svg.clientWidth || 980, height = 760;
  svg.setAttribute("viewBox", `0 0 ${width} ${height}`);
  if(graph.nodes.length <= 1){
    svg.innerHTML = `<text x="${width/2}" y="${height/2}" text-anchor="middle" fill="#657084">関連づけが未登録です</text>`;
    return;
  }
  const cx = width/2, cy = height/2;
  const positions = new Map();
  positions.set(center, {x:cx,y:cy, role:"center"});
  const others = graph.nodes.filter(n => n.name !== center).slice(0,32);
  others.forEach((n,i) => {
    const ring = n.level || 1;
    const sameLevel = others.filter(x => x.level === n.level);
    const levelIndex = sameLevel.findIndex(x => x.name === n.name);
    const angle = (Math.PI*2 * levelIndex / Math.max(1, sameLevel.length)) - Math.PI/2;
    const radius = Math.min(width,height) * (0.26 + (ring-1)*0.18);
    positions.set(n.name, {x:cx + Math.cos(angle)*radius, y:cy + Math.sin(angle)*radius, role:"around"});
  });
  const visibleNames = new Set([...positions.keys()]);
  const edgeLines = graph.edges.filter(e=>visibleNames.has(e.source)&&visibleNames.has(e.target)).map(e => {
    const a = positions.get(e.source), b = positions.get(e.target);
    if(!a || !b) return "";
    const cls = relationClass(e.relationType);
    const mx = (a.x+b.x)/2, my = (a.y+b.y)/2;
    return `<line class="edge ${cls}" x1="${a.x}" y1="${a.y}" x2="${b.x}" y2="${b.y}" marker-end="url(#arrow-${cls})"></line>
      <text class="edge-label ${cls}" x="${mx}" y="${my-7}" text-anchor="middle">${escapeHtml(e.relationType)}</text>`;
  }).join("");
  const nodeEls = [...positions.entries()].map(([name,p]) => nodeSvg(name,p, name===center, p.role)).join("");
  svg.innerHTML = svgDefs() + edgeLines + nodeEls;
}
function nodeSvg(name,p,isCenter=false,role="around"){
  const k = getKeyword(name);
  const r = isCenter ? 64 : 52;
  const label = name.length > 9 ? name.slice(0,9)+"…" : name;
  return `<g class="node ${isCenter?"center":""} ${role}" onclick="setMapCenter('${escapeHtml(name)}')">
    <circle cx="${p.x}" cy="${p.y}" r="${r}"></circle>
    <text x="${p.x}" y="${p.y-2}" text-anchor="middle">${escapeHtml(label)}</text>
    ${k?.checkTag ? `<text x="${p.x}" y="${p.y+22}" text-anchor="middle" font-size="11" fill="#b4234d">要確認</text>` : ""}
  </g>`;
}

function renderBodyAtlas(){
  const regions = [
    {id:"head", label:"頭部・神経", systems:["神経"], x:205,y:64},
    {id:"chest", label:"胸部", systems:["呼吸器","循環器"], x:205,y:172},
    {id:"abdomen", label:"腹部", systems:["消化器","腎泌尿器","内分泌"], x:205,y:292},
    {id:"pelvis", label:"骨盤・泌尿", systems:["腎泌尿器","内分泌"], x:205,y:390},
    {id:"arms", label:"上肢・運動器", systems:["運動器","循環器"], x:80,y:240},
    {id:"legs", label:"下肢・運動器", systems:["運動器","循環器"], x:205,y:520},
    {id:"whole", label:"全身・基礎", systems:["基礎レイヤー","感染免疫","検査","看護観察","修復"], x:330,y:240}
  ];
  const selected = state.filters.bodyRegion || "whole";
  const region = regions.find(r=>r.id===selected) || regions[0];
  const items = state.keywords.filter(k => region.systems.some(s => asArray(k.systems || k.system).includes(s) || k.category === s));
  return `<section class="panel">
    <h2>人体シルエットから探すビュー</h2>
    <p class="muted">部位をクリックして、関係しやすい器官系・基礎概念・検査・看護観察へ入ります。3Dではなく、更新しやすいシンプルな人体入口です。</p>
    <div class="body-layout">
      <div class="body-silhouette-card">
        <svg class="body-svg" viewBox="0 0 410 620" aria-label="人体シルエット">
          <circle class="body-part ${selected==='head'?'active':''}" cx="205" cy="64" r="42" onclick="state.filters.bodyRegion='head';render()"></circle>
          <rect class="body-part ${selected==='chest'?'active':''}" x="145" y="116" width="120" height="132" rx="48" onclick="state.filters.bodyRegion='chest';render()"></rect>
          <rect class="body-part ${selected==='abdomen'?'active':''}" x="155" y="244" width="100" height="116" rx="34" onclick="state.filters.bodyRegion='abdomen';render()"></rect>
          <rect class="body-part ${selected==='pelvis'?'active':''}" x="158" y="360" width="94" height="72" rx="26" onclick="state.filters.bodyRegion='pelvis';render()"></rect>
          <rect class="body-part ${selected==='arms'?'active':''}" x="76" y="130" width="46" height="260" rx="23" onclick="state.filters.bodyRegion='arms';render()"></rect>
          <rect class="body-part ${selected==='arms'?'active':''}" x="288" y="130" width="46" height="260" rx="23" onclick="state.filters.bodyRegion='arms';render()"></rect>
          <rect class="body-part ${selected==='legs'?'active':''}" x="150" y="430" width="48" height="158" rx="24" onclick="state.filters.bodyRegion='legs';render()"></rect>
          <rect class="body-part ${selected==='legs'?'active':''}" x="212" y="430" width="48" height="158" rx="24" onclick="state.filters.bodyRegion='legs';render()"></rect>
          ${regions.map(r=>`<text class="body-label" x="${r.x}" y="${r.y}" text-anchor="middle" onclick="state.filters.bodyRegion='${r.id}';render()">${escapeHtml(r.label)}</text>`).join("")}
        </svg>
      </div>
      <div class="body-result-card">
        <h3>${escapeHtml(region.label)}</h3>
        <p class="muted">関連器官系：${region.systems.map(s=>`<span class="chip">${escapeHtml(s)}</span>`).join(" ")}</p>
        <div class="chips body-region-buttons">
          ${regions.map(r=>`<button class="chip keyword-link ${selected===r.id?'selected':''}" onclick="state.filters.bodyRegion='${r.id}';render()">${escapeHtml(r.label)}</button>`).join("")}
        </div>
        <div class="table-wrap mini-table"><table><thead><tr><th>キーワード</th><th>種類</th><th>一言説明</th><th>操作</th></tr></thead><tbody>
          ${items.slice(0,80).map(k=>`<tr><td><button class="keyword-link" onclick="setSelected('${escapeHtml(k.name)}')">${escapeHtml(k.name)}</button></td><td>${escapeHtml(inferTermType(k))}</td><td>${escapeHtml(k.shortDescription||"")}</td><td><button class="btn" onclick="setMapCenter('${escapeHtml(k.name)}')">マップ</button></td></tr>`).join("") || `<tr><td colspan="4">該当キーワードがありません。</td></tr>`}
        </tbody></table></div>
      </div>
    </div>
  </section>`;
}


function renderSubstances(){
  const items = filteredKeywords(state.keywords).filter(isSubstanceLike);
  const groups = {};
  items.forEach(k => {
    const g = k.substanceGroup || inferTermType(k) || "未分類";
    if(!groups[g]) groups[g] = [];
    groups[g].push(k);
  });
  return `<section class="panel">
    <h2>物質リンクビュー</h2>
    <p class="muted">カタカナ・略語・検査値をジャンル分けし、「何の分野とつながる物質か」を見ます。</p>
    ${renderFilters("substances")}
    <div class="grid cols-2">
      ${Object.entries(groups).map(([group, list]) => `<div class="card substance-card">
        <h3>${escapeHtml(group)} <span class="muted">${list.length}件</span></h3>
        <div class="grid">
          ${list.map(k => `<div class="row-card compact" onclick="setSelected('${escapeHtml(k.name)}')">
            <div class="detail-title compact-title"><h4>${escapeHtml(k.name)}</h4><span class="chip small">${escapeHtml(inferTermType(k))}</span></div>
            ${k.plainName ? `<p class="muted"><strong>言い換え：</strong>${escapeHtml(k.plainName)}</p>` : ""}
            <p>${escapeHtml(k.shortDescription || "")}</p>
            <p class="muted"><strong>つながる分野：</strong>${asArray(k.systems).join("・")}</p>
            ${k.bridge ? `<p class="muted"><strong>橋渡し：</strong>${escapeHtml(k.bridge)}</p>` : ""}
            <button class="btn" onclick="event.stopPropagation();setMapCenter('${escapeHtml(k.name)}')">マップで見る</button>
          </div>`).join("")}
        </div>
      </div>`).join("") || `<div class="empty">該当する物質・検査値がありません。</div>`}
    </div>
  </section>`;
}

function renderCrossLinks(){
  const systems = getAllSystems();
  const selectedSystem = state.filters.crossSystem || systems[0] || "";
  const inSystem = state.keywords.filter(k => !selectedSystem || asArray(k.systems || k.system).includes(selectedSystem) || k.category === selectedSystem);
  const substances = inSystem.filter(isSubstanceLike);
  const concepts = inSystem.filter(k => !isSubstanceLike(k));
  const relatedEdges = state.relations.filter(r => {
    const a = getKeyword(r.source), b = getKeyword(r.target);
    return a && b && (asArray(a.systems).includes(selectedSystem) || asArray(b.systems).includes(selectedSystem));
  }).slice(0, 80);
  return `<section class="panel">
    <h2>分野横断ビュー</h2>
    <p class="muted">「器官系 → 物質・検査値 → 病態・看護観察」の横断関係を見ます。暗記の羅列を避けるためのビューです。</p>
    <div class="controls two">
      <select onchange="state.filters.crossSystem=this.value;render()">
        ${systems.map(s => `<option ${selectedSystem===s?"selected":""}>${escapeHtml(s)}</option>`).join("")}
      </select>
      <button class="btn" onclick="state.filters.crossSystem='';render()">全分野に戻す</button>
    </div>
    <div class="grid cols-3">
      <div class="card soft"><h3>${escapeHtml(selectedSystem || "全分野")}の物質・検査値</h3><div class="chips">${substances.map(k=>`<button class="chip keyword-link" onclick="setSelected('${escapeHtml(k.name)}')">${escapeHtml(k.name)}</button>`).join("") || "なし"}</div></div>
      <div class="card soft"><h3>関連する概念・病態</h3><div class="chips">${concepts.slice(0,80).map(k=>`<button class="chip keyword-link" onclick="setSelected('${escapeHtml(k.name)}')">${escapeHtml(k.name)}</button>`).join("") || "なし"}</div></div>
      <div class="card soft"><h3>看護で拾う入口</h3><p>${escapeHtml(inSystem.map(k=>k.nursingObservation).filter(Boolean).slice(0,8).join(" / ")) || "未登録"}</p></div>
    </div>
    <div class="table-wrap" style="margin-top:16px"><table>
      <thead><tr><th>起点</th><th>関係</th><th>関連先</th><th>メモ</th></tr></thead>
      <tbody>${relatedEdges.map(r=>`<tr><td><button class="keyword-link" onclick="setSelected('${escapeHtml(r.source)}')">${escapeHtml(r.source)}</button></td><td>${escapeHtml(r.relationType)}</td><td><button class="keyword-link" onclick="setSelected('${escapeHtml(r.target)}')">${escapeHtml(r.target)}</button></td><td>${escapeHtml(r.memo||"")}</td></tr>`).join("")}</tbody>
    </table></div>
  </section>`;
}

function renderUnknown(){
  const list = state.keywords.filter(k => Number(k.understanding) <= 2);
  return `<section class="panel">
    <h2>未理解ビュー</h2>
    <p class="muted">理解度が低いキーワードだけを表示します。理解度は平文JSONをローカルで編集し、再暗号化して管理します。</p>
    <div class="grid cols-3">
      ${list.map(k => miniCard(k)).join("") || `<div class="empty">未理解キーワードはありません。</div>`}
    </div>
  </section>`;
}
function renderNursing(){
  const list = state.keywords.filter(k => (k.nursingObservation || "").trim());
  return `<section class="panel">
    <h2>看護につながるビュー</h2>
    <p class="muted">「看護で見ること」が入力されているキーワードを表示します。</p>
    <div class="grid cols-2">
      ${list.map(k => `<div class="row-card" onclick="setSelected('${escapeHtml(k.name)}')"><h3>${escapeHtml(k.name)}</h3><p>${escapeHtml(k.nursingObservation)}</p><div class="chips"><span class="chip">${escapeHtml(k.category)}</span>${k.checkTag?'<span class="chip check">要確認</span>':''}</div></div>`).join("")}
    </div>
  </section>`;
}
function miniCard(k){
  return `<div class="row-card" onclick="setSelected('${escapeHtml(k.name)}')">
    <h3>${escapeHtml(k.name)}</h3><p>${escapeHtml(k.shortDescription)}</p>
    <div class="chips"><span class="chip">${labelUnderstanding(k.understanding)}</span><span class="chip">${labelImportance(k.importance)}</span></div>
  </div>`;
}

function renderQuiz(){
  const questions = state.keywords.slice(0, 12).map((k,i) => ({
    q:`${k.name}を一言で説明すると？`,
    a:k.shortDescription
  })).concat(state.keywords.slice(0,8).map(k => ({
    q:`${k.name}について、看護で見ることは？`,
    a:k.nursingObservation
  })));
  return `<section class="panel">
    <h2>小テストビュー</h2>
    <p class="muted">keywords.json の一言説明・看護で見ることから簡易問題を作成します。</p>
    <div class="grid">
      ${questions.map((x,i)=>`<div class="card">
        <h3>Q${i+1}. ${escapeHtml(x.q)}</h3>
        <button class="btn" onclick="document.getElementById('ans-${i}').classList.toggle('show')">答えを表示</button>
        <p id="ans-${i}" class="quiz-answer"><strong>答え：</strong>${escapeHtml(x.a)}</p>
      </div>`).join("")}
    </div>
  </section>`;
}

function renderTemplate(){
  const keywordTemplate = {
    "id": "new_keyword_id",
    "name": "新しいキーワード",
    "reading": "よみがな",
    "category": "基礎レイヤー",
    "systems": ["基礎レイヤー"],
    "shortDescription": "一言説明を入れる。",
    "detailDescription": "詳しい説明を入れる。",
    "cause": "原因を入れる。直接の原因でない場合は学習上の位置づけを書く。",
    "event": "体内で起こることを入れる。",
    "result": "結果・症状・病態へのつながりを入れる。",
    "relatedCells": "関係する細胞",
    "relatedSubstances": "関係する物質",
    "relatedDiseases": "関係する疾患",
    "relatedTests": "関係する検査",
    "nursingObservation": "看護で見ること",
    "relatedKeywords": ["関連キーワード1","関連キーワード2"],
    "understanding": 2,
    "importance": 4,
    "memo": "学習用の下書き。",
    "source": "AI生成サンプル／教科書・授業資料で確認",
    "checkTag": "要確認",
    "termType": "概念",
    "substanceGroup": "必要時のみ：炎症メディエーターなど",
    "plainName": "カタカナ・略語のやさしい言い換え",
    "bridge": "このキーワードが他分野とどうつながるか"
  };
  const relationTemplate = {
    "source": "起点キーワード",
    "target": "関連キーワード",
    "relationType": "関係する",
    "memo": "関連理由を短く書く"
  };
  return `<section class="panel">
    <h2>JSON追加用テンプレート / データ管理</h2>
    <p class="muted">公開リポジトリには平文の keywords.json / relations.json を置きません。ローカルで編集し、<strong>tools/encrypt.html</strong> で <strong>data/encrypted-data.json</strong> に再暗号化して差し替えます。</p>
    <div class="warning">平文JSONを書き出した場合、そのファイルは公開リポジトリにアップロードしないでください。</div>
    <div class="card soft" style="margin-top:16px">
      <h3>現在の復号済みデータを書き出す</h3>
      <p class="muted">キーワード追加・修正をする時だけ、PC内に保存して編集します。編集後は暗号化ツールで encrypted-data.json を作り直します。</p>
      <button class="btn" onclick="downloadCurrentJson('keywords')">keywords.jsonを書き出す</button>
      <button class="btn" onclick="downloadCurrentJson('relations')">relations.jsonを書き出す</button>
      <button class="btn primary" onclick="downloadCurrentJson('bundle')">keywords + relations を1つに書き出す</button>
    </div>
    <div class="grid cols-2" style="margin-top:16px">
      <div>
        <h3>keywords.json 用テンプレート</h3>
        <pre id="kwTemplate">${escapeHtml(JSON.stringify(keywordTemplate,null,2))}</pre>
        <button class="btn primary" onclick="copyText('kwTemplate')">コピー</button>
      </div>
      <div>
        <h3>relations.json 用テンプレート</h3>
        <pre id="relTemplate">${escapeHtml(JSON.stringify(relationTemplate,null,2))}</pre>
        <button class="btn primary" onclick="copyText('relTemplate')">コピー</button>
      </div>
    </div>
  </section>`;
}

function downloadJsonFile(filename, data){
  const text = JSON.stringify(data, null, 2);
  const blob = new Blob([text], {type:"application/json;charset=utf-8"});
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}
function downloadCurrentJson(type){
  const ok = confirm("平文JSONを書き出します。公開リポジトリには絶対にアップロードしないでください。続行しますか？");
  if(!ok) return;
  if(type === "keywords") return downloadJsonFile("keywords.private.json", state.keywords);
  if(type === "relations") return downloadJsonFile("relations.private.json", state.relations);
  return downloadJsonFile("body-link-atlas-private-data.json", {keywords:state.keywords, relations:state.relations});
}

function copyText(id){
  const text = document.getElementById(id)?.innerText || "";
  navigator.clipboard?.writeText(text);
  alert("コピーしました");
}

initAuth();
