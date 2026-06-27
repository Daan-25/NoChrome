#pragma once
// Minimal shared DOM tree used by both JS engine backends (JavaScriptCore and
// QuickJS). This is a textual include: it relies on the string helpers
// (toLowerCopy, trimCopy, decodeEntities, escapeHtmlEntities, parseClassList)
// defined earlier in main.cpp, and is included after them.

// -------------------- Minimal DOM tree --------------------
// A real (if small) DOM: a pool of nodes addressed by stable integer ids.
// JS bindings hold node ids and mutate this tree directly; for rendering the
// tree is serialized back to HTML and fed through the existing layout pipeline.

enum class DomNodeType { Element, Text };

struct DomNode {
    DomNodeType type = DomNodeType::Element;
    std::string tag;                                          // lowercased (Element)
    std::vector<std::pair<std::string, std::string>> attrs;   // ordered (Element)
    std::string text;                                         // (Text)
    std::string styleDisplay;                                 // style.display, if set
    int parent = -1;
    std::vector<int> children;
    bool alive = true;
};

struct DomTree {
    std::vector<DomNode> nodes;
    int root = -1; // synthetic root; its children are the top-level nodes

    int alloc(DomNodeType t) {
        DomNode n;
        n.type = t;
        nodes.push_back(std::move(n));
        return (int)nodes.size() - 1;
    }
    DomNode* get(int id) {
        if (id < 0 || id >= (int)nodes.size()) return nullptr;
        return &nodes[id];
    }
    const DomNode* get(int id) const {
        if (id < 0 || id >= (int)nodes.size()) return nullptr;
        return &nodes[id];
    }
};

static const std::string* domGetAttrPtr(const DomNode& n, const std::string& key) {
    for (auto& kv : n.attrs) if (kv.first == key) return &kv.second;
    return nullptr;
}
static std::string domGetAttr(const DomNode& n, const std::string& key) {
    const std::string* p = domGetAttrPtr(n, key);
    return p ? *p : std::string();
}
static void domSetAttr(DomNode& n, const std::string& key, const std::string& val) {
    for (auto& kv : n.attrs) if (kv.first == key) { kv.second = val; return; }
    n.attrs.push_back({ key, val });
}

static void domRemoveAttr(DomNode& n, const std::string& key) {
    for (size_t i = 0; i < n.attrs.size(); ++i) {
        if (n.attrs[i].first == key) { n.attrs.erase(n.attrs.begin() + i); return; }
    }
}

static void domAppendChild(DomTree& dom, int parentId, int childId) {
    DomNode* child = dom.get(childId);
    if (!child) return;
    if (child->parent >= 0) {
        if (DomNode* old = dom.get(child->parent)) {
            auto& cs = old->children;
            cs.erase(std::remove(cs.begin(), cs.end(), childId), cs.end());
        }
    }
    DomNode* parent = dom.get(parentId);
    if (!parent) { child->parent = -1; return; }
    parent->children.push_back(childId);
    child->parent = parentId;
}

static void domRemoveChild(DomTree& dom, int parentId, int childId) {
    DomNode* parent = dom.get(parentId);
    DomNode* child = dom.get(childId);
    if (!parent || !child) return;
    auto& cs = parent->children;
    cs.erase(std::remove(cs.begin(), cs.end(), childId), cs.end());
    child->parent = -1;
}

static int domFindById(const DomTree& dom, int start, const std::string& id) {
    const DomNode* n = dom.get(start);
    if (!n) return -1;
    if (n->type == DomNodeType::Element) {
        const std::string* a = domGetAttrPtr(*n, "id");
        if (a && *a == id) return start;
    }
    for (int c : n->children) {
        int r = domFindById(dom, c, id);
        if (r >= 0) return r;
    }
    return -1;
}

static int domFindByTag(const DomTree& dom, int start, const std::string& tag) {
    const DomNode* n = dom.get(start);
    if (!n) return -1;
    if (n->type == DomNodeType::Element && n->tag == tag) return start;
    for (int c : n->children) {
        int r = domFindByTag(dom, c, tag);
        if (r >= 0) return r;
    }
    return -1;
}

static int domFindByClass(const DomTree& dom, int start, const std::string& cls) {
    const DomNode* n = dom.get(start);
    if (!n) return -1;
    if (n->type == DomNodeType::Element) {
        for (auto& c : parseClassList(domGetAttr(*n, "class"))) {
            if (c == cls) return start;
        }
    }
    for (int c : n->children) {
        int r = domFindByClass(dom, c, cls);
        if (r >= 0) return r;
    }
    return -1;
}

// Collect all element ids whose tag matches (or "*" for every element).
static void domCollectByTag(const DomTree& dom, int start, const std::string& tag, std::vector<int>& out) {
    const DomNode* n = dom.get(start);
    if (!n) return;
    if (n->type == DomNodeType::Element && n->tag != "#root" && (tag == "*" || n->tag == tag))
        out.push_back(start);
    for (int c : n->children) domCollectByTag(dom, c, tag, out);
}

static void domCollectByClass(const DomTree& dom, int start, const std::string& cls, std::vector<int>& out) {
    const DomNode* n = dom.get(start);
    if (!n) return;
    if (n->type == DomNodeType::Element) {
        for (auto& c : parseClassList(domGetAttr(*n, "class"))) {
            if (c == cls) { out.push_back(start); break; }
        }
    }
    for (int c : n->children) domCollectByClass(dom, c, cls, out);
}

static int domFindOrCreateTag(DomTree& dom, const std::string& tag) {
    int id = domFindByTag(dom, dom.root, tag);
    if (id >= 0) return id;
    int el = dom.alloc(DomNodeType::Element);
    dom.nodes[el].tag = tag;
    domAppendChild(dom, dom.root, el);
    return el;
}

static void domCollectText(const DomTree& dom, int id, std::string& out) {
    const DomNode* n = dom.get(id);
    if (!n) return;
    if (n->type == DomNodeType::Text) { out += n->text; return; }
    for (int c : n->children) domCollectText(dom, c, out);
}
static std::string domTextContent(const DomTree& dom, int id) {
    std::string out;
    domCollectText(dom, id, out);
    return out;
}

static const std::unordered_set<std::string>& domVoidTags() {
    static const std::unordered_set<std::string> v = {
        "area", "base", "br", "col", "embed", "hr", "img", "input",
        "link", "meta", "param", "source", "track", "wbr"
    };
    return v;
}

// Serialize a node subtree to HTML. Elements with style.display == "none" are
// skipped so the renderer never lays them out.
static void domSerializeNode(const DomTree& dom, int id, std::string& out) {
    const DomNode* n = dom.get(id);
    if (!n || !n->alive) return;

    if (n->type == DomNodeType::Text) {
        out += escapeHtmlEntities(n->text);
        return;
    }

    if (toLowerCopy(trimCopy(n->styleDisplay)) == "none") return;

    std::string tag = n->tag.empty() ? std::string("div") : n->tag;
    out += "<" + tag;
    for (auto& kv : n->attrs) {
        out += " " + kv.first + "=\"" + escapeHtmlEntities(kv.second) + "\"";
    }
    out += ">";

    if (domVoidTags().count(tag)) return;

    for (int c : n->children) domSerializeNode(dom, c, out);
    out += "</" + tag + ">";
}

static std::string domSerialize(const DomTree& dom) {
    std::string out;
    const DomNode* r = dom.get(dom.root);
    if (!r) return out;
    for (int c : r->children) domSerializeNode(dom, c, out);
    return out;
}

static std::string domSerializeChildren(const DomTree& dom, int id) {
    std::string out;
    const DomNode* n = dom.get(id);
    if (!n) return out;
    for (int c : n->children) domSerializeNode(dom, c, out);
    return out;
}

static void domCaptureStyleDisplay(DomNode& n, const std::string& styleAttr) {
    std::string sv = toLowerCopy(styleAttr);
    size_t dp = sv.find("display");
    if (dp == std::string::npos) return;
    size_t colon = sv.find(':', dp);
    if (colon == std::string::npos) return;
    size_t e = sv.find(';', colon);
    n.styleDisplay = trimCopy(sv.substr(colon + 1, (e == std::string::npos ? sv.size() : e) - colon - 1));
}

static DomTree domParse(const std::string& html) {
    DomTree dom;
    dom.root = dom.alloc(DomNodeType::Element);
    dom.nodes[dom.root].tag = "#root";

    std::vector<int> stack;
    stack.push_back(dom.root);
    auto top = [&]() -> int { return stack.empty() ? dom.root : stack.back(); };

    std::string textBuf;
    auto flushText = [&]() {
        if (textBuf.empty()) return;
        std::string decoded = decodeEntities(textBuf);
        textBuf.clear();
        if (trimCopy(decoded).empty()) return; // drop whitespace-only nodes
        int t = dom.alloc(DomNodeType::Text);
        dom.nodes[t].text = decoded;
        domAppendChild(dom, top(), t);
    };

    size_t i = 0;
    const size_t N = html.size();
    while (i < N) {
        char c = html[i];
        if (c != '<') { textBuf.push_back(c); i++; continue; }

        if (html.compare(i, 4, "<!--") == 0) {
            flushText();
            size_t end = html.find("-->", i + 4);
            i = (end == std::string::npos) ? N : end + 3;
            continue;
        }

        size_t gt = html.find('>', i);
        if (gt == std::string::npos) { textBuf.append(html, i, std::string::npos); break; }

        std::string inner = html.substr(i + 1, gt - (i + 1));
        i = gt + 1;

        std::string t = trimCopy(inner);
        if (t.empty()) continue;
        if (t[0] == '!' || t[0] == '?') { flushText(); continue; }

        flushText();

        bool isEnd = (t[0] == '/');
        size_t p = isEnd ? 1 : 0;
        std::string name;
        while (p < t.size() && (std::isalnum((unsigned char)t[p]) || t[p] == '-')) {
            name.push_back((char)std::tolower((unsigned char)t[p]));
            p++;
        }
        if (name.empty()) continue;

        if (isEnd) {
            for (int s = (int)stack.size() - 1; s >= 1; --s) {
                if (dom.nodes[stack[s]].tag == name) { stack.resize(s); break; }
            }
            continue;
        }

        bool selfClose = (!t.empty() && t.back() == '/');

        int el = dom.alloc(DomNodeType::Element);
        dom.nodes[el].tag = name;

        std::string attrsPart = t.substr(p);
        size_t q = 0;
        while (q < attrsPart.size()) {
            while (q < attrsPart.size() && (std::isspace((unsigned char)attrsPart[q]) || attrsPart[q] == '/')) q++;
            if (q >= attrsPart.size()) break;
            std::string key;
            while (q < attrsPart.size() && attrsPart[q] != '=' &&
                   !std::isspace((unsigned char)attrsPart[q]) && attrsPart[q] != '/') {
                key.push_back((char)std::tolower((unsigned char)attrsPart[q]));
                q++;
            }
            while (q < attrsPart.size() && std::isspace((unsigned char)attrsPart[q])) q++;
            std::string val;
            if (q < attrsPart.size() && attrsPart[q] == '=') {
                q++;
                while (q < attrsPart.size() && std::isspace((unsigned char)attrsPart[q])) q++;
                if (q < attrsPart.size() && (attrsPart[q] == '"' || attrsPart[q] == '\'')) {
                    char quote = attrsPart[q++];
                    while (q < attrsPart.size() && attrsPart[q] != quote) { val.push_back(attrsPart[q]); q++; }
                    if (q < attrsPart.size()) q++;
                } else {
                    while (q < attrsPart.size() && !std::isspace((unsigned char)attrsPart[q]) && attrsPart[q] != '/') {
                        val.push_back(attrsPart[q]); q++;
                    }
                }
            }
            if (!key.empty()) {
                std::string dval = decodeEntities(val);
                domSetAttr(dom.nodes[el], key, dval);
                if (key == "style") domCaptureStyleDisplay(dom.nodes[el], dval);
            }
        }

        domAppendChild(dom, top(), el);

        // Raw-text / RCDATA elements: their content is NOT parsed as HTML
        // (so a '<' inside inline <script> JS can't corrupt the tree).
        if (!selfClose && (name == "script" || name == "style" ||
                           name == "textarea" || name == "title")) {
            std::string close = "</" + name;
            size_t end = std::string::npos;
            for (size_t p = html.find('<', i); p != std::string::npos; p = html.find('<', p + 1)) {
                if (p + close.size() > html.size()) break;
                bool m = true;
                for (size_t k = 0; k < close.size(); ++k) {
                    if ((char)std::tolower((unsigned char)html[p + k]) != close[k]) { m = false; break; }
                }
                if (m) { end = p; break; }
            }
            std::string content = (end == std::string::npos) ? html.substr(i) : html.substr(i, end - i);
            if (!content.empty()) {
                int tnode = dom.alloc(DomNodeType::Text);
                dom.nodes[tnode].text = (name == "textarea" || name == "title")
                                            ? decodeEntities(content) : content;
                domAppendChild(dom, el, tnode);
            }
            if (end == std::string::npos) { i = html.size(); }
            else { size_t gt2 = html.find('>', end); i = (gt2 == std::string::npos) ? html.size() : gt2 + 1; }
            continue;
        }

        if (!domVoidTags().count(name) && !selfClose) stack.push_back(el);
    }
    flushText();

    return dom;
}

// Deep-copy a node (and its subtree) from src into dom; returns the new id.
static int domImportNode(DomTree& dom, const DomTree& src, int srcId) {
    const DomNode* sn = src.get(srcId);
    if (!sn) return -1;
    int nid = dom.alloc(sn->type);
    dom.nodes[nid].type = sn->type;
    dom.nodes[nid].tag = sn->tag;
    dom.nodes[nid].attrs = sn->attrs;
    dom.nodes[nid].text = sn->text;
    dom.nodes[nid].styleDisplay = sn->styleDisplay;
    // Copy children list first (recursion may reallocate the vector).
    std::vector<int> kids = sn->children;
    for (int c : kids) {
        int cid = domImportNode(dom, src, c);
        if (cid >= 0) domAppendChild(dom, nid, cid);
    }
    return nid;
}

static void domClearChildren(DomTree& dom, int nodeId) {
    DomNode* n = dom.get(nodeId);
    if (!n) return;
    for (int c : n->children) { if (DomNode* cc = dom.get(c)) cc->parent = -1; }
    dom.get(nodeId)->children.clear();
}

static void domSetTextContent(DomTree& dom, int nodeId, const std::string& text) {
    if (!dom.get(nodeId)) return;
    domClearChildren(dom, nodeId);
    int t = dom.alloc(DomNodeType::Text);
    dom.nodes[t].text = text;
    domAppendChild(dom, nodeId, t);
}

static void domSetInnerHtml(DomTree& dom, int nodeId, const std::string& html) {
    if (!dom.get(nodeId)) return;
    domClearChildren(dom, nodeId);
    DomTree frag = domParse(html);
    const DomNode* fr = frag.get(frag.root);
    if (!fr) return;
    std::vector<int> topKids = fr->children;
    for (int fc : topKids) {
        int nid = domImportNode(dom, frag, fc);
        if (nid >= 0) domAppendChild(dom, nodeId, nid);
    }
}

// -------------------- DOM mutation / traversal extras --------------------

// Insert childId before refChildId in parent's child list. If refChildId is < 0
// or not a child of parent, append. Detaches child from any previous parent.
static void domInsertBefore(DomTree& dom, int parentId, int childId, int refChildId) {
    DomNode* child = dom.get(childId);
    DomNode* parent = dom.get(parentId);
    if (!child || !parent) return;
    if (child->parent >= 0) {
        if (DomNode* old = dom.get(child->parent)) {
            auto& oc = old->children;
            oc.erase(std::remove(oc.begin(), oc.end(), childId), oc.end());
        }
    }
    auto& cs = parent->children;
    auto it = (refChildId < 0) ? cs.end() : std::find(cs.begin(), cs.end(), refChildId);
    cs.insert(it, childId);   // insert(end, x) == push_back
    child->parent = parentId;
}

// Realloc-safe deep clone of a subtree within the SAME tree. (domImportNode
// caches a source pointer across alloc(), which is unsafe when src == dst.)
static int domCloneSubtree(DomTree& dom, int srcId, bool deep) {
    const DomNode* s = dom.get(srcId);
    if (!s) return -1;
    DomNodeType type = s->type;                 // copy fields out before alloc()
    std::string tag = s->tag, text = s->text, sd = s->styleDisplay;
    std::vector<std::pair<std::string, std::string>> attrs = s->attrs;
    std::vector<int> kids = s->children;
    int nid = dom.alloc(type);
    if (DomNode* d = dom.get(nid)) {
        d->tag = tag; d->text = text; d->styleDisplay = sd; d->attrs = attrs;
    }
    if (deep) {
        for (int c : kids) {
            int cid = domCloneSubtree(dom, c, true);
            if (cid >= 0) domAppendChild(dom, nid, cid);
        }
    }
    return nid;
}

// -------------------- class / inline-style helpers --------------------

static bool domClassContains(const DomNode& n, const std::string& cls) {
    for (auto& c : parseClassList(domGetAttr(n, "class"))) if (c == cls) return true;
    return false;
}
static void domClassAdd(DomNode& n, const std::string& cls) {
    if (cls.empty() || domClassContains(n, cls)) return;
    std::string cur = domGetAttr(n, "class");
    domSetAttr(n, "class", cur.empty() ? cls : cur + " " + cls);
}
static void domClassRemove(DomNode& n, const std::string& cls) {
    std::string out;
    for (auto& c : parseClassList(domGetAttr(n, "class"))) {
        if (c == cls) continue;
        if (!out.empty()) out += " ";
        out += c;
    }
    domSetAttr(n, "class", out);
}

// -------------------- simple selector matching (Batch 5) --------------------
// Match a single COMPOUND selector (no combinators) against one element.
// Supports: tag, .class, #id, [attr], [attr=value], and concatenations of
// those on one element (e.g. "div.box", ".a.b", "tag#id", "div[data-x=1]").
// Returns false on text nodes, empty selectors, or any whitespace combinator.
static bool domMatchCompound(const DomNode& n, const std::string& selRaw) {
    if (n.type != DomNodeType::Element) return false;
    std::string sel = trimCopy(selRaw);
    if (sel.empty()) return false;
    // A whitespace combinator (descendant) is not supported: bail false.
    for (char c : sel) if (c == ' ' || c == '\t' || c == '\n' || c == '\r') return false;

    size_t i = 0;
    while (i < sel.size()) {
        char c = sel[i];
        if (c == '.') {                       // .class
            size_t j = i + 1;
            while (j < sel.size() && sel[j] != '.' && sel[j] != '#' && sel[j] != '[') j++;
            std::string cls = toLowerCopy(sel.substr(i + 1, j - (i + 1)));
            if (cls.empty() || !domClassContains(n, cls)) return false;
            i = j;
        } else if (c == '#') {                 // #id
            size_t j = i + 1;
            while (j < sel.size() && sel[j] != '.' && sel[j] != '#' && sel[j] != '[') j++;
            std::string id = sel.substr(i + 1, j - (i + 1));
            if (id.empty() || domGetAttr(n, "id") != id) return false;
            i = j;
        } else if (c == '[') {                 // [attr] or [attr=value]
            size_t close = sel.find(']', i);
            if (close == std::string::npos) return false;
            std::string body = trimCopy(sel.substr(i + 1, close - (i + 1)));
            size_t eq = body.find('=');
            if (eq == std::string::npos) {     // [attr]
                std::string attr = toLowerCopy(trimCopy(body));
                if (attr.empty() || domGetAttrPtr(n, attr) == nullptr) return false;
            } else {                           // [attr=value]
                std::string attr = toLowerCopy(trimCopy(body.substr(0, eq)));
                std::string val  = trimCopy(body.substr(eq + 1));
                if (val.size() >= 2 && (val.front() == '"' || val.front() == '\'') &&
                    val.back() == val.front())
                    val = val.substr(1, val.size() - 2);
                const std::string* p = domGetAttrPtr(n, attr);
                if (attr.empty() || !p || *p != val) return false;
            }
            i = close + 1;
        } else {                               // tag
            size_t j = i;
            while (j < sel.size() && sel[j] != '.' && sel[j] != '#' && sel[j] != '[') j++;
            std::string tag = toLowerCopy(sel.substr(i, j - i));
            if (!tag.empty() && tag != "*") {
                std::string nt = n.tag.empty() ? std::string("div") : n.tag;
                if (nt != tag) return false;
            }
            i = j;
        }
    }
    return true;
}

// element.matches: allow a comma-separated selector list (match-any). Each
// comma group is a single compound selector (see domMatchCompound).
static bool domElementMatches(const DomTree& dom, int nodeId, const std::string& selector) {
    const DomNode* n = dom.get(nodeId);
    if (!n) return false;
    size_t i = 0;
    while (i <= selector.size()) {
        size_t comma = selector.find(',', i);
        std::string part = selector.substr(i, (comma == std::string::npos ? selector.size() : comma) - i);
        if (domMatchCompound(*n, part)) return true;
        if (comma == std::string::npos) break;
        i = comma + 1;
    }
    return false;
}

// element.closest: walk from nodeId up through parents (including self),
// returning the first matching node id, or -1.
static int domElementClosest(const DomTree& dom, int nodeId, const std::string& selector) {
    int cur = nodeId;
    while (cur >= 0) {
        const DomNode* n = dom.get(cur);
        if (!n) break;
        if (n->type == DomNodeType::Element && domElementMatches(dom, cur, selector)) return cur;
        cur = n->parent;
    }
    return -1;
}

// JS style properties are camelCase (backgroundColor); CSS is kebab
// (background-color). Convert for storage in the inline "style" attribute.
static std::string cssCamelToKebab(const std::string& s) {
    std::string out;
    for (char c : s) {
        if (std::isupper((unsigned char)c)) { out.push_back('-'); out.push_back((char)std::tolower((unsigned char)c)); }
        else out.push_back(c);
    }
    return out;
}
static std::vector<std::pair<std::string, std::string>> domParseStyle(const std::string& s) {
    std::vector<std::pair<std::string, std::string>> out;
    size_t i = 0;
    while (i < s.size()) {
        size_t semi = s.find(';', i);
        std::string decl = s.substr(i, (semi == std::string::npos ? s.size() : semi) - i);
        size_t colon = decl.find(':');
        if (colon != std::string::npos) {
            std::string k = toLowerCopy(trimCopy(decl.substr(0, colon)));
            std::string v = trimCopy(decl.substr(colon + 1));
            if (!k.empty()) out.push_back({ k, v });
        }
        if (semi == std::string::npos) break;
        i = semi + 1;
    }
    return out;
}
static std::string domSerializeStyle(const std::vector<std::pair<std::string, std::string>>& decls) {
    std::string out;
    for (auto& kv : decls) {
        if (kv.second.empty()) continue;
        if (!out.empty()) out += " ";
        out += kv.first + ": " + kv.second + ";";
    }
    return out;
}
static std::string domGetStyleProp(const DomNode& n, const std::string& jsProp) {
    std::string css = cssCamelToKebab(jsProp);
    for (auto& kv : domParseStyle(domGetAttr(n, "style"))) if (kv.first == css) return kv.second;
    return "";
}
static void domSetStyleProp(DomNode& n, const std::string& jsProp, const std::string& val) {
    std::string css = cssCamelToKebab(jsProp);
    auto decls = domParseStyle(domGetAttr(n, "style"));
    bool found = false;
    for (auto& kv : decls) if (kv.first == css) { kv.second = val; found = true; break; }
    if (!found) decls.push_back({ css, val });
    domSetAttr(n, "style", domSerializeStyle(decls));
    if (css == "display") n.styleDisplay = toLowerCopy(trimCopy(val));
}

// Curated set of CSS properties exposed on element.style (camelCase). Both JS
// backends reflect these through the inline "style" attribute; other names are
// stored as plain JS properties (set, but not rendered).
static const char* const kCssProps[] = {
    "display", "color", "background", "backgroundColor", "backgroundImage", "width", "height",
    "minWidth", "minHeight", "maxWidth", "maxHeight", "margin", "marginTop", "marginBottom",
    "marginLeft", "marginRight", "padding", "paddingTop", "paddingBottom", "paddingLeft",
    "paddingRight", "border", "borderColor", "borderWidth", "borderStyle", "borderRadius",
    "fontSize", "fontWeight", "fontFamily", "fontStyle", "textAlign", "textDecoration",
    "lineHeight", "letterSpacing", "position", "top", "left", "right", "bottom", "zIndex",
    "visibility", "opacity", "overflow", "cursor", "float", "clear", "verticalAlign",
    "whiteSpace", "boxShadow", "flex", "flexDirection", "justifyContent", "alignItems", "gap"
};
static bool cssIsKnownProp(const std::string& camel) {
    for (const char* p : kCssProps) if (camel == p) return true;
    return false;
}
