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
