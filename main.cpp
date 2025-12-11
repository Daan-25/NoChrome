#include <SDL.h>
#include <SDL_ttf.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

#include <iostream>
#include <string>
#include <sstream>
#include <vector>
#include <algorithm>
#include <cctype>
#include <optional>
#include <unordered_map>
#include <cmath>
#include <cstdio>

// --------- Networking (POSIX + basic Windows support) ----------
#ifdef _WIN32
  #define WIN32_LEAN_AND_MEAN
  #include <winsock2.h>
  #include <ws2tcpip.h>
  #pragma comment(lib, "Ws2_32.lib")
#else
  #include <sys/types.h>
  #include <sys/socket.h>
  #include <netdb.h>
  #include <unistd.h>
#endif

// -------------------- Small helpers --------------------

static bool startsWith(const std::string& s, const std::string& p) {
    return s.size() >= p.size() && s.compare(0, p.size(), p) == 0;
}

static bool endsWith(const std::string& s, const std::string& suf) {
    return s.size() >= suf.size() &&
           s.compare(s.size() - suf.size(), suf.size(), suf) == 0;
}

static std::string toLowerCopy(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c){ return (char)std::tolower(c); });
    return s;
}

static std::string trimCopy(const std::string& s) {
    size_t a = 0;
    while (a < s.size() && std::isspace((unsigned char)s[a])) a++;
    size_t b = s.size();
    while (b > a && std::isspace((unsigned char)s[b - 1])) b--;
    return s.substr(a, b - a);
}

static std::vector<std::string> splitBy(const std::string& s, char delim) {
    std::vector<std::string> out;
    std::stringstream ss(s);
    std::string part;
    while (std::getline(ss, part, delim)) out.push_back(part);
    return out;
}

// -------------------- URL --------------------

struct Url {
    std::string scheme = "http";
    std::string host;
    std::string path = "/";
    int port = 80;
};

static Url parseUrl(const std::string& input) {
    Url u;
    std::string s = input;

    auto pos = s.find("://");
    if (pos != std::string::npos) {
        u.scheme = s.substr(0, pos);
        s = s.substr(pos + 3);
    }

    auto slash = s.find('/');
    if (slash != std::string::npos) {
        u.host = s.substr(0, slash);
        u.path = s.substr(slash);
    } else {
        u.host = s;
        u.path = "/";
    }

    auto colon = u.host.find(':');
    if (colon != std::string::npos) {
        u.port = std::stoi(u.host.substr(colon + 1));
        u.host = u.host.substr(0, colon);
    } else {
        u.port = (u.scheme == "https") ? 443 : 80;
    }

    if (u.path.empty()) u.path = "/";
    return u;
}

static std::string normalizeUserUrl(std::string s) {
    s = trimCopy(s);
    if (s.empty()) return "http://example.com/";

    if (s.find("://") == std::string::npos) {
        s = "http://" + s;
    }
    return s;
}

static std::string dirnameOfPath(const std::string& path) {
    auto pos = path.find_last_of('/');
    if (pos == std::string::npos) return "/";
    if (pos == 0) return "/";
    return path.substr(0, pos + 1);
}

static std::string buildOrigin(const Url& base) {
    bool isHttpDefault  = (base.scheme == "http"  && base.port == 80);
    bool isHttpsDefault = (base.scheme == "https" && base.port == 443);

    std::string portPart;
    if (!isHttpDefault && !isHttpsDefault && base.port > 0) {
        portPart = ":" + std::to_string(base.port);
    }

    return base.scheme + "://" + base.host + portPart;
}

static std::string resolveHref(const Url& base, const std::string& href) {
    if (href.empty()) return "";
    if (startsWith(href, "http://")) return href;
    if (startsWith(href, "https://")) return href;
    if (href[0] == '#') return "";

    const std::string origin = buildOrigin(base);

    if (href[0] == '/') {
        return origin + href;
    }

    std::string dir = dirnameOfPath(base.path);
    return origin + dir + href;
}

// -------------------- Networking (raw HTTP) --------------------

static void netInit() {
#ifdef _WIN32
    WSADATA wsa{};
    if (WSAStartup(MAKEWORD(2,2), &wsa) != 0) {
        throw std::runtime_error("WSAStartup failed");
    }
#endif
}

static void netCleanup() {
#ifdef _WIN32
    WSACleanup();
#endif
}

static void closeSock(int s) {
#ifdef _WIN32
    closesocket(s);
#else
    close(s);
#endif
}

static int openTcpSocket(const std::string& host, int port) {
    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    addrinfo* res = nullptr;
    std::string portStr = std::to_string(port);

    if (getaddrinfo(host.c_str(), portStr.c_str(), &hints, &res) != 0) {
        throw std::runtime_error("getaddrinfo failed");
    }

    int sock = -1;
    for (addrinfo* p = res; p != nullptr; p = p->ai_next) {
        sock = (int)::socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (sock < 0) continue;

        if (connect(sock, p->ai_addr, (int)p->ai_addrlen) == 0) {
            break;
        }
        closeSock(sock);
        sock = -1;
    }

    freeaddrinfo(res);

    if (sock < 0) {
        throw std::runtime_error("connect failed");
    }

    return sock;
}

static std::string httpGet(const Url& u) {
    int sock = openTcpSocket(u.host, u.port);

    std::ostringstream req;
    req << "GET " << u.path << " HTTP/1.1\r\n"
        << "Host: " << u.host << "\r\n"
        << "User-Agent: NoChrome/0.7\r\n"
        << "Connection: close\r\n\r\n";

    std::string request = req.str();

#ifdef _WIN32
    int sent = send(sock, request.c_str(), (int)request.size(), 0);
#else
    ssize_t sent = send(sock, request.c_str(), request.size(), 0);
#endif
    if (sent < 0) {
        closeSock(sock);
        throw std::runtime_error("send failed");
    }

    std::string response;
    char buffer[4096];

    while (true) {
#ifdef _WIN32
        int n = recv(sock, buffer, (int)sizeof(buffer), 0);
#else
        ssize_t n = recv(sock, buffer, sizeof(buffer), 0);
#endif
        if (n <= 0) break;
        response.append(buffer, buffer + n);
    }

    closeSock(sock);
    return response;
}

static std::string extractBody(const std::string& response) {
    auto pos = response.find("\r\n\r\n");
    if (pos == std::string::npos) return response;
    return response.substr(pos + 4);
}

// -------------------- TLS (OpenSSL HTTPS) --------------------

static void sslInitOnce() {
    static bool inited = false;
    if (inited) return;
    OPENSSL_init_ssl(0, nullptr);
    inited = true;
}

static void configureDefaultCa(SSL_CTX* ctx) {
#ifdef __APPLE__
    const char* brewCa = "/opt/homebrew/etc/openssl@3/cert.pem";
    if (FILE* f = fopen(brewCa, "rb")) {
        fclose(f);
        if (SSL_CTX_load_verify_locations(ctx, brewCa, nullptr) == 1) {
            return;
        }
    }
#endif
    SSL_CTX_set_default_verify_paths(ctx);
}

static std::string httpsGet(const Url& u) {
    sslInitOnce();

    SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) throw std::runtime_error("SSL_CTX_new failed");

    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, nullptr);
    configureDefaultCa(ctx);

    int sock = -1;
    SSL* ssl = nullptr;

    try {
        sock = openTcpSocket(u.host, u.port);

        ssl = SSL_new(ctx);
        if (!ssl) throw std::runtime_error("SSL_new failed");

        SSL_set_tlsext_host_name(ssl, u.host.c_str());

        if (SSL_set_fd(ssl, sock) != 1)
            throw std::runtime_error("SSL_set_fd failed");

        if (SSL_connect(ssl) != 1) {
            unsigned long err = ERR_get_error();
            std::string msg = err ? ERR_error_string(err, nullptr) : "SSL_connect failed";
            throw std::runtime_error(msg);
        }

        long verify = SSL_get_verify_result(ssl);
        if (verify != X509_V_OK)
            throw std::runtime_error("TLS certificate verification failed");

        std::ostringstream req;
        req << "GET " << u.path << " HTTP/1.1\r\n"
            << "Host: " << u.host << "\r\n"
            << "User-Agent: NoChrome/0.7\r\n"
            << "Connection: close\r\n\r\n";

        std::string request = req.str();

        int written = 0;
        while (written < (int)request.size()) {
            int n = SSL_write(ssl, request.data() + written,
                              (int)request.size() - written);
            if (n <= 0) throw std::runtime_error("SSL_write failed");
            written += n;
        }

        std::string response;
        char buffer[4096];

        while (true) {
            int n = SSL_read(ssl, buffer, (int)sizeof(buffer));
            if (n <= 0) break;
            response.append(buffer, buffer + n);
        }

        SSL_shutdown(ssl);
        SSL_free(ssl);
        ssl = nullptr;

        closeSock(sock);
        sock = -1;

        SSL_CTX_free(ctx);
        ctx = nullptr;

        return response;

    } catch (...) {
        if (ssl) SSL_free(ssl);
        if (sock >= 0) closeSock(sock);
        if (ctx) SSL_CTX_free(ctx);
        throw;
    }
}

// -------------------- HTML helpers --------------------

static std::vector<std::string> extractStartTagContents(const std::string& html,
                                                        const std::string& tagLower) {
    std::vector<std::string> out;

    std::string lower = toLowerCopy(html);
    std::string needle = "<" + tagLower;

    size_t i = 0;
    while (true) {
        size_t start = lower.find(needle, i);
        if (start == std::string::npos) break;

        size_t end = lower.find('>', start);
        if (end == std::string::npos) break;

        out.push_back(html.substr(start + 1, end - (start + 1)));

        i = end + 1;
    }

    return out;
}

static std::string removeTagBlocks(const std::string& html, const std::string& tag) {
    std::string lower = toLowerCopy(html);
    std::string open = "<" + tag;
    std::string close = "</" + tag + ">";

    std::string out;
    size_t i = 0;

    while (true) {
        size_t start = lower.find(open, i);
        if (start == std::string::npos) {
            out.append(html.substr(i));
            break;
        }

        out.append(html.substr(i, start - i));

        size_t end = lower.find(close, start);
        if (end == std::string::npos) {
            break;
        }

        i = end + close.size();
    }

    return out;
}

static std::vector<std::string> extractTagContents(const std::string& html, const std::string& tag) {
    std::vector<std::string> blocks;

    std::string lower = toLowerCopy(html);
    std::string open = "<" + tag;
    std::string close = "</" + tag + ">";

    size_t i = 0;
    while (true) {
        size_t start = lower.find(open, i);
        if (start == std::string::npos) break;

        size_t openEnd = lower.find('>', start);
        if (openEnd == std::string::npos) break;

        size_t end = lower.find(close, openEnd);
        if (end == std::string::npos) break;

        size_t contentStart = openEnd + 1;
        blocks.push_back(html.substr(contentStart, end - contentStart));

        i = end + close.size();
    }

    return blocks;
}

static std::string decodeEntities(std::string s) {
    auto rep = [&](const std::string& a, const std::string& b){
        size_t pos = 0;
        while ((pos = s.find(a, pos)) != std::string::npos) {
            s.replace(pos, a.size(), b);
            pos += b.size();
        }
    };
    rep("&amp;", "&");
    rep("&lt;", "<");
    rep("&gt;", ">");
    rep("&quot;", "\"");
    rep("&#39;", "'");
    rep("&nbsp;", " ");
    return s;
}

static std::string getAttrValue(const std::string& tagContent, const std::string& attrNameLower) {
    std::string lower = toLowerCopy(tagContent);
    auto pos = lower.find(attrNameLower + "=");
    if (pos == std::string::npos) return "";

    pos += attrNameLower.size() + 1;
    if (pos >= tagContent.size()) return "";

    char quote = tagContent[pos];
    if (quote == '"' || quote == '\'') {
        size_t end = tagContent.find(quote, pos + 1);
        if (end == std::string::npos) return "";
        return tagContent.substr(pos + 1, end - (pos + 1));
    } else {
        size_t end = pos;
        while (end < tagContent.size() &&
               !std::isspace((unsigned char)tagContent[end]) &&
               tagContent[end] != '>') {
            end++;
        }
        return tagContent.substr(pos, end - pos);
    }
}

static std::vector<std::string> parseClassList(const std::string& raw) {
    std::vector<std::string> out;
    std::string s = trimCopy(raw);
    if (s.empty()) return out;

    std::istringstream iss(s);
    std::string c;
    while (iss >> c) out.push_back(toLowerCopy(c));
    return out;
}

// -------------------- CSS v0.x --------------------

struct Style {
    int fontSize = 20;
    SDL_Color color {20, 20, 20, 255};
    bool bold = false;
};

static bool styleEquals(const Style& a, const Style& b) {
    return a.fontSize == b.fontSize &&
           a.bold == b.bold &&
           a.color.r == b.color.r &&
           a.color.g == b.color.g &&
           a.color.b == b.color.b &&
           a.color.a == b.color.a;
}

enum class SelectorType {
    Tag,
    Class,
    Id,
    TagClass
};

struct StyleRule {
    SelectorType type = SelectorType::Tag;
    std::string tag;
    std::string cls;
    std::string id;

    std::optional<int> fontSize;
    std::optional<SDL_Color> color;
    std::optional<bool> bold;

    std::optional<SDL_Color> backgroundColor;
};

static std::optional<SDL_Color> parseColor(const std::string& raw) {
    std::string v = trimCopy(toLowerCopy(raw));
    if (v.empty()) return std::nullopt;

    static std::unordered_map<std::string, SDL_Color> named {
        {"black", {0,0,0,255}},
        {"white", {255,255,255,255}},
        {"red", {255,0,0,255}},
        {"green", {0,255,0,255}},
        {"blue", {0,0,255,255}},
        {"gray", {128,128,128,255}},
        {"grey", {128,128,128,255}},
        {"yellow", {255,255,0,255}},
        {"orange", {255,165,0,255}},
        {"purple", {128,0,128,255}}
    };

    auto it = named.find(v);
    if (it != named.end()) return it->second;

    if (v[0] == '#') {
        if (v.size() == 4) {
            auto hex = [&](char c)->int{
                if (c >= '0' && c <= '9') return c - '0';
                if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
                return 0;
            };
            int r = hex(v[1]); r = r*16 + r;
            int g = hex(v[2]); g = g*16 + g;
            int b = hex(v[3]); b = b*16 + b;
            return SDL_Color{(Uint8)r, (Uint8)g, (Uint8)b, 255};
        }
        if (v.size() == 7) {
            auto hex2 = [&](char c)->int{
                if (c >= '0' && c <= '9') return c - '0';
                if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
                return 0;
            };
            int r = hex2(v[1])*16 + hex2(v[2]);
            int g = hex2(v[3])*16 + hex2(v[4]);
            int b = hex2(v[5])*16 + hex2(v[6]);
            return SDL_Color{(Uint8)r, (Uint8)g, (Uint8)b, 255};
        }
    }

    return std::nullopt;
}

static std::optional<int> parseFontSizePx(const std::string& raw) {
    std::string v = trimCopy(toLowerCopy(raw));
    if (v.empty()) return std::nullopt;

    if (endsWith(v, "px")) {
        v = trimCopy(v.substr(0, v.size() - 2));
    }

    try {
        int n = std::stoi(v);
        n = std::clamp(n, 8, 72);
        return n;
    } catch (...) {
        return std::nullopt;
    }
}

static void applyDeclarationsToRule(StyleRule& rule, const std::string& declsRaw) {
    auto parts = splitBy(declsRaw, ';');
    for (auto& p : parts) {
        auto colon = p.find(':');
        if (colon == std::string::npos) continue;

        std::string key = trimCopy(toLowerCopy(p.substr(0, colon)));
        std::string val = trimCopy(p.substr(colon + 1));

        if (key == "color") {
            auto c = parseColor(val);
            if (c) rule.color = *c;
        } else if (key == "font-size") {
            auto fs = parseFontSizePx(val);
            if (fs) rule.fontSize = *fs;
        } else if (key == "font-weight") {
            std::string v = trimCopy(toLowerCopy(val));
            if (v == "bold" || v == "700") rule.bold = true;
            if (v == "normal" || v == "400") rule.bold = false;
        } else if (key == "background-color" || key == "background") {
            auto c = parseColor(val);
            if (c) rule.backgroundColor = *c;
        }
    }
}

static std::optional<StyleRule> parseSingleSelectorRule(const std::string& selectorRaw,
                                                        const std::string& decls) {
    std::string sel = trimCopy(toLowerCopy(selectorRaw));
    if (sel.empty()) return std::nullopt;

    if (sel.find(' ') != std::string::npos ||
        sel.find('>') != std::string::npos ||
        sel.find('[') != std::string::npos ||
        sel.find(':') != std::string::npos) {
        return std::nullopt;
    }

    StyleRule r;

    if (sel[0] == '.' && sel.size() > 1) {
        r.type = SelectorType::Class;
        r.cls = sel.substr(1);
        applyDeclarationsToRule(r, decls);
        return r;
    }

    if (sel[0] == '#' && sel.size() > 1) {
        r.type = SelectorType::Id;
        r.id = sel.substr(1);
        applyDeclarationsToRule(r, decls);
        return r;
    }

    auto dot = sel.find('.');
    if (dot != std::string::npos && dot > 0 && dot + 1 < sel.size()) {
        r.type = SelectorType::TagClass;
        r.tag = sel.substr(0, dot);
        r.cls = sel.substr(dot + 1);
        applyDeclarationsToRule(r, decls);
        return r;
    }

    r.type = SelectorType::Tag;
    r.tag = sel;
    applyDeclarationsToRule(r, decls);
    return r;
}

static std::vector<StyleRule> parseCssRules(const std::string& cssText) {
    std::vector<StyleRule> rules;
    std::string s = cssText;

    while (true) {
        auto a = s.find("/*");
        if (a == std::string::npos) break;
        auto b = s.find("*/", a + 2);
        if (b == std::string::npos) break;
        s.erase(a, (b - a) + 2);
    }

    size_t i = 0;
    while (i < s.size()) {
        auto brace = s.find('{', i);
        if (brace == std::string::npos) break;

        std::string selectorGroup = s.substr(i, brace - i);

        auto endBrace = s.find('}', brace + 1);
        if (endBrace == std::string::npos) break;

        std::string decls = s.substr(brace + 1, endBrace - (brace + 1));

        auto selectors = splitBy(selectorGroup, ',');
        for (auto& sel : selectors) {
            auto ruleOpt = parseSingleSelectorRule(sel, decls);
            if (ruleOpt) rules.push_back(*ruleOpt);
        }

        i = endBrace + 1;
    }

    return rules;
}

static SDL_Color extractPageBackgroundFromRules(const std::vector<StyleRule>& rules) {
    SDL_Color bg {245, 245, 245, 255};

    for (const auto& r : rules) {
        if (r.type == SelectorType::Tag && r.backgroundColor) {
            if (r.tag == "body" || r.tag == "html") {
                bg = *r.backgroundColor;
            }
        }
    }
    return bg;
}

static void applyTagDefaults(const std::string& tag, Style& st) {
    if (tag == "h1") { st.fontSize = 34; st.bold = true; }
    else if (tag == "h2") { st.fontSize = 28; st.bold = true; }
    else if (tag == "h3") { st.fontSize = 24; st.bold = true; }
    else if (tag == "a") {
        st.color = SDL_Color{120, 180, 255, 255};
    }
}

static void applyInlineStyle(const std::string& inlineCss, Style& st) {
    StyleRule tmp;
    applyDeclarationsToRule(tmp, inlineCss);

    if (tmp.fontSize) st.fontSize = *tmp.fontSize;
    if (tmp.color) st.color = *tmp.color;
    if (tmp.bold) st.bold = *tmp.bold;
}

static bool hasClass(const std::vector<std::string>& classes, const std::string& cls) {
    for (const auto& c : classes) if (c == cls) return true;
    return false;
}

static void applyRulesForElement(const std::vector<StyleRule>& rules,
                                 const std::string& tag,
                                 const std::string& id,
                                 const std::vector<std::string>& classes,
                                 Style& st) {
    for (const auto& r : rules) {
        if (r.type == SelectorType::Tag && r.tag == tag) {
            if (r.fontSize) st.fontSize = *r.fontSize;
            if (r.color) st.color = *r.color;
            if (r.bold) st.bold = *r.bold;
        }
    }

    for (const auto& r : rules) {
        if (r.type == SelectorType::Class && hasClass(classes, r.cls)) {
            if (r.fontSize) st.fontSize = *r.fontSize;
            if (r.color) st.color = *r.color;
            if (r.bold) st.bold = *r.bold;
        }
    }

    for (const auto& r : rules) {
        if (r.type == SelectorType::TagClass && r.tag == tag && hasClass(classes, r.cls)) {
            if (r.fontSize) st.fontSize = *r.fontSize;
            if (r.color) st.color = *r.color;
            if (r.bold) st.bold = *r.bold;
        }
    }

    for (const auto& r : rules) {
        if (r.type == SelectorType::Id && !id.empty() && r.id == id) {
            if (r.fontSize) st.fontSize = *r.fontSize;
            if (r.color) st.color = *r.color;
            if (r.bold) st.bold = *r.bold;
        }
    }
}

// -------------------- Tokens & spacing --------------------

enum class TokenKind { Word, Break };

struct StyledToken {
    TokenKind kind;
    std::string text;
    std::string href;
    Style style;
    int breakCount = 1;
};

static bool isBlockTagName(const std::string& name) {
    return name == "p" || name == "/p" ||
           name == "div" || name == "/div" ||
           name == "h1" || name == "/h1" ||
           name == "h2" || name == "/h2" ||
           name == "h3" || name == "/h3" ||
           name == "ul" || name == "/ul" ||
           name == "ol" || name == "/ol" ||
           name == "li" || name == "/li" ||
           name == "br";
}

static int defaultBreakCountForTag(const std::string& tagNameLower) {
    if (tagNameLower == "h1" || tagNameLower == "/h1" ||
        tagNameLower == "h2" || tagNameLower == "/h2" ||
        tagNameLower == "h3" || tagNameLower == "/h3") {
        return 2;
    }
    if (tagNameLower == "p" || tagNameLower == "/p" ||
        tagNameLower == "li" || tagNameLower == "/li") {
        return 1;
    }
    if (tagNameLower == "div" || tagNameLower == "/div" ||
        tagNameLower == "ul" || tagNameLower == "/ul" ||
        tagNameLower == "ol" || tagNameLower == "/ol") {
        return 1;
    }
    if (tagNameLower == "br") return 1;
    return 1;
}

// Fetch CSS subresource by absolute URL (http/https)
static std::string fetchSubresourceBody(const std::string& absUrl) {
    try {
        Url u = parseUrl(absUrl);
        netInit();
        std::string resp = (u.scheme == "https") ? httpsGet(u) : httpGet(u);
        netCleanup();
        return extractBody(resp);
    } catch (...) {
        netCleanup();
        return "";
    }
}

static std::vector<StyledToken> parseHtmlToStyledTokens(const std::string& html,
                                                        const Url& baseUrl,
                                                        SDL_Color* outPageBg) {
    std::string cssAll;

    for (auto& block : extractTagContents(html, "style")) {
        cssAll += block;
        cssAll.push_back('\n');
    }

    int externalCount = 0;
    auto linkTags = extractStartTagContents(html, "link");
    for (const auto& tagContent : linkTags) {
        if (externalCount >= 8) break;

        std::string rel = toLowerCopy(getAttrValue(tagContent, "rel"));
        if (rel.find("stylesheet") == std::string::npos) continue;

        std::string href = trimCopy(getAttrValue(tagContent, "href"));
        if (href.empty()) continue;

        std::string abs = resolveHref(baseUrl, href);
        if (abs.empty()) continue;

        std::string css = fetchSubresourceBody(abs);
        if (!css.empty()) {
            cssAll += "\n";
            cssAll += css;
            cssAll += "\n";
            externalCount++;
        }
    }

    auto rules = parseCssRules(cssAll);

    if (outPageBg) {
        *outPageBg = extractPageBackgroundFromRules(rules);
    }

    std::string cleaned = removeTagBlocks(html, "script");
    cleaned = removeTagBlocks(cleaned, "style");
    cleaned = removeTagBlocks(cleaned, "head");

    std::vector<StyledToken> tokens;

    bool inTag = false;
    std::string tagBuf;
    std::string textBuf;

    std::vector<Style> styleStack;
    std::vector<std::string> hrefStack;

    Style base;
    styleStack.push_back(base);
    hrefStack.push_back("");

    auto currentStyle = [&]()->Style {
        return styleStack.empty() ? base : styleStack.back();
    };
    auto currentHref = [&]()->std::string {
        return hrefStack.empty() ? "" : hrefStack.back();
    };

    auto pushBreakN = [&](int n){
        if (n <= 0) return;
        StyledToken bt;
        bt.kind = TokenKind::Break;
        bt.style = base;
        bt.breakCount = n;
        tokens.push_back(bt);
    };

    auto flushText = [&](){
        std::string t = decodeEntities(textBuf);
        textBuf.clear();

        t = trimCopy(t);
        if (t.empty()) return;

        std::istringstream iss(t);
        std::string w;
        Style st = currentStyle();
        std::string href = currentHref();

        while (iss >> w) {
            StyledToken tok;
            tok.kind = TokenKind::Word;
            tok.text = w;
            tok.href = href;
            tok.style = st;
            tokens.push_back(std::move(tok));
        }
    };

    auto popOne = [&](){
        if (styleStack.size() > 1) styleStack.pop_back();
        if (hrefStack.size() > 1) hrefStack.pop_back();
    };

    auto processTag = [&](const std::string& raw){
        std::string t = trimCopy(raw);
        if (t.empty()) return;

        if (!t.empty() && (t[0] == '!' || t[0] == '?')) return;

        std::string lower = toLowerCopy(t);
        bool isEnd = (!lower.empty() && lower[0] == '/');

        size_t i = isEnd ? 1 : 0;
        std::string name;
        while (i < lower.size() && std::isalpha((unsigned char)lower[i])) {
            name.push_back(lower[i]);
            i++;
        }
        if (name.empty()) return;

        bool selfClosing = (lower.find("/>") != std::string::npos);
        std::string fullName = isEnd ? ("/" + name) : name;

        if (name == "br") {
            pushBreakN(1);
            return;
        }

        if (isEnd) {
            if (isBlockTagName(fullName)) {
                pushBreakN(defaultBreakCountForTag(fullName));
            }
            popOne();
            return;
        }

        Style st = currentStyle();

        std::string id = trimCopy(getAttrValue(t, "id"));
        std::string classAttr = getAttrValue(t, "class");
        auto classes = parseClassList(classAttr);

        applyTagDefaults(name, st);
        applyRulesForElement(rules, name, toLowerCopy(id), classes, st);

        std::string inlineCss = getAttrValue(t, "style");
        if (!inlineCss.empty()) applyInlineStyle(inlineCss, st);

        styleStack.push_back(st);

        std::string href = currentHref();
        if (name == "a") {
            href = trimCopy(getAttrValue(t, "href"));
        }
        hrefStack.push_back(href);

        if (isBlockTagName(name)) {
            pushBreakN(defaultBreakCountForTag(name));
        }

        if (selfClosing) {
            popOne();
        }
    };

    for (size_t idx = 0; idx < cleaned.size(); ++idx) {
        char c = cleaned[idx];

        if (!inTag) {
            if (c == '<') {
                flushText();
                inTag = true;
                tagBuf.clear();
            } else {
                textBuf.push_back(c);
            }
        } else {
            if (c == '>') {
                inTag = false;
                processTag(tagBuf);
            } else {
                tagBuf.push_back(c);
            }
        }
    }
    flushText();

    while (!tokens.empty() && tokens.back().kind == TokenKind::Break)
        tokens.pop_back();

    return tokens;
}

// -------------------- Fonts by size --------------------

struct FontSet {
    TTF_Font* f16 = nullptr;
    TTF_Font* f20 = nullptr;
    TTF_Font* f24 = nullptr;
    TTF_Font* f28 = nullptr;
    TTF_Font* f34 = nullptr;
};

static std::string findFontPath() {
    if (FILE* f = fopen("fonts/DejaVuSans.ttf", "rb")) { fclose(f); return "fonts/DejaVuSans.ttf"; }
    if (FILE* f = fopen("DejaVuSans.ttf", "rb")) { fclose(f); return "DejaVuSans.ttf"; }

#ifdef __APPLE__
    if (FILE* f = fopen("/System/Library/Fonts/Supplemental/Arial.ttf", "rb")) { fclose(f); return "/System/Library/Fonts/Supplemental/Arial.ttf"; }
    if (FILE* f = fopen("/System/Library/Fonts/Supplemental/Helvetica.ttf", "rb")) { fclose(f); return "/System/Library/Fonts/Supplemental/Helvetica.ttf"; }
#endif

#ifdef __linux__
    if (FILE* f = fopen("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", "rb")) { fclose(f); return "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"; }
#endif

    return "";
}

static bool loadFontSet(FontSet& fs) {
    std::string path = findFontPath();
    if (path.empty()) return false;

    fs.f16 = TTF_OpenFont(path.c_str(), 16);
    fs.f20 = TTF_OpenFont(path.c_str(), 20);
    fs.f24 = TTF_OpenFont(path.c_str(), 24);
    fs.f28 = TTF_OpenFont(path.c_str(), 28);
    fs.f34 = TTF_OpenFont(path.c_str(), 34);

    return fs.f16 && fs.f20 && fs.f24 && fs.f28 && fs.f34;
}

static void freeFontSet(FontSet& fs) {
    if (fs.f16) TTF_CloseFont(fs.f16);
    if (fs.f20) TTF_CloseFont(fs.f20);
    if (fs.f24) TTF_CloseFont(fs.f24);
    if (fs.f28) TTF_CloseFont(fs.f28);
    if (fs.f34) TTF_CloseFont(fs.f34);
    fs = {};
}

static TTF_Font* pickFont(const FontSet& fs, int size) {
    struct Candidate { int s; TTF_Font* f; };
    std::vector<Candidate> c {
        {16, fs.f16}, {20, fs.f20}, {24, fs.f24}, {28, fs.f28}, {34, fs.f34}
    };
    int bestD = 1e9;
    TTF_Font* best = fs.f20;
    for (auto& x : c) {
        if (!x.f) continue;
        int d = std::abs(x.s - size);
        if (d < bestD) { bestD = d; best = x.f; }
    }
    return best ? best : fs.f20;
}

static int textWidth(TTF_Font* font, const std::string& s) {
    int w = 0, h = 0;
    if (!font) return 0;
    if (TTF_SizeUTF8(font, s.c_str(), &w, &h) != 0) return 0;
    return w;
}

static SDL_Surface* renderTextWithStyle(TTF_Font* font, const std::string& text, const Style& st) {
    if (!font) return nullptr;

    int old = TTF_GetFontStyle(font);
    int style = TTF_STYLE_NORMAL;
    if (st.bold) style |= TTF_STYLE_BOLD;

    TTF_SetFontStyle(font, style);
    SDL_Surface* surf = TTF_RenderUTF8_Blended(font, text.c_str(), st.color);
    TTF_SetFontStyle(font, old);

    return surf;
}

// -------------------- Layout structures --------------------

struct StyledWord {
    std::string text;
    std::string href;
    Style style;
};

struct RenderSpan {
    std::string text;
    std::string href;
    Style style;

    SDL_Texture* texture = nullptr;
    int w = 0;
    int h = 0;
};

struct RenderLine {
    std::vector<RenderSpan> spans;
};

struct LinkHit {
    SDL_Rect rect;
    std::string href;
};

static void destroyLines(std::vector<RenderLine>& lines) {
    for (auto& line : lines) {
        for (auto& sp : line.spans) {
            if (sp.texture) SDL_DestroyTexture(sp.texture);
            sp.texture = nullptr;
        }
    }
    lines.clear();
}

static std::vector<std::vector<StyledWord>> wrapTokensToWordLines(
    const FontSet& fonts,
    const std::vector<StyledToken>& tokens,
    int maxWidth)
{
    std::vector<std::vector<StyledWord>> lines;
    std::vector<StyledWord> current;
    int lineW = 0;

    auto flushLine = [&](){
        if (!current.empty()) {
            lines.push_back(current);
            current.clear();
            lineW = 0;
        }
    };

    auto pushEmptyLine = [&](){
        lines.push_back({});
    };

    for (const auto& t : tokens) {
        if (t.kind == TokenKind::Break) {
            flushLine();
            for (int k = 0; k < std::max(1, t.breakCount); ++k) {
                pushEmptyLine();
            }
            continue;
        }

        StyledWord w { t.text, t.href, t.style };
        TTF_Font* f = pickFont(fonts, w.style.fontSize);

        int wW = textWidth(f, w.text);
        int spaceW = textWidth(f, " ");
        int add = current.empty() ? wW : (spaceW + wW);

        if (!current.empty() && lineW + add > maxWidth) {
            flushLine();
        }

        if (current.empty()) {
            lineW = wW;
            current.push_back(std::move(w));
        } else {
            lineW += add;
            current.push_back(std::move(w));
        }
    }

    flushLine();

    while (!lines.empty() && lines.back().empty())
        lines.pop_back();

    return lines;
}

static std::vector<RenderSpan> groupWordsToSpans(const std::vector<StyledWord>& words) {
    std::vector<RenderSpan> spans;
    if (words.empty()) return spans;

    RenderSpan cur;
    cur.text = words[0].text;
    cur.href = words[0].href;
    cur.style = words[0].style;

    for (size_t i = 1; i < words.size(); ++i) {
        bool sameHref = (words[i].href == cur.href);
        bool sameStyle = styleEquals(words[i].style, cur.style);

        if (sameHref && sameStyle) {
            cur.text += " " + words[i].text;
        } else {
            spans.push_back(cur);
            cur.text = words[i].text;
            cur.href = words[i].href;
            cur.style = words[i].style;
        }
    }

    spans.push_back(cur);
    return spans;
}

static std::vector<RenderLine> buildRenderLines(
    SDL_Renderer* renderer,
    const FontSet& fonts,
    const std::vector<std::vector<StyledWord>>& wordLines)
{
    std::vector<RenderLine> out;
    out.reserve(wordLines.size());

    for (const auto& wl : wordLines) {
        RenderLine line;
        auto spans = groupWordsToSpans(wl);

        for (auto& sp : spans) {
            TTF_Font* f = pickFont(fonts, sp.style.fontSize);

            SDL_Surface* surf = renderTextWithStyle(f, sp.text, sp.style);
            if (!surf) {
                line.spans.push_back(std::move(sp));
                continue;
            }

            sp.w = surf->w;
            sp.h = surf->h;
            sp.texture = SDL_CreateTextureFromSurface(renderer, surf);
            SDL_FreeSurface(surf);

            line.spans.push_back(std::move(sp));
        }

        out.push_back(std::move(line));
    }

    return out;
}

static std::vector<LinkHit> buildLinkHits(
    const std::vector<RenderLine>& lines,
    const FontSet& fonts,
    int padding,
    int lineHeight)
{
    std::vector<LinkHit> hits;

    for (int i = 0; i < (int)lines.size(); ++i) {
        int x = padding;
        int y = padding + i * lineHeight;

        for (const auto& sp : lines[i].spans) {
            SDL_Rect r { x, y, sp.w, sp.h };

            if (!sp.href.empty() && sp.w > 0 && sp.h > 0) {
                hits.push_back({ r, sp.href });
            }

            TTF_Font* f = pickFont(fonts, sp.style.fontSize);
            x += sp.w + textWidth(f, " ");
        }
    }

    return hits;
}

// -------------------- Page state --------------------

struct Page {
    Url baseUrl;
    std::string urlString;
    std::string body;

    SDL_Color background {245, 245, 245, 255};

    std::vector<RenderLine> lines;
    std::vector<LinkHit> linkHits;
};

static std::string loadPageBody(const std::string& urlString, Url& outUrl) {
    std::string normalized = normalizeUserUrl(urlString);
    outUrl = parseUrl(normalized);

    try {
        netInit();
        std::string resp = (outUrl.scheme == "https") ? httpsGet(outUrl) : httpGet(outUrl);
        netCleanup();
        return extractBody(resp);
    } catch (const std::exception& ex) {
        netCleanup();
        return std::string("<h2>Network error</h2><p>") + ex.what() + "</p>";
    }
}

static void rebuildLayout(
    Page& page,
    SDL_Renderer* renderer,
    const FontSet& fonts,
    int contentWidth,
    int padding,
    int lineHeight)
{
    destroyLines(page.lines);

    SDL_Color bg = page.background;
    auto tokens = parseHtmlToStyledTokens(page.body, page.baseUrl, &bg);
    page.background = bg;

    auto wordLines = wrapTokensToWordLines(fonts, tokens, contentWidth - padding * 2);

    page.lines = buildRenderLines(renderer, fonts, wordLines);
    page.linkHits = buildLinkHits(page.lines, fonts, padding, lineHeight);
}

// -------------------- UI helpers --------------------

static bool pointInRect(int x, int y, const SDL_Rect& r) {
    return x >= r.x && x < r.x + r.w && y >= r.y && y < r.y + r.h;
}

static void drawFilledRect(SDL_Renderer* r, const SDL_Rect& rect,
                           Uint8 R, Uint8 G, Uint8 B, Uint8 A=255) {
    SDL_SetRenderDrawColor(r, R, G, B, A);
    SDL_RenderFillRect(r, &rect);
}

// -------------------- main --------------------

int main(int argc, char** argv) {
    std::string startUrl = "https://example.com/";
    if (argc >= 2) startUrl = argv[1];

    if (SDL_Init(SDL_INIT_VIDEO) != 0) {
        SDL_LogError(SDL_LOG_CATEGORY_APPLICATION,
                     "SDL init failed: %s", SDL_GetError());
        return 1;
    }
    if (TTF_Init() != 0) {
        SDL_LogError(SDL_LOG_CATEGORY_APPLICATION,
                     "TTF init failed: %s", TTF_GetError());
        SDL_Quit();
        return 1;
    }

    SDL_Window* window = SDL_CreateWindow(
        "NoChrome Browser",
        SDL_WINDOWPOS_CENTERED, SDL_WINDOWPOS_CENTERED,
        1100, 750,
        SDL_WINDOW_RESIZABLE
    );
    if (!window) {
        SDL_LogError(SDL_LOG_CATEGORY_APPLICATION,
                     "Window create failed: %s", SDL_GetError());
        TTF_Quit(); SDL_Quit();
        return 1;
    }

    SDL_Renderer* renderer = SDL_CreateRenderer(window, -1,
        SDL_RENDERER_ACCELERATED | SDL_RENDERER_PRESENTVSYNC);
    if (!renderer) {
        SDL_LogError(SDL_LOG_CATEGORY_APPLICATION,
                     "Renderer create failed: %s", SDL_GetError());
        SDL_DestroyWindow(window);
        TTF_Quit(); SDL_Quit();
        return 1;
    }

    FontSet fonts;
    if (!loadFontSet(fonts)) {
        SDL_LogError(SDL_LOG_CATEGORY_APPLICATION,
                     "Could not load a font. Add ./fonts/DejaVuSans.ttf");
        SDL_DestroyRenderer(renderer);
        SDL_DestroyWindow(window);
        TTF_Quit(); SDL_Quit();
        return 1;
    }

    const int topBarH = 56;
    const int padding = 18;

    int winW = 1100, winH = 750;
    SDL_GetWindowSize(window, &winW, &winH);

    int contentWidth = winW;
    int lineHeight = 32;

    auto calcAddressRect = [&](int w){
        SDL_Rect r;
        r.x = 12;
        r.y = 10;
        r.w = std::max(200, w - 24);
        r.h = topBarH - 20;
        return r;
    };

    SDL_Rect addressRect = calcAddressRect(winW);

    Page page;
    page.urlString = normalizeUserUrl(startUrl);
    page.body = loadPageBody(page.urlString, page.baseUrl);

    rebuildLayout(page, renderer, fonts, contentWidth, padding, lineHeight);
    SDL_SetWindowTitle(window, ("NoChrome Browser - " + page.urlString).c_str());

    bool addressFocused = false;
    std::string addressInput = page.urlString;

    auto focusAddress = [&](){
        addressFocused = true;
        SDL_StartTextInput();
        addressInput = page.urlString;
    };

    auto blurAddress = [&](){
        addressFocused = false;
        SDL_StopTextInput();
    };

    auto loadUrlIntoPage = [&](const std::string& rawUrl){
        std::string norm = normalizeUserUrl(rawUrl);
        Url u;
        std::string body = loadPageBody(norm, u);

        page.baseUrl = u;
        page.urlString = norm;
        page.body = body;

        rebuildLayout(page, renderer, fonts, contentWidth, padding, lineHeight);

        addressInput = page.urlString;
        SDL_SetWindowTitle(window, ("NoChrome Browser - " + page.urlString).c_str());
    };

    float scrollYf = 0.0f;

    auto maxScroll = [&](){
        int contentH = (int)page.lines.size() * lineHeight + padding * 2;
        int viewH = std::max(10, winH - topBarH);
        return std::max(0, contentH - viewH);
    };

    auto clampScroll = [&](){
        float m = (float)maxScroll();
        if (scrollYf < 0) scrollYf = 0;
        if (scrollYf > m) scrollYf = m;
    };
    clampScroll();

    TTF_Font* uiFont = fonts.f16;

    auto renderUiText = [&](const std::string& text, SDL_Color col){
        if (!uiFont) return (SDL_Texture*)nullptr;
        SDL_Surface* surf = TTF_RenderUTF8_Blended(uiFont, text.c_str(), col);
        if (!surf) return (SDL_Texture*)nullptr;
        SDL_Texture* tex = SDL_CreateTextureFromSurface(renderer, surf);
        SDL_FreeSurface(surf);
        return tex;
    };

    bool running = true;
    while (running) {
        SDL_Event e;
        while (SDL_PollEvent(&e)) {
            switch (e.type) {
                case SDL_QUIT:
                    running = false;
                    break;

                case SDL_WINDOWEVENT:
                    if (e.window.event == SDL_WINDOWEVENT_SIZE_CHANGED) {
                        winW = e.window.data1;
                        winH = e.window.data2;

                        addressRect = calcAddressRect(winW);
                        contentWidth = winW;

                        rebuildLayout(page, renderer, fonts, contentWidth, padding, lineHeight);
                        clampScroll();
                    }
                    break;

                case SDL_MOUSEWHEEL: {
                    float dy = (e.wheel.preciseY != 0.0f) ? e.wheel.preciseY : (float)e.wheel.y;
                    scrollYf -= dy * (float)lineHeight * 2.0f;
                    clampScroll();
                    break;
                }

                case SDL_MOUSEBUTTONDOWN: {
                    int mx = e.button.x;
                    int my = e.button.y;

                    if (pointInRect(mx, my, addressRect)) {
                        focusAddress();
                        break;
                    } else {
                        blurAddress();
                    }

                    if (my >= topBarH && e.button.button == SDL_BUTTON_LEFT) {
                        int scrollY = (int)scrollYf;
                        int contentY = (my - topBarH) + scrollY;

                        for (const auto& hit : page.linkHits) {
                            SDL_Rect r = hit.rect;

                            if (mx >= r.x && mx < r.x + r.w &&
                                contentY >= r.y && contentY < r.y + r.h) {

                                std::string abs = resolveHref(page.baseUrl, hit.href);
                                if (abs.empty()) break;

                                loadUrlIntoPage(abs);
                                scrollYf = 0;
                                clampScroll();
                                break;
                            }
                        }
                    }
                    break;
                }

                case SDL_TEXTINPUT:
                    if (addressFocused) {
                        addressInput += e.text.text;
                    }
                    break;

                case SDL_KEYDOWN: {
                    bool ctrl = (e.key.keysym.mod & KMOD_CTRL);

                    if (e.key.keysym.sym == SDLK_ESCAPE) {
                        running = false;
                    }

                    if (ctrl && e.key.keysym.sym == SDLK_l) {
                        focusAddress();
                        break;
                    }

                    if (addressFocused) {
                        if (e.key.keysym.sym == SDLK_BACKSPACE) {
                            if (!addressInput.empty()) addressInput.pop_back();
                        } else if (e.key.keysym.sym == SDLK_RETURN || e.key.keysym.sym == SDLK_KP_ENTER) {
                            loadUrlIntoPage(addressInput);
                            scrollYf = 0;
                            clampScroll();
                            blurAddress();
                        }
                    } else {
                        if (e.key.keysym.sym == SDLK_DOWN) { scrollYf += lineHeight; clampScroll(); }
                        if (e.key.keysym.sym == SDLK_UP)   { scrollYf -= lineHeight; clampScroll(); }
                        if (e.key.keysym.sym == SDLK_PAGEDOWN) { scrollYf += (winH - topBarH) * 0.5f; clampScroll(); }
                        if (e.key.keysym.sym == SDLK_PAGEUP)   { scrollYf -= (winH - topBarH) * 0.5f; clampScroll(); }
                        if (e.key.keysym.sym == SDLK_HOME) { scrollYf = 0; clampScroll(); }
                        if (e.key.keysym.sym == SDLK_END)  { scrollYf = (float)maxScroll(); clampScroll(); }
                    }

                    break;
                }
            }
        }

        SDL_SetRenderDrawColor(renderer, 16, 16, 18, 255);
        SDL_RenderClear(renderer);

        SDL_Rect topBar { 0, 0, winW, topBarH };
        drawFilledRect(renderer, topBar, 24, 24, 28);

        drawFilledRect(renderer, addressRect,
                       addressFocused ? 38 : 32,
                       addressFocused ? 38 : 32,
                       addressFocused ? 44 : 40);

        SDL_SetRenderDrawColor(renderer,
                               addressFocused ? 90 : 60,
                               addressFocused ? 140 : 60,
                               addressFocused ? 200 : 60,
                               255);
        SDL_RenderDrawRect(renderer, &addressRect);

        {
            SDL_Color col { 230, 230, 230, 255 };
            std::string shown = addressFocused ? addressInput : page.urlString;
            if (shown.empty()) shown = "http://";

            SDL_Texture* tex = renderUiText(shown, col);
            if (tex) {
                int tw=0, th=0;
                SDL_QueryTexture(tex, nullptr, nullptr, &tw, &th);

                SDL_Rect dst {
                    addressRect.x + 10,
                    addressRect.y + (addressRect.h - th) / 2,
                    std::min(tw, addressRect.w - 20),
                    th
                };
                SDL_RenderCopy(renderer, tex, nullptr, &dst);
                SDL_DestroyTexture(tex);
            }
        }

        SDL_Rect contentBg { 0, topBarH, winW, winH - topBarH };
        drawFilledRect(renderer, contentBg,
                       page.background.r,
                       page.background.g,
                       page.background.b,
                       page.background.a);

        int scrollY = (int)scrollYf;
        int viewH = std::max(1, winH - topBarH);

        int startIndex = std::max(0, (scrollY - padding) / lineHeight);
        int endIndex = std::min((int)page.lines.size(), startIndex + (viewH / lineHeight) + 6);

        for (int i = startIndex; i < endIndex; ++i) {
            int x = padding;
            int yScreen = topBarH + padding + i * lineHeight - scrollY;

            const auto& line = page.lines[i];

            for (const auto& sp : line.spans) {
                if (sp.texture) {
                    SDL_Rect dst { x, yScreen, sp.w, sp.h };
                    SDL_RenderCopy(renderer, sp.texture, nullptr, &dst);

                    if (!sp.href.empty()) {
                        SDL_SetRenderDrawColor(renderer,
                                               sp.style.color.r,
                                               sp.style.color.g,
                                               sp.style.color.b, 255);
                        SDL_Rect ul { x, yScreen + sp.h + 2, sp.w, 1 };
                        SDL_RenderFillRect(renderer, &ul);
                    }
                }

                TTF_Font* f = pickFont(fonts, sp.style.fontSize);
                x += sp.w + textWidth(f, " ");
            }
        }

        SDL_RenderPresent(renderer);
    }

    destroyLines(page.lines);
    freeFontSet(fonts);

    SDL_DestroyRenderer(renderer);
    SDL_DestroyWindow(window);

    TTF_Quit();
    SDL_Quit();

    return 0;
}