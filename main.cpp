#include <SDL.h>
#include <SDL_ttf.h>
#include <SDL_image.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

#ifdef NOCHROME_ENABLE_JS

// Choose the JavaScript engine: JavaScriptCore on macOS (or when explicitly
// forced, e.g. WebKitGTK's JSC for testing on Linux); QuickJS otherwise.
#if defined(__APPLE__) || defined(NOCHROME_FORCE_JSC)
#define NOCHROME_USE_JSC 1
#endif

#if defined(NOCHROME_USE_JSC)
#if defined(__APPLE__)
#include <JavaScriptCore/JavaScriptCore.h>
#else
#include <JavaScriptCore/JavaScript.h>
#endif
#else
extern "C" {
#if __has_include(<quickjs.h>)
#include <quickjs.h>
#elif __has_include(<quickjs/quickjs.h>)
#include <quickjs/quickjs.h>
#else
#error "QuickJS headers not found. Install QuickJS (brew install quickjs) and ensure include path is set."
#endif
}
#endif
#endif

#include <iostream>
#include <string>
#include <sstream>
#include <vector>
#include <algorithm>
#include <cctype>
#include <optional>
#include <unordered_map>
#include <unordered_set>
#include <chrono>
#include <regex>
#include <cmath>
#include <cstdio>
#include <cstdint>
#include <zlib.h>

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


static std::string toUpperCopy(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c){ return (char)std::toupper(c); });
    return s;
}

static std::string escapeHtmlEntities(const std::string& s) {
    std::string out;
    out.reserve(s.size());
    for (char c : s) {
        switch (c) {
            case '&': out += "&amp;"; break;
            case '<': out += "&lt;"; break;
            case '>': out += "&gt;"; break;
            case '"': out += "&quot;"; break;
            case '\'': out += "&#39;"; break;
            default: out.push_back(c); break;
        }
    }
    return out;
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
    if (startsWith(href, "//")) return base.scheme + ":" + href;
    if (href[0] == '#') return "";

    const std::string origin = buildOrigin(base);

    if (href[0] == '/') {
        return origin + href;
    }

    std::string dir = dirnameOfPath(base.path);
    return origin + dir + href;
}

static std::string hostHeaderValue(const Url& u) {
    bool isHttpDefault  = (u.scheme == "http"  && u.port == 80);
    bool isHttpsDefault = (u.scheme == "https" && u.port == 443);

    if (!isHttpDefault && !isHttpsDefault && u.port > 0) {
        return u.host + ":" + std::to_string(u.port);
    }
    return u.host;
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

static std::string httpGetRaw(const Url& u) {
    int sock = openTcpSocket(u.host, u.port);

    std::ostringstream req;
    req << "GET " << u.path << " HTTP/1.1\r\n"
        << "Host: " << hostHeaderValue(u) << "\r\n"
        << "User-Agent: NoChrome/0.8\r\n"
        << "Accept: */*\r\n"
        << "Accept-Encoding: gzip, deflate\r\n"
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

static std::string httpsGetRaw(const Url& u) {
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
            << "Host: " << hostHeaderValue(u) << "\r\n"
            << "User-Agent: NoChrome/0.8\r\n"
            << "Accept: */*\r\n"
            << "Accept-Encoding: gzip, deflate\r\n"
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

// -------------------- HTTP parsing (incl. chunked) --------------------

struct HttpParts {
    std::string headers;
    std::string body;
};

static HttpParts splitHeadersBody(const std::string& raw) {
    HttpParts p;
    auto pos = raw.find("\r\n\r\n");
    if (pos == std::string::npos) {
        p.body = raw;
        return p;
    }
    p.headers = raw.substr(0, pos);
    p.body = raw.substr(pos + 4);
    return p;
}

static bool headerContainsCI(const std::string& headers, const std::string& needleLower) {
    std::string h = toLowerCopy(headers);
    return h.find(needleLower) != std::string::npos;
}

static std::string decodeChunkedBody(const std::string& chunked) {
    std::string out;
    size_t i = 0;

    auto readLine = [&](std::string& line)->bool{
        size_t eol = chunked.find("\r\n", i);
        if (eol == std::string::npos) return false;
        line = chunked.substr(i, eol - i);
        i = eol + 2;
        return true;
    };

    while (true) {
        std::string line;
        if (!readLine(line)) break;

        auto semi = line.find(';');
        if (semi != std::string::npos) line = line.substr(0, semi);
        line = trimCopy(line);
        if (line.empty()) break;

        size_t chunkSize = 0;
        try {
            chunkSize = std::stoul(line, nullptr, 16);
        } catch (...) {
            break;
        }

        if (chunkSize == 0) {
            break;
        }

        if (i + chunkSize > chunked.size()) break;

        out.append(chunked.data() + i, chunkSize);
        i += chunkSize;

        if (i + 2 <= chunked.size() && chunked[i] == '\r' && chunked[i+1] == '\n') {
            i += 2;
        } else {
            break;
        }
    }

    return out;
}

static std::string extractBodyBytes(const std::string& rawResponse) {
    auto parts = splitHeadersBody(rawResponse);
    if (headerContainsCI(parts.headers, "transfer-encoding: chunked")) {
        return decodeChunkedBody(parts.body);
    }
    return parts.body;
}

// -------------------- HTTP headers / compression / charset / redirects --------------------

// Case-insensitive lookup of a single header value in a raw header block.
static std::string headerValueCI(const std::string& headers, const std::string& nameLower) {
    std::istringstream iss(headers);
    std::string line;
    while (std::getline(iss, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        size_t colon = line.find(':');
        if (colon == std::string::npos) continue;
        if (toLowerCopy(trimCopy(line.substr(0, colon))) == nameLower) {
            return trimCopy(line.substr(colon + 1));
        }
    }
    return "";
}

// Numeric status code from the HTTP status line ("HTTP/1.1 301 ...").
static int parseStatusCode(const std::string& headers) {
    size_t eol = headers.find("\r\n");
    std::string status = (eol == std::string::npos) ? headers : headers.substr(0, eol);
    size_t sp = status.find(' ');
    if (sp == std::string::npos) return 0;
    size_t p = sp + 1;
    while (p < status.size() && status[p] == ' ') p++;
    int code = 0;
    while (p < status.size() && std::isdigit((unsigned char)status[p])) {
        code = code * 10 + (status[p] - '0');
        p++;
    }
    return code;
}

// Inflate gzip/zlib/raw-deflate. windowBits: 47 = auto-detect gzip|zlib header,
// -MAX_WBITS = raw deflate (no header).
static bool zinflateInto(const std::string& in, std::string& out, int windowBits) {
    if (in.empty()) return false;
    z_stream zs = {};
    if (inflateInit2(&zs, windowBits) != Z_OK) return false;

    zs.next_in = (Bytef*)in.data();
    zs.avail_in = (uInt)in.size();

    char buf[16384];
    int ret = Z_OK;
    do {
        zs.next_out = (Bytef*)buf;
        zs.avail_out = sizeof(buf);
        ret = inflate(&zs, Z_NO_FLUSH);
        if (ret != Z_OK && ret != Z_STREAM_END) { inflateEnd(&zs); return false; }
        out.append(buf, sizeof(buf) - zs.avail_out);
    } while (ret != Z_STREAM_END);

    inflateEnd(&zs);
    return true;
}

static std::string maybeDecompress(const std::string& headers, const std::string& body) {
    std::string enc = toLowerCopy(headerValueCI(headers, "content-encoding"));
    if (enc.empty() || enc == "identity") return body;
    if (enc.find("gzip") == std::string::npos && enc.find("deflate") == std::string::npos)
        return body;

    std::string out;
    if (zinflateInto(body, out, 47)) return out;          // gzip or zlib (auto-detect)
    out.clear();
    if (zinflateInto(body, out, -MAX_WBITS)) return out;  // raw deflate fallback
    return body;                                          // could not inflate
}

static void appendUtf8(std::string& out, unsigned cp) {
    if (cp < 0x80) {
        out.push_back((char)cp);
    } else if (cp < 0x800) {
        out.push_back((char)(0xC0 | (cp >> 6)));
        out.push_back((char)(0x80 | (cp & 0x3F)));
    } else {
        out.push_back((char)(0xE0 | (cp >> 12)));
        out.push_back((char)(0x80 | ((cp >> 6) & 0x3F)));
        out.push_back((char)(0x80 | (cp & 0x3F)));
    }
}

// Windows-1252 (also used for iso-8859-1 / latin1, per the HTML standard) -> UTF-8.
static std::string win1252ToUtf8(const std::string& in) {
    static const unsigned hi[32] = {
        0x20AC, 0x0081, 0x201A, 0x0192, 0x201E, 0x2026, 0x2020, 0x2021,
        0x02C6, 0x2030, 0x0160, 0x2039, 0x0152, 0x008D, 0x017D, 0x008F,
        0x0090, 0x2018, 0x2019, 0x201C, 0x201D, 0x2022, 0x2013, 0x2014,
        0x02DC, 0x2122, 0x0161, 0x203A, 0x0153, 0x009D, 0x017E, 0x0178
    };
    std::string out;
    out.reserve(in.size());
    for (unsigned char c : in) {
        if (c < 0x80) out.push_back((char)c);
        else if (c < 0xA0) appendUtf8(out, hi[c - 0x80]);
        else appendUtf8(out, c); // 0xA0-0xFF map 1:1 to U+00A0-U+00FF
    }
    return out;
}

static std::string charsetFromContentType(const std::string& headers) {
    std::string ct = toLowerCopy(headerValueCI(headers, "content-type"));
    size_t cs = ct.find("charset=");
    if (cs == std::string::npos) return "";
    std::string v = ct.substr(cs + 8);
    size_t e = v.find_first_of("; \t\"'");
    if (e != std::string::npos) v = v.substr(0, e);
    return trimCopy(v);
}

static std::string charsetFromMeta(const std::string& html) {
    std::string head = toLowerCopy(html.substr(0, std::min<size_t>(html.size(), 2048)));
    size_t cs = head.find("charset=");
    if (cs == std::string::npos) return "";
    std::string v = head.substr(cs + 8);
    if (!v.empty() && (v[0] == '"' || v[0] == '\'')) v = v.substr(1);
    size_t e = v.find_first_of("; \t\"'>/");
    if (e != std::string::npos) v = v.substr(0, e);
    return trimCopy(v);
}

// Best-effort: convert an HTML document to UTF-8 if it declares a legacy charset.
static std::string decodeHtmlToUtf8(const std::string& headers, const std::string& html) {
    std::string cs = charsetFromContentType(headers);
    if (cs.empty()) cs = charsetFromMeta(html);
    cs = toLowerCopy(cs);
    if (cs.empty() || cs.find("utf-8") != std::string::npos || cs == "utf8") return html;
    if (cs.find("8859-1") != std::string::npos || cs == "latin1" ||
        cs.find("1252") != std::string::npos || cs.find("ascii") != std::string::npos) {
        return win1252ToUtf8(html);
    }
    return html; // unknown encoding: leave as-is
}

// Fetch a URL, following redirects (301/302/303/307/308) and decoding the body
// (chunked + gzip/deflate). outFinal receives the final URL so relative links
// and subresources resolve against it. If outHeaders is non-null it gets the
// final response's header block.
static std::string httpFetchProcessed(Url u, Url& outFinal, std::string* outHeaders) {
    netInit();
    std::string lastHeaders;
    try {
        std::string body;
        for (int hop = 0; hop < 10; ++hop) {
            std::string raw = (u.scheme == "https") ? httpsGetRaw(u) : httpGetRaw(u);
            HttpParts parts = splitHeadersBody(raw);
            lastHeaders = parts.headers;

            int status = parseStatusCode(parts.headers);
            if (status >= 300 && status < 400) {
                std::string loc = headerValueCI(parts.headers, "location");
                if (!loc.empty()) {
                    std::string abs = resolveHref(u, loc);
                    if (abs.empty()) abs = loc;
                    u = parseUrl(normalizeUserUrl(abs));
                    continue;
                }
            }

            body = parts.body;
            if (headerContainsCI(parts.headers, "transfer-encoding: chunked"))
                body = decodeChunkedBody(body);
            body = maybeDecompress(parts.headers, body);
            break;
        }
        netCleanup();
        outFinal = u;
        if (outHeaders) *outHeaders = lastHeaders;
        return body;
    } catch (...) {
        netCleanup();
        outFinal = u;
        if (outHeaders) *outHeaders = lastHeaders;
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

static std::string decodeEntities(const std::string& s) {
    static const std::unordered_map<std::string, unsigned> named = {
        {"amp",38},{"lt",60},{"gt",62},{"quot",34},{"apos",39},{"nbsp",160},
        {"copy",169},{"reg",174},{"trade",8482},{"mdash",8212},{"ndash",8211},
        {"hellip",8230},{"lsquo",8216},{"rsquo",8217},{"ldquo",8220},{"rdquo",8221},
        {"middot",183},{"bull",8226},{"times",215},{"divide",247},{"deg",176},
        {"euro",8364},{"pound",163},{"cent",162},{"yen",165},{"sect",167},
        {"para",182},{"laquo",171},{"raquo",187},{"iexcl",161},{"iquest",191},
        {"plusmn",177},{"micro",181},{"frac12",189},{"frac14",188},{"frac34",190},
        {"larr",8592},{"rarr",8594},{"uarr",8593},{"darr",8595},{"harr",8596},
        {"infin",8734},{"ne",8800},{"le",8804},{"ge",8805},{"shy",173},
        {"agrave",224},{"aacute",225},{"acirc",226},{"atilde",227},{"auml",228},{"aring",229},
        {"ccedil",231},{"egrave",232},{"eacute",233},{"ecirc",234},{"euml",235},
        {"igrave",236},{"iacute",237},{"ntilde",241},{"ograve",242},{"oacute",243},
        {"ocirc",244},{"otilde",245},{"ouml",246},{"ugrave",249},{"uacute",250},
        {"ucirc",251},{"uuml",252},{"szlig",223}
    };

    std::string out;
    out.reserve(s.size());
    size_t i = 0;
    while (i < s.size()) {
        if (s[i] != '&') { out.push_back(s[i++]); continue; }
        size_t semi = s.find(';', i + 1);
        if (semi == std::string::npos || semi - i > 32) { out.push_back(s[i++]); continue; }

        std::string ent = s.substr(i + 1, semi - i - 1);
        unsigned cp = 0;
        bool ok = false;

        if (!ent.empty() && ent[0] == '#') {
            try {
                if (ent.size() > 2 && (ent[1] == 'x' || ent[1] == 'X'))
                    cp = (unsigned)std::stoul(ent.substr(2), nullptr, 16);
                else if (ent.size() > 1)
                    cp = (unsigned)std::stoul(ent.substr(1), nullptr, 10);
                ok = (cp != 0);
            } catch (...) { ok = false; }
        } else {
            auto it = named.find(ent);
            if (it == named.end()) it = named.find(toLowerCopy(ent));
            if (it != named.end()) { cp = it->second; ok = true; }
        }

        if (ok) { appendUtf8(out, cp); i = semi + 1; }
        else    { out.push_back(s[i++]); }
    }
    return out;
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

struct TextStyle {
    int fontSize = 20;
    SDL_Color color {20, 20, 20, 255};
    bool bold = false;
};

static bool styleEquals(const TextStyle& a, const TextStyle& b) {
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

    // Box-model properties (block-level).
    std::optional<int> marginTop, marginRight, marginBottom, marginLeft;
    std::optional<bool> marginAuto;          // margin-left/right: auto -> centering
    std::optional<int> padTop, padRight, padBottom, padLeft;
    std::optional<int> borderW;
    std::optional<SDL_Color> borderColor;
    std::optional<int> width;                // content width, px
    std::optional<int> widthPct;             // width as a percentage
    std::optional<int> textAlign;            // 0 left, 1 center, 2 right
    std::optional<bool> displayNone;
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

// Parse a CSS length to integer pixels. nullopt for auto / percent / unknown.
static std::optional<int> cssLenPx(const std::string& raw) {
    std::string v = trimCopy(toLowerCopy(raw));
    if (v.empty() || v == "auto") return std::nullopt;
    if (!v.empty() && v.back() == '%') return std::nullopt;
    if (endsWith(v, "px")) v = trimCopy(v.substr(0, v.size() - 2));
    try {
        size_t used = 0;
        double d = std::stod(v, &used);
        return std::max(0, (int)std::lround(d));
    } catch (...) { return std::nullopt; }
}

// Expand a 1-4 value box shorthand into top/right/bottom/left.
static void cssExpandBox(const std::string& val,
                         std::optional<int>& top, std::optional<int>& right,
                         std::optional<int>& bottom, std::optional<int>& left,
                         bool* anyAuto) {
    std::istringstream iss(toLowerCopy(trimCopy(val)));
    std::vector<std::string> toks; std::string t;
    while (iss >> t) toks.push_back(t);
    if (toks.empty()) return;
    auto px = [&](const std::string& s) -> std::optional<int> {
        if (s == "auto") { if (anyAuto) *anyAuto = true; return std::nullopt; }
        return cssLenPx(s);
    };
    if (toks.size() == 1)      { auto a = px(toks[0]); top = right = bottom = left = a; }
    else if (toks.size() == 2) { auto v = px(toks[0]); auto h = px(toks[1]); top = bottom = v; right = left = h; }
    else if (toks.size() == 3) { top = px(toks[0]); right = left = px(toks[1]); bottom = px(toks[2]); }
    else                       { top = px(toks[0]); right = px(toks[1]); bottom = px(toks[2]); left = px(toks[3]); }
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
        } else if (key == "margin") {
            bool a = false;
            cssExpandBox(val, rule.marginTop, rule.marginRight, rule.marginBottom, rule.marginLeft, &a);
            if (a) rule.marginAuto = true;
        } else if (key == "margin-top")    rule.marginTop = cssLenPx(val);
        else if (key == "margin-right")    rule.marginRight = cssLenPx(val);
        else if (key == "margin-bottom")   rule.marginBottom = cssLenPx(val);
        else if (key == "margin-left")     rule.marginLeft = cssLenPx(val);
        else if (key == "padding") {
            cssExpandBox(val, rule.padTop, rule.padRight, rule.padBottom, rule.padLeft, nullptr);
        }
        else if (key == "padding-top")     rule.padTop = cssLenPx(val);
        else if (key == "padding-right")   rule.padRight = cssLenPx(val);
        else if (key == "padding-bottom")  rule.padBottom = cssLenPx(val);
        else if (key == "padding-left")    rule.padLeft = cssLenPx(val);
        else if (key == "border" || key == "border-width") {
            std::istringstream iss(toLowerCopy(val)); std::string tk;
            while (iss >> tk) {
                auto w = cssLenPx(tk);
                if (w) rule.borderW = *w;
                else { auto c = parseColor(tk); if (c) rule.borderColor = *c; }
            }
            if (key == "border" && !rule.borderW) rule.borderW = 1;
        }
        else if (key == "border-color") { auto c = parseColor(val); if (c) rule.borderColor = *c; }
        else if (key == "width") {
            std::string v = trimCopy(toLowerCopy(val));
            if (!v.empty() && v.back() == '%') {
                try { rule.widthPct = std::clamp((int)std::lround(std::stod(v.substr(0, v.size() - 1))), 0, 100); }
                catch (...) {}
            } else { auto w = cssLenPx(val); if (w) rule.width = *w; }
        }
        else if (key == "text-align") {
            std::string v = trimCopy(toLowerCopy(val));
            if (v == "center") rule.textAlign = 1;
            else if (v == "right") rule.textAlign = 2;
            else if (v == "left") rule.textAlign = 0;
        }
        else if (key == "display") {
            rule.displayNone = (trimCopy(toLowerCopy(val)) == "none");
        }
    }
}

static std::optional<StyleRule> parseSingleSelectorRule(const std::string& selectorRaw,
                                                        const std::string& decls) {
    std::string sel = trimCopy(toLowerCopy(selectorRaw));
    if (sel.empty()) return std::nullopt;

    // Reject complex selectors for now
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

    // Remove /* ... */ comments
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

static void applyTagDefaults(const std::string& tag, TextStyle& st) {
    if (tag == "h1") { st.fontSize = 34; st.bold = true; }
    else if (tag == "h2") { st.fontSize = 28; st.bold = true; }
    else if (tag == "h3") { st.fontSize = 24; st.bold = true; }
    else if (tag == "a") {
        st.color = SDL_Color{120, 180, 255, 255};
    }
}

static void applyInlineStyle(const std::string& inlineCss, TextStyle& st) {
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
                                 TextStyle& st) {
    // Approximate specificity order: tag -> class -> tag.class -> id
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

// -------------------- CSS box model --------------------

struct BoxStyle {
    int mTop = 0, mRight = 0, mBottom = 0, mLeft = 0;
    bool marginAuto = false;
    int pTop = 0, pRight = 0, pBottom = 0, pLeft = 0;
    int borderW = 0;
    SDL_Color borderColor {120, 120, 120, 255};
    bool hasBg = false;
    SDL_Color bg {0, 0, 0, 0};
    int width = -1;      // content width in px, -1 = auto
    int widthPct = -1;   // width as %, -1 = none
    int textAlign = -1;  // -1 inherit, 0 left, 1 center, 2 right
    bool displayNone = false;
};

// Approximate browser default block margins/padding (px).
static void applyBoxDefaults(const std::string& tag, BoxStyle& b) {
    if (tag == "h1") { b.mTop = b.mBottom = 22; }
    else if (tag == "h2") { b.mTop = b.mBottom = 18; }
    else if (tag == "h3" || tag == "h4") { b.mTop = b.mBottom = 16; }
    else if (tag == "p") { b.mTop = b.mBottom = 14; }
    else if (tag == "ul" || tag == "ol") { b.mTop = b.mBottom = 14; b.pLeft = 32; }
    else if (tag == "blockquote" || tag == "figure") { b.mTop = b.mBottom = 14; b.mLeft = b.mRight = 32; }
    else if (tag == "pre") { b.mTop = b.mBottom = 12; }
    else if (tag == "hr") { b.mTop = b.mBottom = 10; b.borderW = 1; b.borderColor = SDL_Color{180,180,180,255}; }
}

static void applyBoxRuleProps(const StyleRule& r, BoxStyle& b) {
    if (r.marginTop) b.mTop = *r.marginTop;
    if (r.marginRight) b.mRight = *r.marginRight;
    if (r.marginBottom) b.mBottom = *r.marginBottom;
    if (r.marginLeft) b.mLeft = *r.marginLeft;
    if (r.marginAuto) b.marginAuto = *r.marginAuto;
    if (r.padTop) b.pTop = *r.padTop;
    if (r.padRight) b.pRight = *r.padRight;
    if (r.padBottom) b.pBottom = *r.padBottom;
    if (r.padLeft) b.pLeft = *r.padLeft;
    if (r.borderW) b.borderW = *r.borderW;
    if (r.borderColor) b.borderColor = *r.borderColor;
    if (r.backgroundColor) { b.hasBg = true; b.bg = *r.backgroundColor; }
    if (r.width) { b.width = *r.width; b.widthPct = -1; }
    if (r.widthPct) { b.widthPct = *r.widthPct; b.width = -1; }
    if (r.textAlign) b.textAlign = *r.textAlign;
    if (r.displayNone) b.displayNone = *r.displayNone;
}

static void applyBoxRulesForElement(const std::vector<StyleRule>& rules,
                                    const std::string& tag, const std::string& id,
                                    const std::vector<std::string>& classes, BoxStyle& b) {
    for (const auto& r : rules) if (r.type == SelectorType::Tag && r.tag == tag) applyBoxRuleProps(r, b);
    for (const auto& r : rules) if (r.type == SelectorType::Class && hasClass(classes, r.cls)) applyBoxRuleProps(r, b);
    for (const auto& r : rules) if (r.type == SelectorType::TagClass && r.tag == tag && hasClass(classes, r.cls)) applyBoxRuleProps(r, b);
    for (const auto& r : rules) if (r.type == SelectorType::Id && !id.empty() && r.id == id) applyBoxRuleProps(r, b);
}

// -------------------- Tokens --------------------

enum class TokenKind { Word, Break, Image };

struct StyledToken {
    TokenKind kind;
    std::string text;
    std::string href;
    TextStyle style;
    int breakCount = 1;

    std::string elementId; // nearest ancestor element id (for click routing)

    // Image
    std::string imgSrcAbs;
    int imgAttrW = 0;
    int imgAttrH = 0;
    std::string imgAlt;
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
           name == "br" ||
           name == "img";
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
    if (tagNameLower == "img") return 1;
    if (tagNameLower == "br") return 1;
    return 1;
}

// -------------------- Subresource fetching --------------------

static std::string fetchSubresourceBytes(const std::string& absUrl) {
    try {
        Url u = parseUrl(absUrl);
        Url finalU;
        return httpFetchProcessed(u, finalU, nullptr); // follows redirects + decompresses
    } catch (...) {
        return "";
    }
}

static std::string fetchSubresourceText(const std::string& absUrl) {
    return fetchSubresourceBytes(absUrl);
}

// A <script src> that fails to load often yields an HTML error page; evaluating
// that as JS throws a noisy SyntaxError ("unexpected token '<'"). Treat content
// whose first non-space character is '<' as non-JS and skip it — except the
// legacy "<!--" guard that some inline scripts still wrap their code in.
static bool looksLikeHtmlNotJs(const std::string& code) {
    std::string t = trimCopy(code);
    return !t.empty() && t[0] == '<' && t.compare(0, 4, "<!--") != 0;
}

// -------------------- Page title helper --------------------

static std::string extractTitleFromHtmlSimple(const std::string& html) {
    auto titles = extractTagContents(html, "title");
    if (titles.empty()) return "";
    return trimCopy(decodeEntities(titles[0]));
}

#ifdef NOCHROME_ENABLE_JS
#include "dom.h"
#if defined(NOCHROME_USE_JSC)
// -------------------- JavaScript (JavaScriptCore) --------------------

struct JsHost {
    SDL_Window* window = nullptr;
    std::string currentUrl;

    // Real DOM tree (source of truth); the renderer walks it directly.
    DomTree dom;
    bool domDirty = false;

    // --- Realistic-ish JS plumbing (minimal) ---
    struct TimerItem {
        int id = 0;
        double dueMs = 0.0;
        JSObjectRef fn = nullptr;     // protected
        bool isCode = false;
        std::string code;
        bool isInterval = false;      // setInterval: re-arm after firing
        double intervalMs = 0.0;
        bool isRaf = false;           // requestAnimationFrame: pass a timestamp arg
    };

    int nextTimerId = 1;
    std::vector<TimerItem> timers;

    // Event listeners keyed by scope+type, e.g. "window:keydown", "document:DOMContentLoaded", "el:myid:click"
    std::unordered_map<std::string, std::vector<JSObjectRef>> listeners; // protected

    Url baseUrl;

    std::chrono::steady_clock::time_point perfStart = std::chrono::steady_clock::now();
};

struct JsEngine {
    JSGlobalContextRef ctx = nullptr;
    JsHost host;
};

static JsHost* g_jsHost = nullptr;

// Forward declarations for JS callbacks used before their definitions
static JSValueRef jscPerformanceNow(JSContextRef ctx, JSObjectRef, JSObjectRef, size_t, const JSValueRef[], JSValueRef*);

static std::string jsToUtf8(JSContextRef ctx, JSValueRef v) {
    if (!v) return "";
    JSValueRef exc = nullptr;
    JSStringRef s = JSValueToStringCopy(ctx, v, &exc);
    if (!s) return "";
    size_t maxSize = JSStringGetMaximumUTF8CStringSize(s);
    std::string out;
    out.resize(maxSize);
    size_t written = JSStringGetUTF8CString(s, out.data(), maxSize);
    JSStringRelease(s);
    if (written > 0) out.resize(written - 1);
    else out.clear();
    return out;
}

static void jsDumpException(JSContextRef ctx, JSValueRef exc) {
    if (!exc) return;
    std::cerr << "[JS Exception] " << jsToUtf8(ctx, exc) << "\n";
}

static JSValueRef jscConsoleLog(JSContextRef ctx, JSObjectRef /*function*/, JSObjectRef /*thisObject*/,
                               size_t argc, const JSValueRef argv[], JSValueRef* /*exception*/) {
    for (size_t i = 0; i < argc; i++) {
        std::cout << jsToUtf8(ctx, argv[i]);
        if (i + 1 < argc) std::cout << " ";
    }
    std::cout << std::endl;
    return JSValueMakeUndefined(ctx);
}

static JSValueRef jscNoop(JSContextRef ctx, JSObjectRef, JSObjectRef, size_t, const JSValueRef[], JSValueRef*) {
    return JSValueMakeUndefined(ctx);
}

static JSValueRef jscReturnNull(JSContextRef ctx, JSObjectRef, JSObjectRef, size_t, const JSValueRef[], JSValueRef*) {
    return JSValueMakeNull(ctx);
}

static double jscNowMs() {
    if (!g_jsHost) return 0.0;
    auto now = std::chrono::steady_clock::now();
    return std::chrono::duration<double, std::milli>(now - g_jsHost->perfStart).count();
}

static void jscUnprotectAll(JsEngine& js) {
    if (!js.ctx) return;
    for (auto& t : js.host.timers) {
        if (t.fn) JSValueUnprotect(js.ctx, t.fn);
        t.fn = nullptr;
    }
    js.host.timers.clear();

    for (auto& kv : js.host.listeners) {
        for (auto* fn : kv.second) {
            if (fn) JSValueUnprotect(js.ctx, fn);
        }
    }
    js.host.listeners.clear();
}

static JSValueRef jscClearTimeout(JSContextRef ctx, JSObjectRef, JSObjectRef, size_t argc, const JSValueRef argv[], JSValueRef*) {
    if (!g_jsHost) return JSValueMakeUndefined(ctx);
    if (argc < 1) return JSValueMakeUndefined(ctx);

    int id = (int)JSValueToNumber(ctx, argv[0], nullptr);
    auto& timers = g_jsHost->timers;
    for (auto it = timers.begin(); it != timers.end(); ++it) {
        if (it->id == id) {
            if (it->fn) JSValueUnprotect(ctx, it->fn);
            timers.erase(it);
            break;
        }
    }
    return JSValueMakeUndefined(ctx);
}

static JSValueRef jscSetTimeout(JSContextRef ctx, JSObjectRef, JSObjectRef, size_t argc, const JSValueRef argv[], JSValueRef*) {
    if (!g_jsHost) return JSValueMakeNumber(ctx, 0);

    if (argc < 1) return JSValueMakeNumber(ctx, 0);

    double delay = 0.0;
    if (argc >= 2) delay = JSValueToNumber(ctx, argv[1], nullptr);
    if (delay < 0.0) delay = 0.0;

    JsHost::TimerItem item;
    item.id = g_jsHost->nextTimerId++;
    item.dueMs = jscNowMs() + delay;

    if (JSValueIsString(ctx, argv[0])) {
        item.isCode = true;
        item.code = jsToUtf8(ctx, argv[0]);
    } else if (JSValueIsObject(ctx, argv[0])) {
        JSObjectRef fn = JSValueToObject(ctx, argv[0], nullptr);
        if (fn && JSObjectIsFunction(ctx, fn)) {
            item.fn = fn;
            JSValueProtect(ctx, item.fn);
        }
    }

    g_jsHost->timers.push_back(item);
    return JSValueMakeNumber(ctx, (double)item.id);
}

static JSValueRef jscSetInterval(JSContextRef ctx, JSObjectRef, JSObjectRef, size_t argc, const JSValueRef argv[], JSValueRef*) {
    if (!g_jsHost || argc < 1) return JSValueMakeNumber(ctx, 0);
    double delay = (argc >= 2) ? JSValueToNumber(ctx, argv[1], nullptr) : 0.0;
    if (delay < 4.0) delay = 4.0; // clamp like browsers (avoid a 0ms busy-loop)

    JsHost::TimerItem item;
    item.id = g_jsHost->nextTimerId++;
    item.dueMs = jscNowMs() + delay;
    item.isInterval = true;
    item.intervalMs = delay;
    if (JSValueIsString(ctx, argv[0])) {
        item.isCode = true;
        item.code = jsToUtf8(ctx, argv[0]);
    } else if (JSValueIsObject(ctx, argv[0])) {
        JSObjectRef fn = JSValueToObject(ctx, argv[0], nullptr);
        if (fn && JSObjectIsFunction(ctx, fn)) { item.fn = fn; JSValueProtect(ctx, item.fn); }
    }
    g_jsHost->timers.push_back(item);
    return JSValueMakeNumber(ctx, (double)item.id);
}

static JSValueRef jscRequestAnimationFrame(JSContextRef ctx, JSObjectRef, JSObjectRef, size_t argc, const JSValueRef argv[], JSValueRef*) {
    if (!g_jsHost || argc < 1 || !JSValueIsObject(ctx, argv[0])) return JSValueMakeNumber(ctx, 0);
    JSObjectRef fn = JSValueToObject(ctx, argv[0], nullptr);
    if (!fn || !JSObjectIsFunction(ctx, fn)) return JSValueMakeNumber(ctx, 0);

    JsHost::TimerItem item;
    item.id = g_jsHost->nextTimerId++;
    item.dueMs = jscNowMs() + 16.0; // ~next frame
    item.isRaf = true;
    item.fn = fn;
    JSValueProtect(ctx, item.fn);
    g_jsHost->timers.push_back(item);
    return JSValueMakeNumber(ctx, (double)item.id);
}


static JSValueRef jscAlert(JSContextRef ctx, JSObjectRef, JSObjectRef, size_t argc, const JSValueRef argv[], JSValueRef*) {
    std::string msg;
    if (argc > 0) msg = jsToUtf8(ctx, argv[0]);

    SDL_Window* win = g_jsHost ? g_jsHost->window : nullptr;
    SDL_ShowSimpleMessageBox(SDL_MESSAGEBOX_INFORMATION, "alert()", msg.c_str(), win);
    return JSValueMakeUndefined(ctx);
}


static void jscAddListener(const std::string& key, JSObjectRef fn) {
    if (!g_jsHost || !fn) return;
    g_jsHost->listeners[key].push_back(fn);
    // (ctx-aware helper used instead)
}

// NOTE: JavaScriptCore C API doesn't provide "current context" directly; we pass ctx in callbacks.
// So we use a ctx-aware helper:
static void jscAddListenerCtx(JSContextRef ctx, const std::string& key, JSObjectRef fn) {
    if (!g_jsHost || !fn) return;
    g_jsHost->listeners[key].push_back(fn);
    JSValueProtect(ctx, fn);
}

static void jscDispatchEventSimple(JSContextRef ctx, const std::string& key, JSObjectRef eventObj) {
    if (!g_jsHost) return;
    auto it = g_jsHost->listeners.find(key);
    if (it == g_jsHost->listeners.end()) return;

    for (auto* fn : it->second) {
        if (!fn) continue;
        JSValueRef exc = nullptr;
        JSObjectCallAsFunction(ctx, fn, nullptr, eventObj ? 1 : 0, eventObj ? (JSValueRef*)&eventObj : nullptr, &exc);
        if (exc) {
            std::cerr << "[JS Exception] " << jsToUtf8(ctx, exc) << "\n";
        }
    }
}

static std::string stripNoscriptBlocks(const std::string& html) {
    std::string lower = toLowerCopy(html);
    std::string out;
    out.reserve(html.size());

    size_t pos = 0;
    while (true) {
        size_t ns = lower.find("<noscript", pos);
        if (ns == std::string::npos) {
            out.append(html, pos, std::string::npos);
            break;
        }
        out.append(html, pos, ns - pos);

        size_t gt = lower.find('>', ns);
        if (gt == std::string::npos) break;

        size_t end = lower.find("</noscript>", gt);
        if (end == std::string::npos) break;

        pos = end + std::string("</noscript>").size();
    }

    return out;
}

static bool replaceElementTextById(std::string& html, const std::string& id, const std::string& newText) {
    if (id.empty()) return false;
    std::string lower = toLowerCopy(html);

    // Find id="id" or id='id'
    std::string needle1 = "id=\"" + id + "\"";
    std::string needle2 = "id='" + id + "'";
    size_t p = lower.find(toLowerCopy(needle1));
    if (p == std::string::npos) p = lower.find(toLowerCopy(needle2));
    if (p == std::string::npos) return false;

    // Find tag start '<' before id
    size_t tagStart = lower.rfind('<', p);
    if (tagStart == std::string::npos) return false;

    // Find tag name
    size_t nameStart = tagStart + 1;
    while (nameStart < lower.size() && std::isspace((unsigned char)lower[nameStart])) nameStart++;
    size_t nameEnd = nameStart;
    while (nameEnd < lower.size() && std::isalnum((unsigned char)lower[nameEnd])) nameEnd++;
    if (nameEnd <= nameStart) return false;
    std::string tag = lower.substr(nameStart, nameEnd - nameStart);

    // Find end of opening tag
    size_t openEnd = lower.find('>', p);
    if (openEnd == std::string::npos) return false;

    // Self-closing? then nothing to replace
    if (openEnd > 0 && lower[openEnd - 1] == '/') return false;

    // Find closing tag
    std::string closeNeedle = "</" + tag;
    size_t closeStart = lower.find(closeNeedle, openEnd);
    if (closeStart == std::string::npos) return false;

    // Replace inner content (best effort; doesn't handle nested same-tags correctly)
    html = html.substr(0, openEnd + 1) + escapeHtmlEntities(newText) + html.substr(closeStart);
    return true;
}

static void insertBeforeClosingTag(std::string& html, const std::string& tag, const std::string& snippet) {
    std::string lower = toLowerCopy(html);
    std::string closeNeedle = "</" + toLowerCopy(tag) + ">";
    size_t pos = lower.rfind(closeNeedle);
    if (pos != std::string::npos) {
        html.insert(pos, snippet);
        return;
    }
    // Fallback: append
    html += snippet;
}

struct JscResponsePriv {
    std::string body;
    int status = 200;
};

static JSClassRef g_jscResponseClass = nullptr;

static void jscFinalizeResponse(JSObjectRef object) {
    auto* priv = (JscResponsePriv*)JSObjectGetPrivate(object);
    delete priv;
}

static JSValueRef jscResponseText(JSContextRef ctx, JSObjectRef, JSObjectRef thisObject, size_t, const JSValueRef[], JSValueRef*) {
    auto* priv = (JscResponsePriv*)JSObjectGetPrivate(thisObject);
    std::string body = priv ? priv->body : "";

    // Promise.resolve(body)
    JSObjectRef global = JSContextGetGlobalObject(ctx);
    JSStringRef pname = JSStringCreateWithUTF8CString("Promise");
    JSValueRef pval = JSObjectGetProperty(ctx, global, pname, nullptr);
    JSStringRelease(pname);

    if (!JSValueIsObject(ctx, pval)) return JSValueMakeString(ctx, JSStringCreateWithUTF8CString(body.c_str()));
    JSObjectRef pobj = JSValueToObject(ctx, pval, nullptr);

    JSStringRef rname = JSStringCreateWithUTF8CString("resolve");
    JSValueRef rval = JSObjectGetProperty(ctx, pobj, rname, nullptr);
    JSStringRelease(rname);

    if (!JSValueIsObject(ctx, rval)) return JSValueMakeString(ctx, JSStringCreateWithUTF8CString(body.c_str()));
    JSObjectRef resolveFn = JSValueToObject(ctx, rval, nullptr);

    JSStringRef s = JSStringCreateWithUTF8CString(body.c_str());
    JSValueRef arg = JSValueMakeString(ctx, s);
    JSStringRelease(s);

    JSValueRef exc = nullptr;
    JSValueRef args[1] = { arg };
    JSValueRef prom = JSObjectCallAsFunction(ctx, resolveFn, pobj, 1, args, &exc);
    if (exc) {
        std::cerr << "[JS Exception] " << jsToUtf8(ctx, exc) << "\n";
        return JSValueMakeUndefined(ctx);
    }
    return prom;
}

static JSValueRef jscFetch(JSContextRef ctx, JSObjectRef, JSObjectRef, size_t argc, const JSValueRef argv[], JSValueRef*) {
    if (!g_jsHost) return JSValueMakeUndefined(ctx);
    if (argc < 1) return JSValueMakeUndefined(ctx);

    std::string url = jsToUtf8(ctx, argv[0]);
    std::string abs = resolveHref(g_jsHost->baseUrl, url);
    if (abs.empty()) abs = url;

    std::string body = fetchSubresourceText(abs);

    if (!g_jscResponseClass) {
        JSClassDefinition def = kJSClassDefinitionEmpty;
        def.finalize = jscFinalizeResponse;
        g_jscResponseClass = JSClassCreate(&def);
    }

    JSObjectRef resp = JSObjectMake(ctx, g_jscResponseClass, new JscResponsePriv{body, 200});

    // Attach properties: ok, status, text()
    {
        JSStringRef okName = JSStringCreateWithUTF8CString("ok");
        JSObjectSetProperty(ctx, resp, okName, JSValueMakeBoolean(ctx, true), kJSPropertyAttributeNone, nullptr);
        JSStringRelease(okName);

        JSStringRef stName = JSStringCreateWithUTF8CString("status");
        JSObjectSetProperty(ctx, resp, stName, JSValueMakeNumber(ctx, 200), kJSPropertyAttributeNone, nullptr);
        JSStringRelease(stName);

        JSStringRef textName = JSStringCreateWithUTF8CString("text");
        JSObjectRef fn = JSObjectMakeFunctionWithCallback(ctx, textName, jscResponseText);
        JSObjectSetProperty(ctx, resp, textName, fn, kJSPropertyAttributeNone, nullptr);
        JSStringRelease(textName);
    }

    // Return Promise.resolve(resp)
    JSObjectRef global = JSContextGetGlobalObject(ctx);
    JSStringRef pname = JSStringCreateWithUTF8CString("Promise");
    JSValueRef pval = JSObjectGetProperty(ctx, global, pname, nullptr);
    JSStringRelease(pname);

    if (!JSValueIsObject(ctx, pval)) return resp;
    JSObjectRef pobj = JSValueToObject(ctx, pval, nullptr);

    JSStringRef rname = JSStringCreateWithUTF8CString("resolve");
    JSValueRef rval = JSObjectGetProperty(ctx, pobj, rname, nullptr);
    JSStringRelease(rname);

    if (!JSValueIsObject(ctx, rval)) return resp;
    JSObjectRef resolveFn = JSValueToObject(ctx, rval, nullptr);

    JSValueRef exc = nullptr;
    JSValueRef args[1] = { resp };
    JSValueRef prom = JSObjectCallAsFunction(ctx, resolveFn, pobj, 1, args, &exc);
    if (exc) {
        std::cerr << "[JS Exception] " << jsToUtf8(ctx, exc) << "\n";
        return resp;
    }
    return prom;
}

static void jsInstallBaseGlobals(JsEngine& js) {
    JSObjectRef global = JSContextGetGlobalObject(js.ctx);

    // console object
    JSObjectRef consoleObj = JSObjectMake(js.ctx, nullptr, nullptr);

    JSStringRef logName = JSStringCreateWithUTF8CString("log");
    JSObjectRef logFn = JSObjectMakeFunctionWithCallback(js.ctx, logName, jscConsoleLog);
    JSObjectSetProperty(js.ctx, consoleObj, logName, logFn, kJSPropertyAttributeNone, nullptr);
    JSStringRelease(logName);

    JSStringRef errName = JSStringCreateWithUTF8CString("error");
    JSObjectRef errFn = JSObjectMakeFunctionWithCallback(js.ctx, errName, jscConsoleLog);
    JSObjectSetProperty(js.ctx, consoleObj, errName, errFn, kJSPropertyAttributeNone, nullptr);
    JSStringRelease(errName);

    JSStringRef consoleName = JSStringCreateWithUTF8CString("console");
    JSObjectSetProperty(js.ctx, global, consoleName, consoleObj, kJSPropertyAttributeNone, nullptr);
    JSStringRelease(consoleName);

    // window = global
    JSStringRef windowName = JSStringCreateWithUTF8CString("window");
    JSObjectSetProperty(js.ctx, global, windowName, global, kJSPropertyAttributeNone, nullptr);
    JSStringRelease(windowName);

    // self / top / parent / frames all refer to the window (no frames).
    for (const char* nm : { "self", "top", "parent", "frames" }) {
        JSStringRef n = JSStringCreateWithUTF8CString(nm);
        JSObjectSetProperty(js.ctx, global, n, global, kJSPropertyAttributeNone, nullptr);
        JSStringRelease(n);
    }

    // performance.now()
    JSObjectRef perfObj = JSObjectMake(js.ctx, nullptr, nullptr);
    {
        JSStringRef nowName = JSStringCreateWithUTF8CString("now");
        JSObjectRef nowFn = JSObjectMakeFunctionWithCallback(js.ctx, nowName, jscPerformanceNow);
        JSObjectSetProperty(js.ctx, perfObj, nowName, nowFn, kJSPropertyAttributeNone, nullptr);
        JSStringRelease(nowName);
    }
    JSStringRef perfName = JSStringCreateWithUTF8CString("performance");
    JSObjectSetProperty(js.ctx, global, perfName, perfObj, kJSPropertyAttributeNone, nullptr);
    JSStringRelease(perfName);

    // alert
    JSStringRef alertName = JSStringCreateWithUTF8CString("alert");
    JSObjectRef alertFn = JSObjectMakeFunctionWithCallback(js.ctx, alertName, jscAlert);
    JSObjectSetProperty(js.ctx, global, alertName, alertFn, kJSPropertyAttributeNone, nullptr);
    JSStringRelease(alertName);

    // setTimeout / clearTimeout (timer queue)
    {
        JSStringRef stName = JSStringCreateWithUTF8CString("setTimeout");
        JSObjectRef stFn = JSObjectMakeFunctionWithCallback(js.ctx, stName, jscSetTimeout);
        JSObjectSetProperty(js.ctx, global, stName, stFn, kJSPropertyAttributeNone, nullptr);
        JSStringRelease(stName);

        JSStringRef ctName = JSStringCreateWithUTF8CString("clearTimeout");
        JSObjectRef ctFn = JSObjectMakeFunctionWithCallback(js.ctx, ctName, jscClearTimeout);
        JSObjectSetProperty(js.ctx, global, ctName, ctFn, kJSPropertyAttributeNone, nullptr);
        JSStringRelease(ctName);

        // setInterval / clearInterval and requestAnimationFrame / cancelAnimationFrame
        // (cancellation reuses clearTimeout's remove-by-id logic).
        JSStringRef siName = JSStringCreateWithUTF8CString("setInterval");
        JSObjectSetProperty(js.ctx, global, siName, JSObjectMakeFunctionWithCallback(js.ctx, siName, jscSetInterval), kJSPropertyAttributeNone, nullptr);
        JSStringRelease(siName);

        JSStringRef ciName = JSStringCreateWithUTF8CString("clearInterval");
        JSObjectSetProperty(js.ctx, global, ciName, JSObjectMakeFunctionWithCallback(js.ctx, ciName, jscClearTimeout), kJSPropertyAttributeNone, nullptr);
        JSStringRelease(ciName);

        JSStringRef rafName = JSStringCreateWithUTF8CString("requestAnimationFrame");
        JSObjectSetProperty(js.ctx, global, rafName, JSObjectMakeFunctionWithCallback(js.ctx, rafName, jscRequestAnimationFrame), kJSPropertyAttributeNone, nullptr);
        JSStringRelease(rafName);

        JSStringRef cafName = JSStringCreateWithUTF8CString("cancelAnimationFrame");
        JSObjectSetProperty(js.ctx, global, cafName, JSObjectMakeFunctionWithCallback(js.ctx, cafName, jscClearTimeout), kJSPropertyAttributeNone, nullptr);
        JSStringRelease(cafName);
    }

    // fetch (very small subset): returns Promise<response>, response.text() returns Promise<string>
    {
        JSStringRef fName = JSStringCreateWithUTF8CString("fetch");
        JSObjectRef fFn = JSObjectMakeFunctionWithCallback(js.ctx, fName, jscFetch);
        JSObjectSetProperty(js.ctx, global, fName, fFn, kJSPropertyAttributeNone, nullptr);
        JSStringRelease(fName);
    }

    // addEventListener on window
    {
        JSStringRef aelName = JSStringCreateWithUTF8CString("addEventListener");
        JSObjectRef aelFn = JSObjectMakeFunctionWithCallback(js.ctx, aelName, jscNoop); // replaced in page globals for routing
        JSObjectSetProperty(js.ctx, global, aelName, aelFn, kJSPropertyAttributeNone, nullptr);
        JSStringRelease(aelName);
    }
}

static bool jsInit(JsEngine& js) {
    js.ctx = JSGlobalContextCreate(nullptr);
    if (!js.ctx) return false;
    g_jsHost = &js.host;
    jsInstallBaseGlobals(js);
    return true;
}

static void jsResetContext(JsEngine& js) {
    if (js.ctx) {
        jscUnprotectAll(js);
        JSGlobalContextRelease(js.ctx);
        js.ctx = nullptr;
    }
    js.ctx = JSGlobalContextCreate(nullptr);
    g_jsHost = &js.host;
    jsInstallBaseGlobals(js);
}

static void jsShutdown(JsEngine& js) {
    if (js.ctx) {
        JSGlobalContextRelease(js.ctx);
        js.ctx = nullptr;
    }
    if (g_jsHost == &js.host) g_jsHost = nullptr;
}

struct ScriptItem {
    std::string code;
    std::string srcAbs;
    bool isModule = false;
};

static std::vector<ScriptItem> extractScriptsSimple(const std::string& html, const Url& baseUrl) {
    std::vector<ScriptItem> out;

    std::string lower = toLowerCopy(html);
    size_t pos = 0;

    while (true) {
        size_t s = lower.find("<script", pos);
        if (s == std::string::npos) break;

        size_t gt = lower.find('>', s);
        if (gt == std::string::npos) break;

        std::string tagContent = html.substr(s + 1, gt - (s + 1)); // "script ..."

        std::string type = toLowerCopy(getAttrValue(tagContent, "type"));
        bool isModule = (type.find("module") != std::string::npos);

        std::string src = trimCopy(getAttrValue(tagContent, "src"));

        size_t end = lower.find("</script>", gt);
        if (end == std::string::npos) break;

        std::string inlineCode = html.substr(gt + 1, end - (gt + 1));

        ScriptItem it;
        it.isModule = isModule;
        if (!src.empty()) it.srcAbs = resolveHref(baseUrl, src);
        else it.code = inlineCode;

        out.push_back(std::move(it));
        pos = end + 9;
    }

    return out;
}


// -------------------- Minimal DOM stubs (id map + style.display) --------------------

struct JscElementPriv {
    int nodeId = -1; // index into JsHost::dom
};

struct JscStylePriv {
    int nodeId = -1; // element this style belongs to
};

// Backing store for a DOM Event object. Standard fields live here; ad-hoc
// properties (clientX, key, ...) are stored as ordinary own properties on the
// JS instance (the get/set handlers return NULL/false for unknown names so
// normal property storage takes over).
struct JscEventPriv {
    std::string type;
    bool bubbles = false;
    bool cancelable = false;
    bool defaultPrevented = false;
    bool propagationStopped = false;
    bool immediateStopped = false;
    int eventPhase = 0;
    int targetNodeId = -1;
    int currentTargetNodeId = -1;
};

static JSClassRef g_jscElementClass = nullptr;
static JSClassRef g_jscStyleClass = nullptr;
static JSClassRef g_jscEventClass = nullptr;

// Backing store for an XMLHttpRequest object. on* handlers (onload, onerror,
// onreadystatechange) are NOT stored here; they are ordinary own JS properties
// read back off the object during send().
struct JscXhrPriv {
    std::string method;
    std::string url;
    int readyState = 0;
    int status = 0;
    std::string statusText;
    std::string responseText;
    std::string responseType;
    std::string responseHeaders; // raw header block from the last send()
    bool sent = false;
};
static JSClassRef g_jscXhrClass = nullptr;

static std::string jsStringToUtf8(JSStringRef s) {
    size_t maxSize = JSStringGetMaximumUTF8CStringSize(s);
    std::string out(maxSize, '\0');
    size_t used = JSStringGetUTF8CString(s, out.data(), out.size());
    if (used == 0) return "";
    out.resize(used - 1);
    return out;
}

static void jscFinalizeElement(JSObjectRef object) {
    auto* priv = (JscElementPriv*)JSObjectGetPrivate(object);
    delete priv;
}

static void jscFinalizeStyle(JSObjectRef object) {
    auto* priv = (JscStylePriv*)JSObjectGetPrivate(object);
    delete priv;
}

static DomNode* jscElNode(JSObjectRef object) {
    auto* priv = (JscElementPriv*)JSObjectGetPrivate(object);
    if (!priv || !g_jsHost) return nullptr;
    return g_jsHost->dom.get(priv->nodeId);
}

static int jscElNodeId(JSObjectRef object) {
    auto* priv = (JscElementPriv*)JSObjectGetPrivate(object);
    return priv ? priv->nodeId : -1;
}

static int jscSiblingId(int nid, int dir) {   // dir +1 next, -1 prev
    if (!g_jsHost) return -1;
    DomNode* n = g_jsHost->dom.get(nid);
    if (!n || n->parent < 0) return -1;
    DomNode* p = g_jsHost->dom.get(n->parent);
    if (!p) return -1;
    auto& cs = p->children;
    for (size_t i = 0; i < cs.size(); ++i)
        if (cs[i] == nid) { int j = (int)i + dir; return (j < 0 || j >= (int)cs.size()) ? -1 : cs[j]; }
    return -1;
}
static JSValueRef jscNodeArray(JSContextRef ctx, const std::vector<int>& nids);

static JSValueRef jscStyleGetProperty(JSContextRef ctx, JSObjectRef object, JSStringRef propertyName, JSValueRef* /*exception*/) {
    auto* priv = (JscStylePriv*)JSObjectGetPrivate(object);
    if (!priv || !g_jsHost) return nullptr;
    std::string prop = jsStringToUtf8(propertyName);
    if (!cssIsKnownProp(prop)) return nullptr; // delegate (methods, toString, ...)
    DomNode* n = g_jsHost->dom.get(priv->nodeId);
    std::string v = n ? domGetStyleProp(*n, prop) : "";
    JSStringRef s = JSStringCreateWithUTF8CString(v.c_str());
    JSValueRef vStr = JSValueMakeString(ctx, s);
    JSStringRelease(s);
    return vStr;
}

static bool jscStyleSetProperty(JSContextRef ctx, JSObjectRef object, JSStringRef propertyName, JSValueRef value, JSValueRef* /*exception*/) {
    auto* priv = (JscStylePriv*)JSObjectGetPrivate(object);
    if (!priv || !g_jsHost) return false;
    std::string prop = jsStringToUtf8(propertyName);
    if (!cssIsKnownProp(prop)) return false; // store as a plain JS property
    if (DomNode* n = g_jsHost->dom.get(priv->nodeId)) {
        domSetStyleProp(*n, prop, jsToUtf8(ctx, value));
        g_jsHost->domDirty = true;
    }
    return true;
}


#if defined(NOCHROME_USE_JSC)
// Forward declarations for element methods used by the property getter.
static JSValueRef jscElementAddEventListener(JSContextRef ctx, JSObjectRef function,
                                             JSObjectRef thisObject, size_t argumentCount,
                                             const JSValueRef arguments[], JSValueRef* exception);
static JSValueRef jscElementRemoveEventListener(JSContextRef, JSObjectRef, JSObjectRef, size_t, const JSValueRef[], JSValueRef*);
static JSValueRef jscElementDispatchEvent(JSContextRef, JSObjectRef, JSObjectRef, size_t, const JSValueRef[], JSValueRef*);
// Defined below jscEnsureDomClasses; used by element event methods above it.
static void jscRemoveListener(JSContextRef ctx, const std::string& key, JSObjectRef fn);
static bool jscDispatchEvent(JSContextRef ctx, int targetNodeId, JSObjectRef evt,
                             const std::string& type, bool bubbles);
static JSValueRef jscElementAppendChild(JSContextRef ctx, JSObjectRef function,
                                       JSObjectRef thisObject, size_t argumentCount,
                                       const JSValueRef arguments[], JSValueRef* exception);
static JSValueRef jscElementRemoveChild(JSContextRef ctx, JSObjectRef function,
                                        JSObjectRef thisObject, size_t argumentCount,
                                        const JSValueRef arguments[], JSValueRef* exception);
static JSValueRef jscElementSetAttribute(JSContextRef ctx, JSObjectRef function,
                                        JSObjectRef thisObject, size_t argumentCount,
                                        const JSValueRef arguments[], JSValueRef* exception);
static JSValueRef jscElementGetAttribute(JSContextRef ctx, JSObjectRef function,
                                        JSObjectRef thisObject, size_t argumentCount,
                                        const JSValueRef arguments[], JSValueRef* exception);
// Batch 1 DOM additions.
static JSValueRef jscElementInsertBefore(JSContextRef, JSObjectRef, JSObjectRef, size_t, const JSValueRef[], JSValueRef*);
static JSValueRef jscElementReplaceChild(JSContextRef, JSObjectRef, JSObjectRef, size_t, const JSValueRef[], JSValueRef*);
static JSValueRef jscElementCloneNode(JSContextRef, JSObjectRef, JSObjectRef, size_t, const JSValueRef[], JSValueRef*);
static JSValueRef jscElementHasAttribute(JSContextRef, JSObjectRef, JSObjectRef, size_t, const JSValueRef[], JSValueRef*);
static JSValueRef jscElementRemoveAttribute(JSContextRef, JSObjectRef, JSObjectRef, size_t, const JSValueRef[], JSValueRef*);
static JSObjectRef jscMakeClassList(JSContextRef, int);
#endif

static JSValueRef jscElementGetProperty(JSContextRef ctx, JSObjectRef object, JSStringRef propertyName, JSValueRef* /*exception*/) {
    DomNode* n = jscElNode(object);
    if (!n) return nullptr; // not our element: fall through to normal lookup

    std::string prop = jsStringToUtf8(propertyName);
    int nid = jscElNodeId(object);

    auto makeStr = [&](const std::string& s) -> JSValueRef {
        JSStringRef v = JSStringCreateWithUTF8CString(s.c_str());
        JSValueRef r = JSValueMakeString(ctx, v);
        JSStringRelease(v);
        return r;
    };
    auto makeFn = [&](const char* name, JSObjectCallAsFunctionCallback cb) -> JSValueRef {
        JSStringRef nm = JSStringCreateWithUTF8CString(name);
        JSObjectRef fn = JSObjectMakeFunctionWithCallback(ctx, nm, cb);
        JSStringRelease(nm);
        return fn;
    };

    if (prop == "id")        return makeStr(domGetAttr(*n, "id"));
    if (prop == "tagName")   return makeStr(n->tag.empty() ? "DIV" : toUpperCopy(n->tag));
    if (prop == "textContent" || prop == "innerText")
        return makeStr(domTextContent(g_jsHost->dom, nid));
    if (prop == "innerHTML") return makeStr(domSerializeChildren(g_jsHost->dom, nid));
    if (prop == "className") return makeStr(domGetAttr(*n, "class"));
    if (prop == "src" || prop == "href" || prop == "type" || prop == "value" || prop == "name")
        return makeStr(domGetAttr(*n, prop));

    if (prop == "style") {
        return JSObjectMake(ctx, g_jscStyleClass, new JscStylePriv{ nid });
    }
    if (prop == "parentNode") {
        if (n->parent < 0 || n->parent == g_jsHost->dom.root) return JSValueMakeNull(ctx);
        return JSObjectMake(ctx, g_jscElementClass, new JscElementPriv{ n->parent });
    }

    if (prop == "addEventListener") return makeFn("addEventListener", jscElementAddEventListener);
    if (prop == "removeEventListener") return makeFn("removeEventListener", jscElementRemoveEventListener);
    if (prop == "dispatchEvent")    return makeFn("dispatchEvent", jscElementDispatchEvent);
    if (prop == "appendChild")      return makeFn("appendChild", jscElementAppendChild);
    if (prop == "removeChild")      return makeFn("removeChild", jscElementRemoveChild);
    if (prop == "setAttribute")     return makeFn("setAttribute", jscElementSetAttribute);
    if (prop == "getAttribute")     return makeFn("getAttribute", jscElementGetAttribute);

    // --- traversal (Batch 1) ---
    if (prop == "classList")  return jscMakeClassList(ctx, nid);
    if (prop == "childNodes") return jscNodeArray(ctx, n->children);
    if (prop == "children") {
        std::vector<int> els;
        for (int c : n->children) {
            DomNode* cn = g_jsHost->dom.get(c);
            if (cn && cn->type == DomNodeType::Element) els.push_back(c);
        }
        return jscNodeArray(ctx, els);
    }
    if (prop == "firstChild")
        return n->children.empty() ? JSValueMakeNull(ctx)
            : (JSValueRef)JSObjectMake(ctx, g_jscElementClass, new JscElementPriv{ n->children.front() });
    if (prop == "lastChild")
        return n->children.empty() ? JSValueMakeNull(ctx)
            : (JSValueRef)JSObjectMake(ctx, g_jscElementClass, new JscElementPriv{ n->children.back() });
    if (prop == "nextSibling") {
        int s = jscSiblingId(nid, +1);
        return s < 0 ? JSValueMakeNull(ctx) : (JSValueRef)JSObjectMake(ctx, g_jscElementClass, new JscElementPriv{ s });
    }
    if (prop == "previousSibling") {
        int s = jscSiblingId(nid, -1);
        return s < 0 ? JSValueMakeNull(ctx) : (JSValueRef)JSObjectMake(ctx, g_jscElementClass, new JscElementPriv{ s });
    }

    // --- mutation / attribute methods (Batch 1) ---
    if (prop == "insertBefore")    return makeFn("insertBefore", jscElementInsertBefore);
    if (prop == "replaceChild")    return makeFn("replaceChild", jscElementReplaceChild);
    if (prop == "cloneNode")       return makeFn("cloneNode", jscElementCloneNode);
    if (prop == "hasAttribute")    return makeFn("hasAttribute", jscElementHasAttribute);
    if (prop == "removeAttribute") return makeFn("removeAttribute", jscElementRemoveAttribute);

    return nullptr; // delegate (stored props / prototype)
}

static bool jscElementSetProperty(JSContextRef ctx, JSObjectRef object, JSStringRef propertyName, JSValueRef value, JSValueRef*) {
    DomNode* n = jscElNode(object);
    if (!n) return false;

    std::string prop = jsStringToUtf8(propertyName);
    int nid = jscElNodeId(object);

    if (prop == "id") {
        domSetAttr(*n, "id", jsToUtf8(ctx, value));
        if (g_jsHost) g_jsHost->domDirty = true;
        return true;
    }
    if (prop == "textContent" || prop == "innerText") {
        domSetTextContent(g_jsHost->dom, nid, jsToUtf8(ctx, value));
        g_jsHost->domDirty = true;
        return true;
    }
    if (prop == "innerHTML") {
        domSetInnerHtml(g_jsHost->dom, nid, jsToUtf8(ctx, value));
        g_jsHost->domDirty = true;
        return true;
    }
    if (prop == "className") {
        domSetAttr(*n, "class", jsToUtf8(ctx, value));
        g_jsHost->domDirty = true;
        return true;
    }
    if (prop == "src" || prop == "href" || prop == "type" || prop == "value" || prop == "name") {
        domSetAttr(*n, prop, jsToUtf8(ctx, value));
        g_jsHost->domDirty = true;
        return true;
    }

    return false;
}

static JSValueRef jscElementAddEventListener(JSContextRef ctx, JSObjectRef, JSObjectRef thisObject, size_t argc, const JSValueRef argv[], JSValueRef*) {
    if (!g_jsHost) return JSValueMakeUndefined(ctx);
    int nid = jscElNodeId(thisObject);
    if (nid < 0) return JSValueMakeUndefined(ctx);
    if (argc < 2) return JSValueMakeUndefined(ctx);

    std::string type = jsToUtf8(ctx, argv[0]);
    if (!JSValueIsObject(ctx, argv[1])) return JSValueMakeUndefined(ctx);
    JSObjectRef fn = JSValueToObject(ctx, argv[1], nullptr);
    if (!fn || !JSObjectIsFunction(ctx, fn)) return JSValueMakeUndefined(ctx);

    jscAddListenerCtx(ctx, "node:" + std::to_string(nid) + ":" + type, fn);
    return JSValueMakeUndefined(ctx);
}

static JSValueRef jscElementRemoveEventListener(JSContextRef ctx, JSObjectRef, JSObjectRef thisObject, size_t argc, const JSValueRef argv[], JSValueRef*) {
    if (!g_jsHost) return JSValueMakeUndefined(ctx);
    int nid = jscElNodeId(thisObject);
    if (nid < 0 || argc < 2 || !JSValueIsObject(ctx, argv[1])) return JSValueMakeUndefined(ctx);
    std::string type = jsToUtf8(ctx, argv[0]);
    JSObjectRef fn = JSValueToObject(ctx, argv[1], nullptr);
    if (!fn) return JSValueMakeUndefined(ctx);
    jscRemoveListener(ctx, "node:" + std::to_string(nid) + ":" + type, fn);
    return JSValueMakeUndefined(ctx);
}

// element.dispatchEvent(evt): dispatch through the bubbling path rooted at this
// element. Returns !defaultPrevented.
static JSValueRef jscElementDispatchEvent(JSContextRef ctx, JSObjectRef, JSObjectRef thisObject, size_t argc, const JSValueRef argv[], JSValueRef*) {
    if (!g_jsHost) return JSValueMakeBoolean(ctx, true);
    int nid = jscElNodeId(thisObject);
    if (nid < 0 || argc < 1 || !JSValueIsObject(ctx, argv[0])) return JSValueMakeBoolean(ctx, true);

    JSObjectRef evt = JSValueToObject(ctx, argv[0], nullptr);
    auto* ep = (JscEventPriv*)JSObjectGetPrivate(evt);
    std::string type;
    bool bubbles = false;
    if (ep) {
        type = ep->type;
        bubbles = ep->bubbles;
    } else {
        // Best-effort for plain-object "events": read .type, assume non-bubbling.
        JSStringRef tk = JSStringCreateWithUTF8CString("type");
        JSValueRef tv = JSObjectGetProperty(ctx, evt, tk, nullptr);
        JSStringRelease(tk);
        type = jsToUtf8(ctx, tv);
    }
    bool prevented = jscDispatchEvent(ctx, nid, evt, type, bubbles);
    return JSValueMakeBoolean(ctx, !prevented);
}

static JSValueRef jscElementAppendChild(JSContextRef ctx, JSObjectRef, JSObjectRef thisObject, size_t argc, const JSValueRef argv[], JSValueRef*) {
    if (!g_jsHost) return JSValueMakeUndefined(ctx);
    if (argc < 1 || !JSValueIsObject(ctx, argv[0])) return JSValueMakeUndefined(ctx);

    int parentId = jscElNodeId(thisObject);
    JSObjectRef childObj = JSValueToObject(ctx, argv[0], nullptr);
    auto* childPriv = (JscElementPriv*)JSObjectGetPrivate(childObj);
    if (parentId < 0 || !childPriv) return argv[0];
    int childId = childPriv->nodeId;

    domAppendChild(g_jsHost->dom, parentId, childId);
    g_jsHost->domDirty = true;

    // Appending a <script> element runs it (matches browser behavior).
    if (DomNode* child = g_jsHost->dom.get(childId)) {
        if (child->tag == "script") {
            std::string src = domGetAttr(*child, "src");
            std::string code;
            if (!src.empty()) {
                std::string abs = resolveHref(g_jsHost->baseUrl, src);
                if (abs.empty()) abs = src;
                code = fetchSubresourceText(abs);
                if (looksLikeHtmlNotJs(code)) code.clear();
            } else {
                code = domTextContent(g_jsHost->dom, childId);
            }
            if (!trimCopy(code).empty()) {
                JSStringRef script = JSStringCreateWithUTF8CString(code.c_str());
                JSValueRef exc = nullptr;
                (void)JSEvaluateScript(ctx, script, nullptr, nullptr, 1, &exc);
                JSStringRelease(script);
                if (exc) std::cerr << "[JS Exception] " << jsToUtf8(ctx, exc) << "\n";
            }
        }
    }

    return argv[0];
}

static JSValueRef jscElementRemoveChild(JSContextRef ctx, JSObjectRef, JSObjectRef thisObject, size_t argc, const JSValueRef argv[], JSValueRef*) {
    if (!g_jsHost) return JSValueMakeUndefined(ctx);
    if (argc < 1 || !JSValueIsObject(ctx, argv[0])) return JSValueMakeUndefined(ctx);
    int parentId = jscElNodeId(thisObject);
    JSObjectRef childObj = JSValueToObject(ctx, argv[0], nullptr);
    auto* childPriv = (JscElementPriv*)JSObjectGetPrivate(childObj);
    if (parentId < 0 || !childPriv) return argv[0];
    domRemoveChild(g_jsHost->dom, parentId, childPriv->nodeId);
    g_jsHost->domDirty = true;
    return argv[0];
}

static JSValueRef jscElementSetAttribute(JSContextRef ctx, JSObjectRef, JSObjectRef thisObject, size_t argc, const JSValueRef argv[], JSValueRef*) {
    DomNode* n = jscElNode(thisObject);
    if (!n || argc < 2) return JSValueMakeUndefined(ctx);
    std::string k = toLowerCopy(jsToUtf8(ctx, argv[0]));
    std::string v = jsToUtf8(ctx, argv[1]);
    if (!k.empty()) {
        domSetAttr(*n, k, v);
        if (k == "style") domCaptureStyleDisplay(*n, v);
        if (g_jsHost) g_jsHost->domDirty = true;
    }
    return JSValueMakeUndefined(ctx);
}

static JSValueRef jscElementGetAttribute(JSContextRef ctx, JSObjectRef, JSObjectRef thisObject, size_t argc, const JSValueRef argv[], JSValueRef*) {
    DomNode* n = jscElNode(thisObject);
    if (!n || argc < 1) return JSValueMakeNull(ctx);
    std::string k = toLowerCopy(jsToUtf8(ctx, argv[0]));
    const std::string* p = domGetAttrPtr(*n, k);
    if (!p) return JSValueMakeNull(ctx);
    JSStringRef s = JSStringCreateWithUTF8CString(p->c_str());
    JSValueRef r = JSValueMakeString(ctx, s);
    JSStringRelease(s);
    return r;
}


// Event class handlers (defined below; declared here for jscEnsureDomClasses).
static void jscFinalizeEvent(JSObjectRef object);
static JSValueRef jscEventGetProperty(JSContextRef ctx, JSObjectRef object, JSStringRef propertyName, JSValueRef* exception);
static bool jscEventSetProperty(JSContextRef ctx, JSObjectRef object, JSStringRef propertyName, JSValueRef value, JSValueRef* exception);

// XMLHttpRequest class handlers (defined below; declared here for jscEnsureDomClasses).
static void jscFinalizeXhr(JSObjectRef object);
static JSValueRef jscXhrGetProperty(JSContextRef ctx, JSObjectRef object, JSStringRef propertyName, JSValueRef* exception);
static bool jscXhrSetProperty(JSContextRef ctx, JSObjectRef object, JSStringRef propertyName, JSValueRef value, JSValueRef* exception);

static void jscEnsureDomClasses() {
    if (!g_jscStyleClass) {
        JSClassDefinition def = kJSClassDefinitionEmpty;
        def.finalize = jscFinalizeStyle;
        def.getProperty = jscStyleGetProperty;
        def.setProperty = jscStyleSetProperty;
        g_jscStyleClass = JSClassCreate(&def);
    }
    if (!g_jscElementClass) {
        JSClassDefinition def = kJSClassDefinitionEmpty;
        def.finalize = jscFinalizeElement;
        def.getProperty = jscElementGetProperty;
        def.setProperty = jscElementSetProperty;
        g_jscElementClass = JSClassCreate(&def);
    }
    if (!g_jscEventClass) {
        JSClassDefinition def = kJSClassDefinitionEmpty;
        def.finalize = jscFinalizeEvent;
        def.getProperty = jscEventGetProperty;
        def.setProperty = jscEventSetProperty;
        g_jscEventClass = JSClassCreate(&def);
    }
    if (!g_jscXhrClass) {
        JSClassDefinition def = kJSClassDefinitionEmpty;
        def.finalize = jscFinalizeXhr;
        def.getProperty = jscXhrGetProperty;
        def.setProperty = jscXhrSetProperty;
        g_jscXhrClass = JSClassCreate(&def);
    }
}

// -------------------- Event object (JavaScriptCore) --------------------

static void jscFinalizeEvent(JSObjectRef object) {
    auto* priv = (JscEventPriv*)JSObjectGetPrivate(object);
    delete priv;
}

static JscEventPriv* jscEvtPriv(JSObjectRef object) {
    return (JscEventPriv*)JSObjectGetPrivate(object);
}

// Method callbacks: preventDefault / stopPropagation / stopImmediatePropagation.
static JSValueRef jscEvtPreventDefault(JSContextRef ctx, JSObjectRef, JSObjectRef thisObject, size_t, const JSValueRef[], JSValueRef*) {
    if (auto* p = jscEvtPriv(thisObject)) { if (p->cancelable) p->defaultPrevented = true; }
    return JSValueMakeUndefined(ctx);
}
static JSValueRef jscEvtStopPropagation(JSContextRef ctx, JSObjectRef, JSObjectRef thisObject, size_t, const JSValueRef[], JSValueRef*) {
    if (auto* p = jscEvtPriv(thisObject)) p->propagationStopped = true;
    return JSValueMakeUndefined(ctx);
}
static JSValueRef jscEvtStopImmediate(JSContextRef ctx, JSObjectRef, JSObjectRef thisObject, size_t, const JSValueRef[], JSValueRef*) {
    if (auto* p = jscEvtPriv(thisObject)) { p->propagationStopped = true; p->immediateStopped = true; }
    return JSValueMakeUndefined(ctx);
}

static JSValueRef jscEventGetProperty(JSContextRef ctx, JSObjectRef object, JSStringRef propertyName, JSValueRef* /*exception*/) {
    auto* p = jscEvtPriv(object);
    if (!p) return nullptr;
    std::string prop = jsStringToUtf8(propertyName);

    auto makeStr = [&](const std::string& s) -> JSValueRef {
        JSStringRef v = JSStringCreateWithUTF8CString(s.c_str());
        JSValueRef r = JSValueMakeString(ctx, v);
        JSStringRelease(v);
        return r;
    };
    auto makeFn = [&](const char* name, JSObjectCallAsFunctionCallback cb) -> JSValueRef {
        JSStringRef nm = JSStringCreateWithUTF8CString(name);
        JSObjectRef fn = JSObjectMakeFunctionWithCallback(ctx, nm, cb);
        JSStringRelease(nm);
        return fn;
    };
    auto makeEl = [&](int nid) -> JSValueRef {
        if (nid < 0) return JSValueMakeNull(ctx);
        jscEnsureDomClasses();
        return JSObjectMake(ctx, g_jscElementClass, new JscElementPriv{ nid });
    };

    if (prop == "type")             return makeStr(p->type);
    if (prop == "bubbles")          return JSValueMakeBoolean(ctx, p->bubbles);
    if (prop == "cancelable")       return JSValueMakeBoolean(ctx, p->cancelable);
    if (prop == "defaultPrevented") return JSValueMakeBoolean(ctx, p->defaultPrevented);
    if (prop == "eventPhase")       return JSValueMakeNumber(ctx, p->eventPhase);
    if (prop == "target")           return makeEl(p->targetNodeId);
    if (prop == "currentTarget")    return makeEl(p->currentTargetNodeId);
    if (prop == "preventDefault")          return makeFn("preventDefault", jscEvtPreventDefault);
    if (prop == "stopPropagation")         return makeFn("stopPropagation", jscEvtStopPropagation);
    if (prop == "stopImmediatePropagation") return makeFn("stopImmediatePropagation", jscEvtStopImmediate);

    return nullptr; // unknown: delegate to normal own-property storage
}

static bool jscEventSetProperty(JSContextRef /*ctx*/, JSObjectRef object, JSStringRef propertyName, JSValueRef /*value*/, JSValueRef*) {
    if (!jscEvtPriv(object)) return false;
    std::string prop = jsStringToUtf8(propertyName);
    // Standard fields are read-only here; everything else (clientX, key, ...) is
    // stored as a normal own property (return false delegates to default store).
    if (prop == "type" || prop == "bubbles" || prop == "cancelable" ||
        prop == "defaultPrevented" || prop == "eventPhase" ||
        prop == "target" || prop == "currentTarget" ||
        prop == "preventDefault" || prop == "stopPropagation" ||
        prop == "stopImmediatePropagation")
        return true; // swallow writes to standard members
    return false;
}

// Build a backed Event instance (no constructor invocation).
static JSObjectRef jscMakeEvent(JSContextRef ctx, const std::string& type, bool bubbles, bool cancelable) {
    jscEnsureDomClasses();
    auto* p = new JscEventPriv();
    p->type = type;
    p->bubbles = bubbles;
    p->cancelable = cancelable;
    return JSObjectMake(ctx, g_jscEventClass, p);
}

// Read .bubbles/.cancelable off an options object (any may be missing).
static void jscReadEventOptions(JSContextRef ctx, JSValueRef opts, bool& bubbles, bool& cancelable) {
    if (!opts || !JSValueIsObject(ctx, opts)) return;
    JSObjectRef o = JSValueToObject(ctx, opts, nullptr);
    JSStringRef bk = JSStringCreateWithUTF8CString("bubbles");
    JSValueRef bv = JSObjectGetProperty(ctx, o, bk, nullptr);
    JSStringRelease(bk);
    if (bv && !JSValueIsUndefined(ctx, bv)) bubbles = JSValueToBoolean(ctx, bv);
    JSStringRef ck = JSStringCreateWithUTF8CString("cancelable");
    JSValueRef cv = JSObjectGetProperty(ctx, o, ck, nullptr);
    JSStringRelease(ck);
    if (cv && !JSValueIsUndefined(ctx, cv)) cancelable = JSValueToBoolean(ctx, cv);
}

// Native factory backing the Event() JS shim. JavaScriptCore's C API can make
// EITHER a callable function (typeof "function" but not `new`-able) OR a
// constructor (new-able but typeof "object"); neither alone satisfies a page
// that checks `typeof Event === "function"` AND does `new Event(...)`. So we
// expose this native factory and define Event/CustomEvent as real JS functions
// (see kEventShim) that return the backed object — which `new` then adopts.
static JSValueRef jscMakeEventNative(JSContextRef ctx, JSObjectRef /*function*/, JSObjectRef /*thisObject*/, size_t argc, const JSValueRef argv[], JSValueRef* /*exception*/) {
    std::string type = (argc > 0) ? jsToUtf8(ctx, argv[0]) : "";
    bool bubbles = false, cancelable = false;
    if (argc > 1) jscReadEventOptions(ctx, argv[1], bubbles, cancelable);
    return jscMakeEvent(ctx, type, bubbles, cancelable);
}

static JSValueRef jscMakeCustomEventNative(JSContextRef ctx, JSObjectRef /*function*/, JSObjectRef /*thisObject*/, size_t argc, const JSValueRef argv[], JSValueRef* /*exception*/) {
    std::string type = (argc > 0) ? jsToUtf8(ctx, argv[0]) : "";
    bool bubbles = false, cancelable = false;
    if (argc > 1) jscReadEventOptions(ctx, argv[1], bubbles, cancelable);
    JSObjectRef obj = jscMakeEvent(ctx, type, bubbles, cancelable);
    JSValueRef detail = JSValueMakeNull(ctx);
    if (argc > 1 && JSValueIsObject(ctx, argv[1])) {
        JSObjectRef o = JSValueToObject(ctx, argv[1], nullptr);
        JSStringRef dk = JSStringCreateWithUTF8CString("detail");
        JSValueRef dv = JSObjectGetProperty(ctx, o, dk, nullptr);
        JSStringRelease(dk);
        if (dv && !JSValueIsUndefined(ctx, dv)) detail = dv;
    }
    // detail is an ordinary own property.
    JSStringRef dn = JSStringCreateWithUTF8CString("detail");
    JSObjectSetProperty(ctx, obj, dn, detail, kJSPropertyAttributeNone, nullptr);
    JSStringRelease(dn);
    return obj;
}

// -------------------- XMLHttpRequest object (JavaScriptCore) --------------------

static void jscFinalizeXhr(JSObjectRef object) {
    auto* priv = (JscXhrPriv*)JSObjectGetPrivate(object);
    delete priv;
}

static JscXhrPriv* jscXhrPriv(JSObjectRef object) {
    return (JscXhrPriv*)JSObjectGetPrivate(object);
}

// Read an on* handler back off the XHR object and, if callable, invoke it with
// the XHR as `this` and no args. on* handlers are ordinary own properties.
static void jscXhrFireHandler(JSContextRef ctx, JSObjectRef xhr, const char* name) {
    JSStringRef nm = JSStringCreateWithUTF8CString(name);
    JSValueRef h = JSObjectGetProperty(ctx, xhr, nm, nullptr);
    JSStringRelease(nm);
    if (!h || !JSValueIsObject(ctx, h)) return;
    JSObjectRef fn = JSValueToObject(ctx, h, nullptr);
    if (!fn || !JSObjectIsFunction(ctx, fn)) return;
    JSValueRef exc = nullptr;
    JSObjectCallAsFunction(ctx, fn, xhr, 0, nullptr, &exc);
    if (exc) std::cerr << "[JS Exception] " << jsToUtf8(ctx, exc) << "\n";
}

// open(method, url, async?)
static JSValueRef jscXhrOpen(JSContextRef ctx, JSObjectRef, JSObjectRef thisObject, size_t argc, const JSValueRef argv[], JSValueRef*) {
    auto* p = jscXhrPriv(thisObject);
    if (!p) return JSValueMakeUndefined(ctx);
    std::string method = (argc > 0) ? jsToUtf8(ctx, argv[0]) : "GET";
    p->method = toUpperCopy(method);
    std::string url = (argc > 1) ? jsToUtf8(ctx, argv[1]) : "";
    std::string abs = g_jsHost ? resolveHref(g_jsHost->baseUrl, url) : url;
    if (abs.empty()) abs = url;
    p->url = abs;
    p->readyState = 1;
    p->sent = false;
    return JSValueMakeUndefined(ctx);
}

// setRequestHeader(name, value): accepted and ignored (no-op).
static JSValueRef jscXhrSetRequestHeader(JSContextRef ctx, JSObjectRef, JSObjectRef, size_t, const JSValueRef[], JSValueRef*) {
    return JSValueMakeUndefined(ctx);
}

// send(body?): perform the request synchronously NOW, then fire callbacks.
// The underlying transport is GET-only; for non-GET methods we still do a GET.
static JSValueRef jscXhrSend(JSContextRef ctx, JSObjectRef, JSObjectRef thisObject, size_t, const JSValueRef[], JSValueRef*) {
    auto* p = jscXhrPriv(thisObject);
    if (!p) return JSValueMakeUndefined(ctx);
    p->sent = true;

    std::string headers;
    Url finalU;
    std::string body;
    try {
        body = httpFetchProcessed(parseUrl(p->url), finalU, &headers);
    } catch (...) {
        body = "";
    }

    p->responseText = body;
    p->responseHeaders = headers;
    int code = parseStatusCode(headers);
    if (code == 0 && !body.empty()) code = 200; // body but no parseable status
    p->status = code;
    if (code >= 200 && code < 300) p->statusText = "OK";
    else p->statusText = "";
    p->readyState = 4;

    // Fire callbacks in order: onreadystatechange (sees readyState===4), then
    // onload for 2xx else onerror.
    jscXhrFireHandler(ctx, thisObject, "onreadystatechange");
    if (code >= 200 && code < 300) jscXhrFireHandler(ctx, thisObject, "onload");
    else jscXhrFireHandler(ctx, thisObject, "onerror");

    return JSValueMakeUndefined(ctx);
}

// getAllResponseHeaders(): raw header block stored during send().
static JSValueRef jscXhrGetAllResponseHeaders(JSContextRef ctx, JSObjectRef, JSObjectRef thisObject, size_t, const JSValueRef[], JSValueRef*) {
    auto* p = jscXhrPriv(thisObject);
    std::string s = p ? p->responseHeaders : "";
    JSStringRef v = JSStringCreateWithUTF8CString(s.c_str());
    JSValueRef r = JSValueMakeString(ctx, v);
    JSStringRelease(v);
    return r;
}

// getResponseHeader(name): look up a single header in the stored block.
static JSValueRef jscXhrGetResponseHeader(JSContextRef ctx, JSObjectRef, JSObjectRef thisObject, size_t argc, const JSValueRef argv[], JSValueRef*) {
    auto* p = jscXhrPriv(thisObject);
    if (!p || argc < 1) return JSValueMakeNull(ctx);
    std::string val = headerValueCI(p->responseHeaders, jsToUtf8(ctx, argv[0]));
    if (val.empty()) return JSValueMakeNull(ctx);
    JSStringRef v = JSStringCreateWithUTF8CString(val.c_str());
    JSValueRef r = JSValueMakeString(ctx, v);
    JSStringRelease(v);
    return r;
}

// abort(): no-op (reset readyState).
static JSValueRef jscXhrAbort(JSContextRef ctx, JSObjectRef, JSObjectRef thisObject, size_t, const JSValueRef[], JSValueRef*) {
    if (auto* p = jscXhrPriv(thisObject)) p->readyState = 0;
    return JSValueMakeUndefined(ctx);
}

static JSValueRef jscXhrGetProperty(JSContextRef ctx, JSObjectRef object, JSStringRef propertyName, JSValueRef* /*exception*/) {
    auto* p = jscXhrPriv(object);
    if (!p) return nullptr;
    std::string prop = jsStringToUtf8(propertyName);

    auto makeStr = [&](const std::string& s) -> JSValueRef {
        JSStringRef v = JSStringCreateWithUTF8CString(s.c_str());
        JSValueRef r = JSValueMakeString(ctx, v);
        JSStringRelease(v);
        return r;
    };
    auto makeFn = [&](const char* name, JSObjectCallAsFunctionCallback cb) -> JSValueRef {
        JSStringRef nm = JSStringCreateWithUTF8CString(name);
        JSObjectRef fn = JSObjectMakeFunctionWithCallback(ctx, nm, cb);
        JSStringRelease(nm);
        return fn;
    };

    if (prop == "readyState")   return JSValueMakeNumber(ctx, p->readyState);
    if (prop == "status")       return JSValueMakeNumber(ctx, p->status);
    if (prop == "statusText")   return makeStr(p->statusText);
    if (prop == "responseText") return makeStr(p->responseText);
    if (prop == "responseType") return makeStr(p->responseType);
    if (prop == "response")     return makeStr(p->responseText); // text-equivalent
    if (prop == "open")                   return makeFn("open", jscXhrOpen);
    if (prop == "setRequestHeader")       return makeFn("setRequestHeader", jscXhrSetRequestHeader);
    if (prop == "send")                   return makeFn("send", jscXhrSend);
    if (prop == "getAllResponseHeaders")  return makeFn("getAllResponseHeaders", jscXhrGetAllResponseHeaders);
    if (prop == "getResponseHeader")      return makeFn("getResponseHeader", jscXhrGetResponseHeader);
    if (prop == "abort")                  return makeFn("abort", jscXhrAbort);

    return nullptr; // unknown (on* handlers, etc.): normal own-property storage
}

static bool jscXhrSetProperty(JSContextRef ctx, JSObjectRef object, JSStringRef propertyName, JSValueRef value, JSValueRef*) {
    auto* p = jscXhrPriv(object);
    if (!p) return false;
    std::string prop = jsStringToUtf8(propertyName);
    if (prop == "responseType") { p->responseType = jsToUtf8(ctx, value); return true; }
    // readyState/status/statusText/responseText/response and the methods are
    // read-only; swallow writes. Everything else (on* handlers, ad-hoc props)
    // delegates to normal own-property storage.
    if (prop == "readyState" || prop == "status" || prop == "statusText" ||
        prop == "responseText" || prop == "response" ||
        prop == "open" || prop == "setRequestHeader" || prop == "send" ||
        prop == "getAllResponseHeaders" || prop == "getResponseHeader" || prop == "abort")
        return true;
    return false;
}

// Build a backed XMLHttpRequest instance (no constructor body).
static JSObjectRef jscMakeXhr(JSContextRef ctx) {
    jscEnsureDomClasses();
    return JSObjectMake(ctx, g_jscXhrClass, new JscXhrPriv());
}

// Native factory backing the XMLHttpRequest() constructor shim.
static JSValueRef jscMakeXhrNative(JSContextRef ctx, JSObjectRef /*function*/, JSObjectRef /*thisObject*/, size_t, const JSValueRef[], JSValueRef* /*exception*/) {
    return jscMakeXhr(ctx);
}

// Fire every listener registered under `key`, passing evt as the single arg.
// Stops early if the event's stopImmediatePropagation() was called.
static void jscFireListeners(JSContextRef ctx, const std::string& key, JSObjectRef evt) {
    if (!g_jsHost) return;
    auto it = g_jsHost->listeners.find(key);
    if (it == g_jsHost->listeners.end()) return;
    auto* ep = (JscEventPriv*)JSObjectGetPrivate(evt); // may be null for plain events
    std::vector<JSObjectRef> fns = it->second; // copy (handler may mutate the map)
    for (auto* fn : fns) {
        if (!fn) continue;
        JSValueRef exc = nullptr;
        JSValueRef arg = evt;
        JSObjectCallAsFunction(ctx, fn, nullptr, 1, &arg, &exc);
        if (exc) std::cerr << "[JS Exception] " << jsToUtf8(ctx, exc) << "\n";
        if (ep && ep->immediateStopped) break; // stopImmediatePropagation()
    }
}

// Remove every listener stored under `key` whose function is identity-equal to
// fn; removed entries are unprotected.
static void jscRemoveListener(JSContextRef ctx, const std::string& key, JSObjectRef fn) {
    if (!g_jsHost || !fn) return;
    auto it = g_jsHost->listeners.find(key);
    if (it == g_jsHost->listeners.end()) return;
    auto& vec = it->second;
    for (size_t i = 0; i < vec.size();) {
        if (vec[i] == fn) {
            JSValueUnprotect(ctx, vec[i]);
            vec.erase(vec.begin() + i);
        } else {
            ++i;
        }
    }
}

// Unified DOM event dispatch with bubbling. Returns evt.defaultPrevented.
static bool jscDispatchEvent(JSContextRef ctx, int targetNodeId, JSObjectRef evt,
                             const std::string& type, bool bubbles) {
    if (!g_jsHost) return false;
    auto* ep = (JscEventPriv*)JSObjectGetPrivate(evt);
    if (ep) {
        ep->targetNodeId = targetNodeId;
        ep->propagationStopped = false;
        ep->immediateStopped = false;
    }

    // Propagation path: target, then ancestors up to (not including) root.
    std::vector<int> path;
    if (targetNodeId >= 0) {
        for (int n = targetNodeId; n >= 0 && n != g_jsHost->dom.root;) {
            path.push_back(n);
            DomNode* dn = g_jsHost->dom.get(n);
            n = dn ? dn->parent : -1;
        }
    }

    bool stopped = false;
    for (size_t i = 0; i < path.size(); ++i) {
        if (i > 0 && !bubbles) break; // non-bubbling: target only
        if (ep) ep->currentTargetNodeId = path[i];
        jscFireListeners(ctx, "node:" + std::to_string(path[i]) + ":" + type, evt);
        if (ep && ep->propagationStopped) { stopped = true; break; }
    }

    if ((bubbles || path.empty()) && !stopped) {
        if (ep) ep->currentTargetNodeId = -1;
        jscFireListeners(ctx, "document:" + type, evt);
        if (!(ep && ep->propagationStopped))
            jscFireListeners(ctx, "window:" + type, evt);
    }

    return ep ? ep->defaultPrevented : false;
}

static JSValueRef jscGetElementById(JSContextRef ctx, JSObjectRef, JSObjectRef, size_t argc, const JSValueRef argv[], JSValueRef*) {
    if (!g_jsHost || argc < 1) return JSValueMakeNull(ctx);
    std::string id = jsToUtf8(ctx, argv[0]);
    if (id.empty()) return JSValueMakeNull(ctx);

    int nid = domFindById(g_jsHost->dom, g_jsHost->dom.root, id);
    if (nid < 0) {
        // Unknown id: hand back a detached element so getElementById(...).x
        // doesn't throw. It is not part of the rendered tree.
        nid = g_jsHost->dom.alloc(DomNodeType::Element);
        g_jsHost->dom.nodes[nid].tag = "div";
        domSetAttr(g_jsHost->dom.nodes[nid], "id", id);
    }
    jscEnsureDomClasses();
    return JSObjectMake(ctx, g_jscElementClass, new JscElementPriv{ nid });
}

static JSValueRef jscQuerySelector(JSContextRef ctx, JSObjectRef, JSObjectRef, size_t argc, const JSValueRef argv[], JSValueRef*) {
    if (!g_jsHost || argc < 1) return JSValueMakeNull(ctx);
    std::string sel = trimCopy(jsToUtf8(ctx, argv[0]));
    if (sel.empty() || sel.find(' ') != std::string::npos) return JSValueMakeNull(ctx);

    int nid = -1;
    if (sel[0] == '#')      nid = domFindById(g_jsHost->dom, g_jsHost->dom.root, sel.substr(1));
    else if (sel[0] == '.') nid = domFindByClass(g_jsHost->dom, g_jsHost->dom.root, sel.substr(1));
    else                    nid = domFindByTag(g_jsHost->dom, g_jsHost->dom.root, toLowerCopy(sel));

    if (nid < 0) return JSValueMakeNull(ctx);
    jscEnsureDomClasses();
    return JSObjectMake(ctx, g_jscElementClass, new JscElementPriv{ nid });
}

static JSValueRef jscNodeArray(JSContextRef ctx, const std::vector<int>& nids) {
    jscEnsureDomClasses();
    std::vector<JSValueRef> elems;
    elems.reserve(nids.size());
    for (int nid : nids) elems.push_back(JSObjectMake(ctx, g_jscElementClass, new JscElementPriv{ nid }));
    JSValueRef exc = nullptr;
    JSObjectRef arr = JSObjectMakeArray(ctx, elems.size(), elems.empty() ? nullptr : elems.data(), &exc);
    return arr ? (JSValueRef)arr : JSValueMakeNull(ctx);
}

// ---------- Batch 1: DOM mutation / classList / text nodes (JSC) ----------

static int jscArgNodeId(JSContextRef ctx, JSValueRef v) {
    if (!JSValueIsObject(ctx, v)) return -1;
    auto* p = (JscElementPriv*)JSObjectGetPrivate(JSValueToObject(ctx, v, nullptr));
    return p ? p->nodeId : -1;
}

static JSValueRef jscElementInsertBefore(JSContextRef ctx, JSObjectRef, JSObjectRef thisObject, size_t argc, const JSValueRef argv[], JSValueRef*) {
    if (!g_jsHost || argc < 1) return JSValueMakeUndefined(ctx);
    int pid = jscElNodeId(thisObject);
    int newId = jscArgNodeId(ctx, argv[0]);
    int refId = (argc >= 2) ? jscArgNodeId(ctx, argv[1]) : -1;
    if (pid < 0 || newId < 0) return argv[0];
    domInsertBefore(g_jsHost->dom, pid, newId, refId);
    g_jsHost->domDirty = true;
    return argv[0];
}
static JSValueRef jscElementReplaceChild(JSContextRef ctx, JSObjectRef, JSObjectRef thisObject, size_t argc, const JSValueRef argv[], JSValueRef*) {
    if (!g_jsHost || argc < 2) return JSValueMakeUndefined(ctx);
    int pid = jscElNodeId(thisObject);
    int newId = jscArgNodeId(ctx, argv[0]);
    int oldId = jscArgNodeId(ctx, argv[1]);
    if (pid < 0 || newId < 0 || oldId < 0) return JSValueMakeUndefined(ctx);
    domInsertBefore(g_jsHost->dom, pid, newId, oldId);
    domRemoveChild(g_jsHost->dom, pid, oldId);
    g_jsHost->domDirty = true;
    return argv[1];
}
static JSValueRef jscElementCloneNode(JSContextRef ctx, JSObjectRef, JSObjectRef thisObject, size_t argc, const JSValueRef argv[], JSValueRef*) {
    if (!g_jsHost) return JSValueMakeNull(ctx);
    int nid = jscElNodeId(thisObject);
    if (nid < 0) return JSValueMakeNull(ctx);
    bool deep = (argc > 0) && JSValueToBoolean(ctx, argv[0]);
    int cl = domCloneSubtree(g_jsHost->dom, nid, deep);
    if (cl < 0) return JSValueMakeNull(ctx);
    jscEnsureDomClasses();
    return JSObjectMake(ctx, g_jscElementClass, new JscElementPriv{ cl });
}
static JSValueRef jscElementHasAttribute(JSContextRef ctx, JSObjectRef, JSObjectRef thisObject, size_t argc, const JSValueRef argv[], JSValueRef*) {
    DomNode* n = jscElNode(thisObject);
    if (!n || argc < 1) return JSValueMakeBoolean(ctx, false);
    return JSValueMakeBoolean(ctx, domGetAttrPtr(*n, toLowerCopy(jsToUtf8(ctx, argv[0]))) != nullptr);
}
static JSValueRef jscElementRemoveAttribute(JSContextRef ctx, JSObjectRef, JSObjectRef thisObject, size_t argc, const JSValueRef argv[], JSValueRef*) {
    DomNode* n = jscElNode(thisObject);
    if (n && argc >= 1) {
        domRemoveAttr(*n, toLowerCopy(jsToUtf8(ctx, argv[0])));
        if (g_jsHost) g_jsHost->domDirty = true;
    }
    return JSValueMakeUndefined(ctx);
}

// classList: a plain object carrying its element id in a hidden "_nid" property.
static int jscClassListNid(JSContextRef ctx, JSObjectRef thisObject) {
    JSStringRef k = JSStringCreateWithUTF8CString("_nid");
    JSValueRef v = JSObjectGetProperty(ctx, thisObject, k, nullptr);
    JSStringRelease(k);
    return (int)JSValueToNumber(ctx, v, nullptr);
}
static JSValueRef jscClassListAdd(JSContextRef ctx, JSObjectRef, JSObjectRef thisObject, size_t argc, const JSValueRef argv[], JSValueRef*) {
    if (g_jsHost) if (DomNode* n = g_jsHost->dom.get(jscClassListNid(ctx, thisObject)))
        for (size_t i = 0; i < argc; ++i) { domClassAdd(*n, jsToUtf8(ctx, argv[i])); g_jsHost->domDirty = true; }
    return JSValueMakeUndefined(ctx);
}
static JSValueRef jscClassListRemove(JSContextRef ctx, JSObjectRef, JSObjectRef thisObject, size_t argc, const JSValueRef argv[], JSValueRef*) {
    if (g_jsHost) if (DomNode* n = g_jsHost->dom.get(jscClassListNid(ctx, thisObject)))
        for (size_t i = 0; i < argc; ++i) { domClassRemove(*n, jsToUtf8(ctx, argv[i])); g_jsHost->domDirty = true; }
    return JSValueMakeUndefined(ctx);
}
static JSValueRef jscClassListContains(JSContextRef ctx, JSObjectRef, JSObjectRef thisObject, size_t argc, const JSValueRef argv[], JSValueRef*) {
    if (argc >= 1 && g_jsHost) if (DomNode* n = g_jsHost->dom.get(jscClassListNid(ctx, thisObject)))
        return JSValueMakeBoolean(ctx, domClassContains(*n, jsToUtf8(ctx, argv[0])));
    return JSValueMakeBoolean(ctx, false);
}
static JSValueRef jscClassListToggle(JSContextRef ctx, JSObjectRef, JSObjectRef thisObject, size_t argc, const JSValueRef argv[], JSValueRef*) {
    if (argc < 1 || !g_jsHost) return JSValueMakeBoolean(ctx, false);
    DomNode* n = g_jsHost->dom.get(jscClassListNid(ctx, thisObject));
    if (!n) return JSValueMakeBoolean(ctx, false);
    std::string cls = jsToUtf8(ctx, argv[0]);
    bool add = (argc >= 2) ? JSValueToBoolean(ctx, argv[1]) : !domClassContains(*n, cls);
    if (add) domClassAdd(*n, cls); else domClassRemove(*n, cls);
    g_jsHost->domDirty = true;
    return JSValueMakeBoolean(ctx, add);
}
static JSObjectRef jscMakeClassList(JSContextRef ctx, int nid) {
    JSObjectRef o = JSObjectMake(ctx, nullptr, nullptr);
    JSStringRef k = JSStringCreateWithUTF8CString("_nid");
    JSObjectSetProperty(ctx, o, k, JSValueMakeNumber(ctx, nid),
                        kJSPropertyAttributeDontEnum | kJSPropertyAttributeReadOnly, nullptr);
    JSStringRelease(k);
    auto add = [&](const char* name, JSObjectCallAsFunctionCallback cb) {
        JSStringRef nm = JSStringCreateWithUTF8CString(name);
        JSObjectSetProperty(ctx, o, nm, JSObjectMakeFunctionWithCallback(ctx, nm, cb), kJSPropertyAttributeNone, nullptr);
        JSStringRelease(nm);
    };
    add("add", jscClassListAdd);
    add("remove", jscClassListRemove);
    add("toggle", jscClassListToggle);
    add("contains", jscClassListContains);
    return o;
}

static JSValueRef jscCreateTextNode(JSContextRef ctx, JSObjectRef, JSObjectRef, size_t argc, const JSValueRef argv[], JSValueRef*) {
    if (!g_jsHost) return JSValueMakeNull(ctx);
    int nid = g_jsHost->dom.alloc(DomNodeType::Text);
    g_jsHost->dom.nodes[nid].text = (argc > 0) ? jsToUtf8(ctx, argv[0]) : "";
    jscEnsureDomClasses();
    return JSObjectMake(ctx, g_jscElementClass, new JscElementPriv{ nid });
}

static JSValueRef jscGetElementsByTagName(JSContextRef ctx, JSObjectRef, JSObjectRef, size_t argc, const JSValueRef argv[], JSValueRef*) {
    if (!g_jsHost || argc < 1) return jscNodeArray(ctx, {});
    std::vector<int> found;
    domCollectByTag(g_jsHost->dom, g_jsHost->dom.root, toLowerCopy(jsToUtf8(ctx, argv[0])), found);
    return jscNodeArray(ctx, found);
}

static JSValueRef jscGetElementsByClassName(JSContextRef ctx, JSObjectRef, JSObjectRef, size_t argc, const JSValueRef argv[], JSValueRef*) {
    if (!g_jsHost || argc < 1) return jscNodeArray(ctx, {});
    std::vector<int> found;
    domCollectByClass(g_jsHost->dom, g_jsHost->dom.root, trimCopy(jsToUtf8(ctx, argv[0])), found);
    return jscNodeArray(ctx, found);
}

static JSValueRef jscQuerySelectorAll(JSContextRef ctx, JSObjectRef, JSObjectRef, size_t argc, const JSValueRef argv[], JSValueRef*) {
    if (!g_jsHost || argc < 1) return jscNodeArray(ctx, {});
    std::string sel = trimCopy(jsToUtf8(ctx, argv[0]));
    std::vector<int> found;
    if (sel.size() > 1 && sel[0] == '.') domCollectByClass(g_jsHost->dom, g_jsHost->dom.root, sel.substr(1), found);
    else if (sel.size() > 1 && sel[0] == '#') { int n = domFindById(g_jsHost->dom, g_jsHost->dom.root, sel.substr(1)); if (n >= 0) found.push_back(n); }
    else if (!sel.empty() && sel.find(' ') == std::string::npos) domCollectByTag(g_jsHost->dom, g_jsHost->dom.root, toLowerCopy(sel), found);
    return jscNodeArray(ctx, found);
}

static JSValueRef jscPerformanceNow(JSContextRef ctx, JSObjectRef, JSObjectRef, size_t, const JSValueRef[], JSValueRef*) {
    if (!g_jsHost) return JSValueMakeNumber(ctx, 0.0);
    auto now = std::chrono::steady_clock::now();
    double ms = std::chrono::duration<double, std::milli>(now - g_jsHost->perfStart).count();
    return JSValueMakeNumber(ctx, ms);
}

static void jsSetupPageGlobals(JSContextRef ctx, const std::string& url, const std::string& title) {
    JSObjectRef global = JSContextGetGlobalObject(ctx);

    // document
    JSObjectRef document = JSObjectMake(ctx, nullptr, nullptr);
    {
        JSStringRef k = JSStringCreateWithUTF8CString("title");
        JSStringRef v = JSStringCreateWithUTF8CString(title.c_str());
        JSValueRef vStr = JSValueMakeString(ctx, v);
        JSObjectSetProperty(ctx, document, k, vStr, kJSPropertyAttributeNone, nullptr);
        JSStringRelease(v);
        JSStringRelease(k);

        // document.addEventListener
        JSStringRef ael = JSStringCreateWithUTF8CString("addEventListener");
        JSObjectRef aelFn = JSObjectMakeFunctionWithCallback(ctx, ael, [](JSContextRef ctx, JSObjectRef, JSObjectRef, size_t argc, const JSValueRef argv[], JSValueRef*) -> JSValueRef {
            if (!g_jsHost) return JSValueMakeUndefined(ctx);
            if (argc < 2) return JSValueMakeUndefined(ctx);
            std::string type = jsToUtf8(ctx, argv[0]);
            if (!JSValueIsObject(ctx, argv[1])) return JSValueMakeUndefined(ctx);
            JSObjectRef fn = JSValueToObject(ctx, argv[1], nullptr);
            if (!fn || !JSObjectIsFunction(ctx, fn)) return JSValueMakeUndefined(ctx);
            jscAddListenerCtx(ctx, "document:" + type, fn);
            return JSValueMakeUndefined(ctx);
        });
        JSObjectSetProperty(ctx, document, ael, aelFn, kJSPropertyAttributeNone, nullptr);
        JSStringRelease(ael);

        // document.removeEventListener
        JSStringRef rel = JSStringCreateWithUTF8CString("removeEventListener");
        JSObjectRef relFn = JSObjectMakeFunctionWithCallback(ctx, rel, [](JSContextRef ctx, JSObjectRef, JSObjectRef, size_t argc, const JSValueRef argv[], JSValueRef*) -> JSValueRef {
            if (!g_jsHost) return JSValueMakeUndefined(ctx);
            if (argc < 2 || !JSValueIsObject(ctx, argv[1])) return JSValueMakeUndefined(ctx);
            std::string type = jsToUtf8(ctx, argv[0]);
            JSObjectRef fn = JSValueToObject(ctx, argv[1], nullptr);
            if (fn) jscRemoveListener(ctx, "document:" + type, fn);
            return JSValueMakeUndefined(ctx);
        });
        JSObjectSetProperty(ctx, document, rel, relFn, kJSPropertyAttributeNone, nullptr);
        JSStringRelease(rel);

        // document.getElementById
        JSStringRef gebi = JSStringCreateWithUTF8CString("getElementById");
        JSObjectRef gebiFn = JSObjectMakeFunctionWithCallback(ctx, gebi, jscGetElementById);
        JSObjectSetProperty(ctx, document, gebi, gebiFn, kJSPropertyAttributeNone, nullptr);
        JSStringRelease(gebi);

        // document.createElement
        JSStringRef ce = JSStringCreateWithUTF8CString("createElement");
        JSObjectRef ceFn = JSObjectMakeFunctionWithCallback(ctx, ce, [](JSContextRef ctx, JSObjectRef, JSObjectRef, size_t argc, const JSValueRef argv[], JSValueRef*) -> JSValueRef {
            if (!g_jsHost || argc < 1) return JSValueMakeNull(ctx);
            std::string tag = toLowerCopy(jsToUtf8(ctx, argv[0]));
            if (tag.empty()) tag = "div";

            int nid = g_jsHost->dom.alloc(DomNodeType::Element);
            g_jsHost->dom.nodes[nid].tag = tag;
            jscEnsureDomClasses();
            return JSObjectMake(ctx, g_jscElementClass, new JscElementPriv{ nid });
        });
        JSObjectSetProperty(ctx, document, ce, ceFn, kJSPropertyAttributeNone, nullptr);
        JSStringRelease(ce);

        // document.createTextNode
        JSStringRef ctn = JSStringCreateWithUTF8CString("createTextNode");
        JSObjectRef ctnFn = JSObjectMakeFunctionWithCallback(ctx, ctn, jscCreateTextNode);
        JSObjectSetProperty(ctx, document, ctn, ctnFn, kJSPropertyAttributeNone, nullptr);
        JSStringRelease(ctn);

        // document.body / document.head resolve to the real <body>/<head> nodes
        // (created if the page omitted them) so appendChild() actually renders.
        jscEnsureDomClasses();
        JSObjectRef body = JSObjectMake(ctx, g_jscElementClass, new JscElementPriv{ domFindOrCreateTag(g_jsHost->dom, "body") });
        JSObjectRef head = JSObjectMake(ctx, g_jscElementClass, new JscElementPriv{ domFindOrCreateTag(g_jsHost->dom, "head") });
        JSStringRef bname = JSStringCreateWithUTF8CString("body");
        JSObjectSetProperty(ctx, document, bname, body, kJSPropertyAttributeNone, nullptr);
        JSStringRelease(bname);
        JSStringRef hname = JSStringCreateWithUTF8CString("head");
        JSObjectSetProperty(ctx, document, hname, head, kJSPropertyAttributeNone, nullptr);
        JSStringRelease(hname);

        JSStringRef qs = JSStringCreateWithUTF8CString("querySelector");
        JSObjectRef qsFn = JSObjectMakeFunctionWithCallback(ctx, qs, jscQuerySelector);
        JSObjectSetProperty(ctx, document, qs, qsFn, kJSPropertyAttributeNone, nullptr);
        JSStringRelease(qs);

        auto setDocFn = [&](const char* name, JSObjectCallAsFunctionCallback cb) {
            JSStringRef n = JSStringCreateWithUTF8CString(name);
            JSObjectSetProperty(ctx, document, n, JSObjectMakeFunctionWithCallback(ctx, n, cb), kJSPropertyAttributeNone, nullptr);
            JSStringRelease(n);
        };
        setDocFn("querySelectorAll", jscQuerySelectorAll);
        setDocFn("getElementsByTagName", jscGetElementsByTagName);
        setDocFn("getElementsByClassName", jscGetElementsByClassName);

        JSObjectRef docEl = JSObjectMake(ctx, g_jscElementClass, new JscElementPriv{ domFindOrCreateTag(g_jsHost->dom, "html") });
        JSStringRef den = JSStringCreateWithUTF8CString("documentElement");
        JSObjectSetProperty(ctx, document, den, docEl, kJSPropertyAttributeNone, nullptr);
        JSStringRelease(den);
    }

    JSStringRef docName = JSStringCreateWithUTF8CString("document");
    JSObjectSetProperty(ctx, global, docName, document, kJSPropertyAttributeNone, nullptr);
    JSStringRelease(docName);

    // location.href
    JSObjectRef location = JSObjectMake(ctx, nullptr, nullptr);
    {
        JSStringRef k = JSStringCreateWithUTF8CString("href");
        JSStringRef v = JSStringCreateWithUTF8CString(url.c_str());
        JSValueRef vStr = JSValueMakeString(ctx, v);
        JSObjectSetProperty(ctx, location, k, vStr, kJSPropertyAttributeNone, nullptr);
        JSStringRelease(v);
        JSStringRelease(k);
    }
    JSStringRef locName = JSStringCreateWithUTF8CString("location");
    JSObjectSetProperty(ctx, global, locName, location, kJSPropertyAttributeNone, nullptr);
    JSStringRelease(locName);

    
    // window.addEventListener
    {
        JSStringRef ael = JSStringCreateWithUTF8CString("addEventListener");
        JSObjectRef aelFn = JSObjectMakeFunctionWithCallback(ctx, ael, [](JSContextRef ctx, JSObjectRef, JSObjectRef, size_t argc, const JSValueRef argv[], JSValueRef*) -> JSValueRef {
            if (!g_jsHost) return JSValueMakeUndefined(ctx);
            if (argc < 2) return JSValueMakeUndefined(ctx);
            std::string type = jsToUtf8(ctx, argv[0]);
            if (!JSValueIsObject(ctx, argv[1])) return JSValueMakeUndefined(ctx);
            JSObjectRef fn = JSValueToObject(ctx, argv[1], nullptr);
            if (!fn || !JSObjectIsFunction(ctx, fn)) return JSValueMakeUndefined(ctx);
            jscAddListenerCtx(ctx, "window:" + type, fn);
            return JSValueMakeUndefined(ctx);
        });
        JSObjectSetProperty(ctx, global, ael, aelFn, kJSPropertyAttributeNone, nullptr);
        JSStringRelease(ael);

        // window.removeEventListener
        JSStringRef rel = JSStringCreateWithUTF8CString("removeEventListener");
        JSObjectRef relFn = JSObjectMakeFunctionWithCallback(ctx, rel, [](JSContextRef ctx, JSObjectRef, JSObjectRef, size_t argc, const JSValueRef argv[], JSValueRef*) -> JSValueRef {
            if (!g_jsHost) return JSValueMakeUndefined(ctx);
            if (argc < 2 || !JSValueIsObject(ctx, argv[1])) return JSValueMakeUndefined(ctx);
            std::string type = jsToUtf8(ctx, argv[0]);
            JSObjectRef fn = JSValueToObject(ctx, argv[1], nullptr);
            if (fn) jscRemoveListener(ctx, "window:" + type, fn);
            return JSValueMakeUndefined(ctx);
        });
        JSObjectSetProperty(ctx, global, rel, relFn, kJSPropertyAttributeNone, nullptr);
        JSStringRelease(rel);
    }
// navigator.userAgent
    JSObjectRef navigator = JSObjectMake(ctx, nullptr, nullptr);
    {
        JSStringRef k = JSStringCreateWithUTF8CString("userAgent");
        JSStringRef v = JSStringCreateWithUTF8CString("NoChrome/0.10 (JavaScriptCore)");
        JSValueRef vStr = JSValueMakeString(ctx, v);
        JSObjectSetProperty(ctx, navigator, k, vStr, kJSPropertyAttributeNone, nullptr);
        JSStringRelease(v);
        JSStringRelease(k);
    }
    JSStringRef navName = JSStringCreateWithUTF8CString("navigator");
    JSObjectSetProperty(ctx, global, navName, navigator, kJSPropertyAttributeNone, nullptr);
    JSStringRelease(navName);

    // Event / CustomEvent constructors. Native factories are installed under
    // hidden names, then real JS constructor functions (typeof "function" AND
    // `new`-able) delegate to them; `new` adopts the returned backed object.
    {
        jscEnsureDomClasses();
        JSStringRef mk = JSStringCreateWithUTF8CString("__nochromeMakeEvent");
        JSObjectSetProperty(ctx, global, mk, JSObjectMakeFunctionWithCallback(ctx, mk, jscMakeEventNative), kJSPropertyAttributeDontEnum, nullptr);
        JSStringRelease(mk);
        JSStringRef mkc = JSStringCreateWithUTF8CString("__nochromeMakeCustomEvent");
        JSObjectSetProperty(ctx, global, mkc, JSObjectMakeFunctionWithCallback(ctx, mkc, jscMakeCustomEventNative), kJSPropertyAttributeDontEnum, nullptr);
        JSStringRelease(mkc);

        static const char kEventShim[] =
            "function Event(t,o){return __nochromeMakeEvent(t,o);}"
            "function CustomEvent(t,o){return __nochromeMakeCustomEvent(t,o);}";
        JSStringRef s = JSStringCreateWithUTF8CString(kEventShim);
        JSEvaluateScript(ctx, s, nullptr, nullptr, 1, nullptr);
        JSStringRelease(s);
    }

    // XMLHttpRequest constructor. Hidden native factory + a real JS constructor
    // function (typeof "function" AND `new`-able); `new` adopts the backed object.
    {
        jscEnsureDomClasses();
        JSStringRef mk = JSStringCreateWithUTF8CString("__nochromeMakeXhr");
        JSObjectSetProperty(ctx, global, mk, JSObjectMakeFunctionWithCallback(ctx, mk, jscMakeXhrNative), kJSPropertyAttributeDontEnum, nullptr);
        JSStringRelease(mk);

        static const char kXhrShim[] =
            "function XMLHttpRequest(){return __nochromeMakeXhr();}";
        JSStringRef s = JSStringCreateWithUTF8CString(kXhrShim);
        JSEvaluateScript(ctx, s, nullptr, nullptr, 1, nullptr);
        JSStringRelease(s);
    }

    // Image(): minimal HTMLImageElement constructor. Sites use `new Image()`
    // for preloading and tracking pixels (img.src = url). Delegates to
    // createElement so it behaves like a real detached <img> node.
    {
        static const char kImageShim[] =
            "function Image(w,h){var e=document.createElement('img');"
            "if(w!=null)e.setAttribute('width',w);"
            "if(h!=null)e.setAttribute('height',h);return e;}";
        JSStringRef s = JSStringCreateWithUTF8CString(kImageShim);
        JSEvaluateScript(ctx, s, nullptr, nullptr, 1, nullptr);
        JSStringRelease(s);
    }
}

static std::string jsReadDocumentTitle(JSContextRef ctx) {
    JSObjectRef global = JSContextGetGlobalObject(ctx);

    JSStringRef docName = JSStringCreateWithUTF8CString("document");
    JSValueRef docVal = JSObjectGetProperty(ctx, global, docName, nullptr);
    JSStringRelease(docName);
    if (!docVal || !JSValueIsObject(ctx, docVal)) return "";

    JSObjectRef docObj = (JSObjectRef)docVal;

    JSStringRef titleName = JSStringCreateWithUTF8CString("title");
    JSValueRef titleVal = JSObjectGetProperty(ctx, docObj, titleName, nullptr);
    JSStringRelease(titleName);

    if (!titleVal) return "";
    return jsToUtf8(ctx, titleVal);
}

static std::string runJavaScriptForHtml(JsEngine& js,
                                       const std::string& html,
                                       const Url& baseUrl,
                                       const std::string& urlString) {
    js.host.currentUrl = urlString;
    js.host.baseUrl = baseUrl;
    js.host.domDirty = false;

    jsResetContext(js);

    // Build the real DOM tree (the source of truth for this page; the renderer
    // walks it directly).
    js.host.dom = domParse(stripNoscriptBlocks(html));

    std::string initialTitle = extractTitleFromHtmlSimple(html);
    jsSetupPageGlobals(js.ctx, urlString, initialTitle);

    auto scripts = extractScriptsSimple(html, baseUrl);

    int externalCount = 0;
    for (auto& sc : scripts) {
        if (sc.isModule) {
            // Best-effort: treat module scripts like normal scripts.
            // Many modern sites use type="module". If the source uses
            // real module syntax (import/export), JavaScriptCore will throw
            // a SyntaxError and we will ignore it.
        }
        std::string code = sc.code;
        std::string filename = "<inline>";

        if (!sc.srcAbs.empty()) {
            if (externalCount >= 16) break;
            code = fetchSubresourceText(sc.srcAbs);
            filename = sc.srcAbs;
            externalCount++;
            if (looksLikeHtmlNotJs(code)) continue;
        }

        if (trimCopy(code).empty()) continue;

        JSStringRef scriptStr = JSStringCreateWithUTF8CString(code.c_str());
        JSStringRef sourceUrl = JSStringCreateWithUTF8CString(filename.c_str());

        JSValueRef exc = nullptr;
        (void)JSEvaluateScript(js.ctx, scriptStr, nullptr, sourceUrl, 1, &exc);

        JSStringRelease(sourceUrl);
        JSStringRelease(scriptStr);

        if (exc) jsDumpException(js.ctx, exc);
    }

    return jsReadDocumentTitle(js.ctx);
}



static void jsPumpTimers(JsEngine& js) {
    if (!js.ctx) return;
    g_jsHost = &js.host;

    double now = jscNowMs();
    // Collect due timers; re-arm intervals (keep them, fn stays protected), drop
    // one-shots. Copy the fire list so a callback that mutates timers can't
    // invalidate iteration.
    std::vector<JsHost::TimerItem> due;
    for (auto it = js.host.timers.begin(); it != js.host.timers.end(); ) {
        if (it->dueMs <= now) {
            due.push_back(*it);
            if (it->isInterval) {
                it->dueMs = now + it->intervalMs;
                ++it;
            } else {
                if (it->fn) JSValueUnprotect(js.ctx, it->fn);
                it = js.host.timers.erase(it);
            }
        } else {
            ++it;
        }
    }

    for (auto& t : due) {
        JSValueRef exc = nullptr;

        if (t.isCode) {
            JSStringRef script = JSStringCreateWithUTF8CString(t.code.c_str());
            (void)JSEvaluateScript(js.ctx, script, nullptr, nullptr, 1, &exc);
            JSStringRelease(script);
        } else if (t.fn) {
            if (t.isRaf) {
                JSValueRef arg = JSValueMakeNumber(js.ctx, now);
                JSObjectCallAsFunction(js.ctx, t.fn, nullptr, 1, &arg, &exc);
            } else {
                JSObjectCallAsFunction(js.ctx, t.fn, nullptr, 0, nullptr, &exc);
            }
        }

        if (exc) {
            std::cerr << "[JS Exception] " << jsToUtf8(js.ctx, exc) << "\n";
        }
    }
}
#else
// -------------------- JavaScript (QuickJS) --------------------


struct JsHost {
    SDL_Window* window = nullptr;
    std::string currentUrl;

    // Set whenever JS mutates the DOM tree; triggers a re-render of the page.
    bool domDirty = false;

    // setTimeout/clearTimeout queue (no threads; pumped from the UI loop).
    struct TimerItem {
        int id = 0;
        double dueMs = 0.0;
        JSValue fn = JS_UNDEFINED; // duplicated; freed when the timer fires or is cleared
        bool isCode = false;
        std::string code;
        bool isInterval = false;   // setInterval: re-arm after firing
        double intervalMs = 0.0;
        bool isRaf = false;        // requestAnimationFrame: pass a timestamp arg
    };
    int nextTimerId = 1;
    std::vector<TimerItem> timers;

    // Event listeners keyed by scope+type, e.g. "window:click", "document:keydown", "el:myid:click".
    std::unordered_map<std::string, std::vector<JSValue>> listeners; // duplicated

    // Real DOM tree (source of truth); the renderer walks it directly.
    Url baseUrl;
    DomTree dom;

    std::chrono::steady_clock::time_point perfStart = std::chrono::steady_clock::now();
};

struct JsEngine {
    JSRuntime* rt = nullptr;
    JSContext* ctx = nullptr;
    JsHost host;
};

// QuickJS class ids for our minimal DOM wrappers (registered once for the runtime).
static JSClassID g_qjsElementClassId = 0;
static JSClassID g_qjsStyleClassId = 0;
static JSClassID g_qjsEventClassId = 0;

struct QjsElementPriv {
    int nodeId = -1; // index into JsHost::dom
};

struct QjsStylePriv {
    int nodeId = -1; // element this style belongs to
};

// Backing store for a DOM Event object. Standard fields live here; ad-hoc
// properties (clientX, key, ...) are stored as ordinary own properties on the
// JS instance.
struct QjsEventPriv {
    std::string type;
    bool bubbles = false;
    bool cancelable = false;
    bool defaultPrevented = false;
    bool propagationStopped = false;
    bool immediateStopped = false;
    int eventPhase = 0;
    int targetNodeId = -1;
    int currentTargetNodeId = -1;
};

static JSClassID g_qjsXhrClassId = 0;

// Backing store for an XMLHttpRequest object. on* handlers (onload, onerror,
// onreadystatechange) are NOT stored here; they are ordinary own JS properties
// read back off the object during send().
struct QjsXhrPriv {
    std::string method;
    std::string url;
    int readyState = 0;
    int status = 0;
    std::string statusText;
    std::string responseText;
    std::string responseType;
    std::string responseHeaders; // raw header block from the last send()
    bool sent = false;
};

static JsHost* qjsHost(JSContext* ctx) {
    return (JsHost*)JS_GetContextOpaque(ctx);
}

static std::string jsToUtf8(JSContext* ctx, JSValueConst v) {
    const char* s = JS_ToCString(ctx, v);
    if (!s) return "";
    std::string out(s);
    JS_FreeCString(ctx, s);
    return out;
}

// -------------------- best-effort HTML mutation helpers --------------------

static std::string stripNoscriptBlocks(const std::string& html) {
    std::string lower = toLowerCopy(html);
    std::string out;
    out.reserve(html.size());

    size_t pos = 0;
    while (true) {
        size_t ns = lower.find("<noscript", pos);
        if (ns == std::string::npos) {
            out.append(html, pos, std::string::npos);
            break;
        }
        out.append(html, pos, ns - pos);

        size_t gt = lower.find('>', ns);
        if (gt == std::string::npos) break;

        size_t end = lower.find("</noscript>", gt);
        if (end == std::string::npos) break;

        pos = end + std::string("</noscript>").size();
    }

    return out;
}

static void jsDumpException(JSContext* ctx) {
    JSValue exc = JS_GetException(ctx);

    const char* msg = JS_ToCString(ctx, exc);
    if (msg) {
        std::cerr << "[JS Exception] " << msg << "\n";
        JS_FreeCString(ctx, msg);
    }

    JSValue stack = JS_GetPropertyStr(ctx, exc, "stack");
    if (JS_IsString(stack)) {
        const char* st = JS_ToCString(ctx, stack);
        if (st) {
            std::cerr << st << "\n";
            JS_FreeCString(ctx, st);
        }
    }

    JS_FreeValue(ctx, stack);
    JS_FreeValue(ctx, exc);
}

static JSValue jsConsoleLog(JSContext* ctx, JSValueConst /*this_val*/, int argc, JSValueConst* argv) {
    for (int i = 0; i < argc; i++) {
        const char* s = JS_ToCString(ctx, argv[i]);
        if (s) {
            std::cout << s;
            JS_FreeCString(ctx, s);
        } else {
            std::cout << "[unprintable]";
        }
        if (i + 1 < argc) std::cout << " ";
    }
    std::cout << std::endl;
    return JS_UNDEFINED;
}

static JSValue jsNoop(JSContext* /*ctx*/, JSValueConst /*this_val*/, int /*argc*/, JSValueConst* /*argv*/) {
    return JS_UNDEFINED;
}

static JSValue jsReturnNull(JSContext* /*ctx*/, JSValueConst /*this_val*/, int /*argc*/, JSValueConst* /*argv*/) {
    return JS_NULL;
}

static double qjsNowMs(JsHost* host) {
    if (!host) return 0.0;
    auto now = std::chrono::steady_clock::now();
    return std::chrono::duration<double, std::milli>(now - host->perfStart).count();
}

static JSValue jsSetTimeout(JSContext* ctx, JSValueConst /*this_val*/, int argc, JSValueConst* argv) {
    JsHost* host = qjsHost(ctx);
    if (!host || argc < 1) return JS_NewInt32(ctx, 0);

    double delay = 0.0;
    if (argc >= 2) JS_ToFloat64(ctx, &delay, argv[1]);
    if (delay < 0.0) delay = 0.0;

    JsHost::TimerItem item;
    int timerId = host->nextTimerId++;
    item.id = timerId;
    item.dueMs = qjsNowMs(host) + delay;

    if (JS_IsString(argv[0])) {
        item.isCode = true;
        item.code = jsToUtf8(ctx, argv[0]);
    } else if (JS_IsFunction(ctx, argv[0])) {
        item.fn = JS_DupValue(ctx, argv[0]);
    } else {
        return JS_NewInt32(ctx, 0);
    }

    host->timers.push_back(std::move(item));
    return JS_NewInt32(ctx, timerId);
}

static JSValue jsSetInterval(JSContext* ctx, JSValueConst /*this_val*/, int argc, JSValueConst* argv) {
    JsHost* host = qjsHost(ctx);
    if (!host || argc < 1) return JS_NewInt32(ctx, 0);

    double delay = 0.0;
    if (argc >= 2) JS_ToFloat64(ctx, &delay, argv[1]);
    if (delay < 4.0) delay = 4.0; // clamp like browsers (avoid a 0ms busy-loop)

    JsHost::TimerItem item;
    int timerId = host->nextTimerId++;
    item.id = timerId;
    item.dueMs = qjsNowMs(host) + delay;
    item.isInterval = true;
    item.intervalMs = delay;

    if (JS_IsString(argv[0])) {
        item.isCode = true;
        item.code = jsToUtf8(ctx, argv[0]);
    } else if (JS_IsFunction(ctx, argv[0])) {
        item.fn = JS_DupValue(ctx, argv[0]);
    } else {
        return JS_NewInt32(ctx, 0);
    }

    host->timers.push_back(std::move(item));
    return JS_NewInt32(ctx, timerId);
}

static JSValue jsRequestAnimationFrame(JSContext* ctx, JSValueConst /*this_val*/, int argc, JSValueConst* argv) {
    JsHost* host = qjsHost(ctx);
    if (!host || argc < 1 || !JS_IsFunction(ctx, argv[0])) return JS_NewInt32(ctx, 0);

    JsHost::TimerItem item;
    int timerId = host->nextTimerId++;
    item.id = timerId;
    item.dueMs = qjsNowMs(host) + 16.0; // ~next frame
    item.isRaf = true;
    item.fn = JS_DupValue(ctx, argv[0]);

    host->timers.push_back(std::move(item));
    return JS_NewInt32(ctx, timerId);
}

static JSValue jsClearTimeout(JSContext* ctx, JSValueConst /*this_val*/, int argc, JSValueConst* argv) {
    JsHost* host = qjsHost(ctx);
    if (!host || argc < 1) return JS_UNDEFINED;

    int32_t id = 0;
    JS_ToInt32(ctx, &id, argv[0]);
    for (auto it = host->timers.begin(); it != host->timers.end(); ++it) {
        if (it->id == id) {
            if (!JS_IsUndefined(it->fn)) JS_FreeValue(ctx, it->fn);
            host->timers.erase(it);
            break;
        }
    }
    return JS_UNDEFINED;
}

static JSValue jsPerformanceNow(JSContext* ctx, JSValueConst /*this_val*/, int /*argc*/, JSValueConst* /*argv*/) {
    return JS_NewFloat64(ctx, qjsNowMs(qjsHost(ctx)));
}

// -------------------- fetch (very small synchronous subset) --------------------

static JSValue qjsPromiseResolve(JSContext* ctx, JSValue value) {
    JSValue global = JS_GetGlobalObject(ctx);
    JSValue promiseCtor = JS_GetPropertyStr(ctx, global, "Promise");
    JSValue resolveFn = JS_GetPropertyStr(ctx, promiseCtor, "resolve");

    JSValue result = value;
    if (JS_IsFunction(ctx, resolveFn)) {
        JSValueConst args[1] = { value };
        result = JS_Call(ctx, resolveFn, promiseCtor, 1, args);
        JS_FreeValue(ctx, value);
    }

    JS_FreeValue(ctx, resolveFn);
    JS_FreeValue(ctx, promiseCtor);
    JS_FreeValue(ctx, global);
    return result;
}

static JSValue jsResponseText(JSContext* ctx, JSValueConst this_val, int /*argc*/, JSValueConst* /*argv*/) {
    JSValue body = JS_GetPropertyStr(ctx, this_val, "_bodyText");
    return qjsPromiseResolve(ctx, body);
}

static JSValue jsResponseJson(JSContext* ctx, JSValueConst this_val, int /*argc*/, JSValueConst* /*argv*/) {
    JSValue body = JS_GetPropertyStr(ctx, this_val, "_bodyText");
    std::string text = jsToUtf8(ctx, body);
    JS_FreeValue(ctx, body);
    JSValue parsed = JS_ParseJSON(ctx, text.c_str(), text.size(), "<fetch>");
    if (JS_IsException(parsed)) {
        jsDumpException(ctx);
        parsed = JS_NULL;
    }
    return qjsPromiseResolve(ctx, parsed);
}

static JSValue jsFetch(JSContext* ctx, JSValueConst /*this_val*/, int argc, JSValueConst* argv) {
    JsHost* host = qjsHost(ctx);
    if (!host || argc < 1) return JS_UNDEFINED;

    std::string url = jsToUtf8(ctx, argv[0]);
    std::string abs = resolveHref(host->baseUrl, url);
    if (abs.empty()) abs = url;

    std::string body = fetchSubresourceText(abs);

    JSValue resp = JS_NewObject(ctx);
    JS_SetPropertyStr(ctx, resp, "ok", JS_NewBool(ctx, 1));
    JS_SetPropertyStr(ctx, resp, "status", JS_NewInt32(ctx, 200));
    JS_SetPropertyStr(ctx, resp, "url", JS_NewString(ctx, abs.c_str()));
    JS_SetPropertyStr(ctx, resp, "_bodyText", JS_NewString(ctx, body.c_str()));
    JS_SetPropertyStr(ctx, resp, "text", JS_NewCFunction(ctx, jsResponseText, "text", 0));
    JS_SetPropertyStr(ctx, resp, "json", JS_NewCFunction(ctx, jsResponseJson, "json", 0));

    return qjsPromiseResolve(ctx, resp);
}

// -------------------- DOM element / style wrappers --------------------

static void qjsElementFinalizer(JSRuntime* /*rt*/, JSValue val) {
    auto* p = (QjsElementPriv*)JS_GetOpaque(val, g_qjsElementClassId);
    delete p;
}

static void qjsStyleFinalizer(JSRuntime* /*rt*/, JSValue val) {
    auto* p = (QjsStylePriv*)JS_GetOpaque(val, g_qjsStyleClassId);
    delete p;
}

static void qjsEventFinalizer(JSRuntime* /*rt*/, JSValue val) {
    auto* p = (QjsEventPriv*)JS_GetOpaque(val, g_qjsEventClassId);
    delete p;
}

static void qjsXhrFinalizer(JSRuntime* /*rt*/, JSValue val) {
    auto* p = (QjsXhrPriv*)JS_GetOpaque(val, g_qjsXhrClassId);
    delete p;
}

static DomNode* qjsElNode(JSContext* ctx, JSValueConst this_val) {
    JsHost* host = qjsHost(ctx);
    auto* p = (QjsElementPriv*)JS_GetOpaque(this_val, g_qjsElementClassId);
    if (!host || !p) return nullptr;
    return host->dom.get(p->nodeId);
}

static int qjsElNodeId(JSValueConst this_val) {
    auto* p = (QjsElementPriv*)JS_GetOpaque(this_val, g_qjsElementClassId);
    return p ? p->nodeId : -1;
}

static JSValue qjsMakeElement(JSContext* ctx, int nodeId) {
    JSValue obj = JS_NewObjectClass(ctx, g_qjsElementClassId);
    if (JS_IsException(obj)) return obj;
    auto* p = new QjsElementPriv();
    p->nodeId = nodeId;
    JS_SetOpaque(obj, p);
    return obj;
}

static JSValue qjsElGetId(JSContext* ctx, JSValueConst this_val, int, JSValueConst*) {
    DomNode* n = qjsElNode(ctx, this_val);
    return n ? JS_NewString(ctx, domGetAttr(*n, "id").c_str()) : JS_UNDEFINED;
}

static JSValue qjsElSetId(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
    JsHost* host = qjsHost(ctx);
    DomNode* n = qjsElNode(ctx, this_val);
    if (n && argc > 0) {
        domSetAttr(*n, "id", jsToUtf8(ctx, argv[0]));
        if (host) host->domDirty = true;
    }
    return JS_UNDEFINED;
}

static JSValue qjsElGetTagName(JSContext* ctx, JSValueConst this_val, int, JSValueConst*) {
    DomNode* n = qjsElNode(ctx, this_val);
    std::string tn = (n && !n->tag.empty()) ? toUpperCopy(n->tag) : "DIV";
    return JS_NewString(ctx, tn.c_str());
}

static JSValue qjsElGetText(JSContext* ctx, JSValueConst this_val, int, JSValueConst*) {
    JsHost* host = qjsHost(ctx);
    int nid = qjsElNodeId(this_val);
    if (!host || nid < 0) return JS_UNDEFINED;
    return JS_NewString(ctx, domTextContent(host->dom, nid).c_str());
}

static JSValue qjsElSetText(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
    JsHost* host = qjsHost(ctx);
    int nid = qjsElNodeId(this_val);
    if (!host || nid < 0) return JS_UNDEFINED;
    domSetTextContent(host->dom, nid, (argc > 0) ? jsToUtf8(ctx, argv[0]) : "");
    host->domDirty = true;
    return JS_UNDEFINED;
}

static JSValue qjsElGetInnerHtml(JSContext* ctx, JSValueConst this_val, int, JSValueConst*) {
    JsHost* host = qjsHost(ctx);
    int nid = qjsElNodeId(this_val);
    if (!host || nid < 0) return JS_UNDEFINED;
    return JS_NewString(ctx, domSerializeChildren(host->dom, nid).c_str());
}

static JSValue qjsElSetInnerHtml(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
    JsHost* host = qjsHost(ctx);
    int nid = qjsElNodeId(this_val);
    if (!host || nid < 0) return JS_UNDEFINED;
    domSetInnerHtml(host->dom, nid, (argc > 0) ? jsToUtf8(ctx, argv[0]) : "");
    host->domDirty = true;
    return JS_UNDEFINED;
}

static JSValue qjsElGetParent(JSContext* ctx, JSValueConst this_val, int, JSValueConst*) {
    JsHost* host = qjsHost(ctx);
    int nid = qjsElNodeId(this_val);
    if (!host) return JS_NULL;
    DomNode* n = host->dom.get(nid);
    if (!n || n->parent < 0 || n->parent == host->dom.root) return JS_NULL;
    return qjsMakeElement(ctx, n->parent);
}

static JSValue qjsElGetStyle(JSContext* ctx, JSValueConst this_val, int, JSValueConst*) {
    int nid = qjsElNodeId(this_val);
    if (nid < 0) return JS_UNDEFINED;
    JSValue s = JS_NewObjectClass(ctx, g_qjsStyleClassId);
    if (JS_IsException(s)) return s;
    auto* sp = new QjsStylePriv();
    sp->nodeId = nid;
    JS_SetOpaque(s, sp);
    return s;
}

static JSValue qjsElAttrGet(JSContext* ctx, JSValueConst this_val, int, JSValueConst*, int, JSValue* data) {
    DomNode* n = qjsElNode(ctx, this_val);
    if (!n) return JS_UNDEFINED;
    return JS_NewString(ctx, domGetAttr(*n, jsToUtf8(ctx, data[0])).c_str());
}

static JSValue qjsElAttrSet(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv, int, JSValue* data) {
    JsHost* host = qjsHost(ctx);
    DomNode* n = qjsElNode(ctx, this_val);
    if (!n) return JS_UNDEFINED;
    domSetAttr(*n, jsToUtf8(ctx, data[0]), (argc > 0) ? jsToUtf8(ctx, argv[0]) : "");
    if (host) host->domDirty = true;
    return JS_UNDEFINED;
}

// -------------------- Event object (QuickJS) --------------------

static QjsEventPriv* qjsEvtPriv(JSValueConst this_val) {
    return (QjsEventPriv*)JS_GetOpaque(this_val, g_qjsEventClassId);
}

static JSValue qjsEvtGetType(JSContext* ctx, JSValueConst this_val, int, JSValueConst*) {
    QjsEventPriv* p = qjsEvtPriv(this_val);
    return p ? JS_NewString(ctx, p->type.c_str()) : JS_UNDEFINED;
}
static JSValue qjsEvtGetBubbles(JSContext* ctx, JSValueConst this_val, int, JSValueConst*) {
    QjsEventPriv* p = qjsEvtPriv(this_val);
    return JS_NewBool(ctx, p && p->bubbles);
}
static JSValue qjsEvtGetCancelable(JSContext* ctx, JSValueConst this_val, int, JSValueConst*) {
    QjsEventPriv* p = qjsEvtPriv(this_val);
    return JS_NewBool(ctx, p && p->cancelable);
}
static JSValue qjsEvtGetDefaultPrevented(JSContext* ctx, JSValueConst this_val, int, JSValueConst*) {
    QjsEventPriv* p = qjsEvtPriv(this_val);
    return JS_NewBool(ctx, p && p->defaultPrevented);
}
static JSValue qjsEvtGetEventPhase(JSContext* ctx, JSValueConst this_val, int, JSValueConst*) {
    QjsEventPriv* p = qjsEvtPriv(this_val);
    return JS_NewInt32(ctx, p ? p->eventPhase : 0);
}
static JSValue qjsEvtGetTarget(JSContext* ctx, JSValueConst this_val, int, JSValueConst*) {
    QjsEventPriv* p = qjsEvtPriv(this_val);
    if (!p || p->targetNodeId < 0) return JS_NULL;
    return qjsMakeElement(ctx, p->targetNodeId);
}
static JSValue qjsEvtGetCurrentTarget(JSContext* ctx, JSValueConst this_val, int, JSValueConst*) {
    QjsEventPriv* p = qjsEvtPriv(this_val);
    if (!p || p->currentTargetNodeId < 0) return JS_NULL;
    return qjsMakeElement(ctx, p->currentTargetNodeId);
}
static JSValue qjsEvtPreventDefault(JSContext* ctx, JSValueConst this_val, int, JSValueConst*) {
    QjsEventPriv* p = qjsEvtPriv(this_val);
    if (p && p->cancelable) p->defaultPrevented = true;
    return JS_UNDEFINED;
}
static JSValue qjsEvtStopPropagation(JSContext* ctx, JSValueConst this_val, int, JSValueConst*) {
    QjsEventPriv* p = qjsEvtPriv(this_val);
    if (p) p->propagationStopped = true;
    return JS_UNDEFINED;
}
static JSValue qjsEvtStopImmediatePropagation(JSContext* ctx, JSValueConst this_val, int, JSValueConst*) {
    QjsEventPriv* p = qjsEvtPriv(this_val);
    if (p) { p->propagationStopped = true; p->immediateStopped = true; }
    return JS_UNDEFINED;
}

// Build a backed Event instance (no constructor invocation).
static JSValue qjsMakeEvent(JSContext* ctx, const std::string& type, bool bubbles, bool cancelable) {
    JSValue obj = JS_NewObjectClass(ctx, g_qjsEventClassId);
    if (JS_IsException(obj)) return obj;
    auto* p = new QjsEventPriv();
    p->type = type;
    p->bubbles = bubbles;
    p->cancelable = cancelable;
    JS_SetOpaque(obj, p);
    return obj;
}

// Read .bubbles/.cancelable/.detail off an options object (any may be missing).
static void qjsReadEventOptions(JSContext* ctx, JSValueConst opts, bool& bubbles, bool& cancelable) {
    if (!JS_IsObject(opts)) return;
    JSValue b = JS_GetPropertyStr(ctx, opts, "bubbles");
    if (!JS_IsUndefined(b)) bubbles = JS_ToBool(ctx, b);
    JS_FreeValue(ctx, b);
    JSValue c = JS_GetPropertyStr(ctx, opts, "cancelable");
    if (!JS_IsUndefined(c)) cancelable = JS_ToBool(ctx, c);
    JS_FreeValue(ctx, c);
}

// new Event(type, {bubbles, cancelable})
static JSValue qjsEventCtor(JSContext* ctx, JSValueConst /*new_target*/, int argc, JSValueConst* argv) {
    std::string type = (argc > 0) ? jsToUtf8(ctx, argv[0]) : "";
    bool bubbles = false, cancelable = false;
    if (argc > 1) qjsReadEventOptions(ctx, argv[1], bubbles, cancelable);
    return qjsMakeEvent(ctx, type, bubbles, cancelable);
}

// new CustomEvent(type, {bubbles, cancelable, detail})
static JSValue qjsCustomEventCtor(JSContext* ctx, JSValueConst /*new_target*/, int argc, JSValueConst* argv) {
    std::string type = (argc > 0) ? jsToUtf8(ctx, argv[0]) : "";
    bool bubbles = false, cancelable = false;
    if (argc > 1) qjsReadEventOptions(ctx, argv[1], bubbles, cancelable);
    JSValue obj = qjsMakeEvent(ctx, type, bubbles, cancelable);
    if (JS_IsException(obj)) return obj;
    JSValue detail = JS_UNDEFINED;
    if (argc > 1 && JS_IsObject(argv[1])) detail = JS_GetPropertyStr(ctx, argv[1], "detail");
    // detail is an ordinary own property (default null when absent).
    JS_SetPropertyStr(ctx, obj, "detail", JS_IsUndefined(detail) ? JS_NULL : detail);
    return obj;
}

// -------------------- XMLHttpRequest object (QuickJS) --------------------

static QjsXhrPriv* qjsXhrPriv(JSValueConst this_val) {
    return (QjsXhrPriv*)JS_GetOpaque(this_val, g_qjsXhrClassId);
}

// Read-only property getters.
static JSValue qjsXhrGetReadyState(JSContext* ctx, JSValueConst this_val, int, JSValueConst*) {
    QjsXhrPriv* p = qjsXhrPriv(this_val);
    return JS_NewInt32(ctx, p ? p->readyState : 0);
}
static JSValue qjsXhrGetStatus(JSContext* ctx, JSValueConst this_val, int, JSValueConst*) {
    QjsXhrPriv* p = qjsXhrPriv(this_val);
    return JS_NewInt32(ctx, p ? p->status : 0);
}
static JSValue qjsXhrGetStatusText(JSContext* ctx, JSValueConst this_val, int, JSValueConst*) {
    QjsXhrPriv* p = qjsXhrPriv(this_val);
    return JS_NewString(ctx, p ? p->statusText.c_str() : "");
}
static JSValue qjsXhrGetResponseText(JSContext* ctx, JSValueConst this_val, int, JSValueConst*) {
    QjsXhrPriv* p = qjsXhrPriv(this_val);
    return JS_NewString(ctx, p ? p->responseText.c_str() : "");
}
static JSValue qjsXhrGetResponse(JSContext* ctx, JSValueConst this_val, int, JSValueConst*) {
    QjsXhrPriv* p = qjsXhrPriv(this_val);
    return JS_NewString(ctx, p ? p->responseText.c_str() : ""); // text-equivalent
}
static JSValue qjsXhrGetResponseType(JSContext* ctx, JSValueConst this_val, int, JSValueConst*) {
    QjsXhrPriv* p = qjsXhrPriv(this_val);
    return JS_NewString(ctx, p ? p->responseType.c_str() : "");
}
static JSValue qjsXhrSetResponseType(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
    QjsXhrPriv* p = qjsXhrPriv(this_val);
    if (p && argc > 0) p->responseType = jsToUtf8(ctx, argv[0]);
    return JS_UNDEFINED;
}

// open(method, url, async?)
static JSValue qjsXhrOpen(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
    QjsXhrPriv* p = qjsXhrPriv(this_val);
    if (!p) return JS_UNDEFINED;
    JsHost* host = qjsHost(ctx);
    std::string method = (argc > 0) ? jsToUtf8(ctx, argv[0]) : "GET";
    p->method = toUpperCopy(method);
    std::string url = (argc > 1) ? jsToUtf8(ctx, argv[1]) : "";
    std::string abs = host ? resolveHref(host->baseUrl, url) : url;
    if (abs.empty()) abs = url;
    p->url = abs;
    p->readyState = 1;
    p->sent = false;
    return JS_UNDEFINED;
}

// setRequestHeader(name, value): accepted and ignored (no-op).
static JSValue qjsXhrSetRequestHeader(JSContext* /*ctx*/, JSValueConst /*this_val*/, int /*argc*/, JSValueConst* /*argv*/) {
    return JS_UNDEFINED;
}

// Read an on* handler back off the XHR object and, if callable, invoke it with
// the XHR as `this` and no args. on* handlers are ordinary own properties.
static void qjsXhrFireHandler(JSContext* ctx, JSValueConst xhr, const char* name) {
    JSValue h = JS_GetPropertyStr(ctx, xhr, name);
    if (JS_IsFunction(ctx, h)) {
        JSValue ret = JS_Call(ctx, h, xhr, 0, nullptr);
        if (JS_IsException(ret)) jsDumpException(ctx);
        JS_FreeValue(ctx, ret);
    }
    JS_FreeValue(ctx, h);
}

// send(body?): perform the request synchronously NOW, then fire callbacks.
// The underlying transport is GET-only; for non-GET methods we still do a GET.
static JSValue qjsXhrSend(JSContext* ctx, JSValueConst this_val, int /*argc*/, JSValueConst* /*argv*/) {
    QjsXhrPriv* p = qjsXhrPriv(this_val);
    if (!p) return JS_UNDEFINED;
    p->sent = true;

    std::string headers;
    Url finalU;
    std::string body;
    try {
        body = httpFetchProcessed(parseUrl(p->url), finalU, &headers);
    } catch (...) {
        body = "";
    }

    p->responseText = body;
    p->responseHeaders = headers;
    int code = parseStatusCode(headers);
    if (code == 0 && !body.empty()) code = 200; // body but no parseable status
    p->status = code;
    if (code >= 200 && code < 300) p->statusText = "OK";
    else p->statusText = "";
    p->readyState = 4;

    // Fire callbacks in order: onreadystatechange (sees readyState===4), then
    // onload for 2xx else onerror.
    qjsXhrFireHandler(ctx, this_val, "onreadystatechange");
    if (code >= 200 && code < 300) qjsXhrFireHandler(ctx, this_val, "onload");
    else qjsXhrFireHandler(ctx, this_val, "onerror");

    return JS_UNDEFINED;
}

// getAllResponseHeaders(): raw header block stored during send().
static JSValue qjsXhrGetAllResponseHeaders(JSContext* ctx, JSValueConst this_val, int, JSValueConst*) {
    QjsXhrPriv* p = qjsXhrPriv(this_val);
    return JS_NewString(ctx, p ? p->responseHeaders.c_str() : "");
}

// getResponseHeader(name): look up a single header in the stored block.
static JSValue qjsXhrGetResponseHeader(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
    QjsXhrPriv* p = qjsXhrPriv(this_val);
    if (!p || argc < 1) return JS_NULL;
    std::string val = headerValueCI(p->responseHeaders, jsToUtf8(ctx, argv[0]));
    return val.empty() ? JS_NULL : JS_NewString(ctx, val.c_str());
}

// abort(): no-op (reset readyState).
static JSValue qjsXhrAbort(JSContext* /*ctx*/, JSValueConst this_val, int, JSValueConst*) {
    if (QjsXhrPriv* p = qjsXhrPriv(this_val)) p->readyState = 0;
    return JS_UNDEFINED;
}

// new XMLHttpRequest()
static JSValue qjsXhrCtor(JSContext* ctx, JSValueConst /*new_target*/, int /*argc*/, JSValueConst* /*argv*/) {
    JSValue obj = JS_NewObjectClass(ctx, g_qjsXhrClassId);
    if (JS_IsException(obj)) return obj;
    JS_SetOpaque(obj, new QjsXhrPriv());
    return obj;
}

// Forward declarations for element methods used while building the prototype.
static JSValue qjsElAddEventListener(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv);
static JSValue qjsElRemoveEventListener(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv);
static JSValue qjsElDispatchEvent(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv);
static JSValue qjsElAppendChild(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv);
static JSValue qjsElRemoveChild(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv);
static JSValue qjsElSetAttribute(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv);
static JSValue qjsElGetAttribute(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv);
// Batch 1 DOM: traversal / mutation / classList (defined after qjsNodeArray).
static JSValue qjsElInsertBefore(JSContext*, JSValueConst, int, JSValueConst*);
static JSValue qjsElReplaceChild(JSContext*, JSValueConst, int, JSValueConst*);
static JSValue qjsElCloneNode(JSContext*, JSValueConst, int, JSValueConst*);
static JSValue qjsElHasAttribute(JSContext*, JSValueConst, int, JSValueConst*);
static JSValue qjsElRemoveAttribute(JSContext*, JSValueConst, int, JSValueConst*);
static JSValue qjsElGetClassName(JSContext*, JSValueConst, int, JSValueConst*);
static JSValue qjsElSetClassName(JSContext*, JSValueConst, int, JSValueConst*);
static JSValue qjsElGetClassList(JSContext*, JSValueConst, int, JSValueConst*);
static JSValue qjsElGetChildNodes(JSContext*, JSValueConst, int, JSValueConst*);
static JSValue qjsElGetChildren(JSContext*, JSValueConst, int, JSValueConst*);
static JSValue qjsElGetFirstChild(JSContext*, JSValueConst, int, JSValueConst*);
static JSValue qjsElGetLastChild(JSContext*, JSValueConst, int, JSValueConst*);
static JSValue qjsElGetNextSibling(JSContext*, JSValueConst, int, JSValueConst*);
static JSValue qjsElGetPrevSibling(JSContext*, JSValueConst, int, JSValueConst*);

// style.<prop> get/set for a curated set of common CSS properties. The property
// name is carried in CFunctionData so one pair of callbacks serves them all.
static JSValue qjsStylePropGet(JSContext* ctx, JSValueConst this_val, int, JSValueConst*, int, JSValue* data) {
    JsHost* host = qjsHost(ctx);
    auto* p = (QjsStylePriv*)JS_GetOpaque(this_val, g_qjsStyleClassId);
    if (!host || !p) return JS_NewString(ctx, "");
    DomNode* n = host->dom.get(p->nodeId);
    return JS_NewString(ctx, n ? domGetStyleProp(*n, jsToUtf8(ctx, data[0])).c_str() : "");
}
static JSValue qjsStylePropSet(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv, int, JSValue* data) {
    JsHost* host = qjsHost(ctx);
    auto* p = (QjsStylePriv*)JS_GetOpaque(this_val, g_qjsStyleClassId);
    if (host && p) {
        if (DomNode* n = host->dom.get(p->nodeId)) {
            domSetStyleProp(*n, jsToUtf8(ctx, data[0]), (argc > 0) ? jsToUtf8(ctx, argv[0]) : "");
            host->domDirty = true;
        }
    }
    return JS_UNDEFINED;
}
static void qjsDefineStyleProp(JSContext* ctx, JSValueConst proto, const char* jsName) {
    JSValue nameVal = JS_NewString(ctx, jsName);
    JSValueConst data[1] = { nameVal };
    JSValue g = JS_NewCFunctionData(ctx, qjsStylePropGet, 0, 0, 1, data);
    JSValue s = JS_NewCFunctionData(ctx, qjsStylePropSet, 1, 0, 1, data);
    JS_FreeValue(ctx, nameVal);
    JSAtom atom = JS_NewAtom(ctx, jsName);
    JS_DefinePropertyGetSet(ctx, proto, atom, g, s, JS_PROP_CONFIGURABLE | JS_PROP_ENUMERABLE);
    JS_FreeAtom(ctx, atom);
}
static void qjsRegisterDomClasses(JSRuntime* rt) {
    if (g_qjsElementClassId == 0) {
        JS_NewClassID(&g_qjsElementClassId);
        JSClassDef def{};
        def.class_name = "Element";
        def.finalizer = qjsElementFinalizer;
        JS_NewClass(rt, g_qjsElementClassId, &def);
    }
    if (g_qjsStyleClassId == 0) {
        JS_NewClassID(&g_qjsStyleClassId);
        JSClassDef def{};
        def.class_name = "CSSStyleDeclaration";
        def.finalizer = qjsStyleFinalizer;
        JS_NewClass(rt, g_qjsStyleClassId, &def);
    }
    if (g_qjsEventClassId == 0) {
        JS_NewClassID(&g_qjsEventClassId);
        JSClassDef def{};
        def.class_name = "Event";
        def.finalizer = qjsEventFinalizer;
        JS_NewClass(rt, g_qjsEventClassId, &def);
    }
    if (g_qjsXhrClassId == 0) {
        JS_NewClassID(&g_qjsXhrClassId);
        JSClassDef def{};
        def.class_name = "XMLHttpRequest";
        def.finalizer = qjsXhrFinalizer;
        JS_NewClass(rt, g_qjsXhrClassId, &def);
    }
}

static void qjsDefineAccessor(JSContext* ctx, JSValueConst proto, const char* name,
                              JSCFunction* getter, JSCFunction* setter) {
    JSValue g = getter ? JS_NewCFunction(ctx, getter, name, 0) : JS_UNDEFINED;
    JSValue s = setter ? JS_NewCFunction(ctx, setter, name, 1) : JS_UNDEFINED;
    JSAtom atom = JS_NewAtom(ctx, name);
    JS_DefinePropertyGetSet(ctx, proto, atom, g, s, JS_PROP_CONFIGURABLE | JS_PROP_ENUMERABLE);
    JS_FreeAtom(ctx, atom);
}

static void qjsDefineAttrAccessor(JSContext* ctx, JSValueConst proto, const char* name) {
    JSValue nameVal = JS_NewString(ctx, name);
    JSValueConst data[1] = { nameVal };
    JSValue g = JS_NewCFunctionData(ctx, qjsElAttrGet, 0, 0, 1, data);
    JSValue s = JS_NewCFunctionData(ctx, qjsElAttrSet, 1, 0, 1, data);
    JS_FreeValue(ctx, nameVal);
    JSAtom atom = JS_NewAtom(ctx, name);
    JS_DefinePropertyGetSet(ctx, proto, atom, g, s, JS_PROP_CONFIGURABLE | JS_PROP_ENUMERABLE);
    JS_FreeAtom(ctx, atom);
}

// Installs element/style prototypes for the current context. Must run after the
// context is created and before any DOM wrapper objects are made.
static void qjsSetupDomProtos(JSContext* ctx) {
    JSValue elProto = JS_NewObject(ctx);
    JS_SetPropertyStr(ctx, elProto, "addEventListener", JS_NewCFunction(ctx, qjsElAddEventListener, "addEventListener", 2));
    JS_SetPropertyStr(ctx, elProto, "removeEventListener", JS_NewCFunction(ctx, qjsElRemoveEventListener, "removeEventListener", 2));
    JS_SetPropertyStr(ctx, elProto, "dispatchEvent", JS_NewCFunction(ctx, qjsElDispatchEvent, "dispatchEvent", 1));
    JS_SetPropertyStr(ctx, elProto, "appendChild", JS_NewCFunction(ctx, qjsElAppendChild, "appendChild", 1));
    JS_SetPropertyStr(ctx, elProto, "setAttribute", JS_NewCFunction(ctx, qjsElSetAttribute, "setAttribute", 2));
    JS_SetPropertyStr(ctx, elProto, "getAttribute", JS_NewCFunction(ctx, qjsElGetAttribute, "getAttribute", 1));
    JS_SetPropertyStr(ctx, elProto, "removeChild", JS_NewCFunction(ctx, qjsElRemoveChild, "removeChild", 1));
    JS_SetPropertyStr(ctx, elProto, "insertBefore", JS_NewCFunction(ctx, qjsElInsertBefore, "insertBefore", 2));
    JS_SetPropertyStr(ctx, elProto, "replaceChild", JS_NewCFunction(ctx, qjsElReplaceChild, "replaceChild", 2));
    JS_SetPropertyStr(ctx, elProto, "cloneNode", JS_NewCFunction(ctx, qjsElCloneNode, "cloneNode", 1));
    JS_SetPropertyStr(ctx, elProto, "hasAttribute", JS_NewCFunction(ctx, qjsElHasAttribute, "hasAttribute", 1));
    JS_SetPropertyStr(ctx, elProto, "removeAttribute", JS_NewCFunction(ctx, qjsElRemoveAttribute, "removeAttribute", 1));
    qjsDefineAccessor(ctx, elProto, "id", qjsElGetId, qjsElSetId);
    qjsDefineAccessor(ctx, elProto, "className", qjsElGetClassName, qjsElSetClassName);
    qjsDefineAccessor(ctx, elProto, "classList", qjsElGetClassList, nullptr);
    qjsDefineAccessor(ctx, elProto, "childNodes", qjsElGetChildNodes, nullptr);
    qjsDefineAccessor(ctx, elProto, "children", qjsElGetChildren, nullptr);
    qjsDefineAccessor(ctx, elProto, "firstChild", qjsElGetFirstChild, nullptr);
    qjsDefineAccessor(ctx, elProto, "lastChild", qjsElGetLastChild, nullptr);
    qjsDefineAccessor(ctx, elProto, "nextSibling", qjsElGetNextSibling, nullptr);
    qjsDefineAccessor(ctx, elProto, "previousSibling", qjsElGetPrevSibling, nullptr);
    qjsDefineAccessor(ctx, elProto, "tagName", qjsElGetTagName, nullptr);
    qjsDefineAccessor(ctx, elProto, "style", qjsElGetStyle, nullptr);
    qjsDefineAccessor(ctx, elProto, "parentNode", qjsElGetParent, nullptr);
    qjsDefineAccessor(ctx, elProto, "textContent", qjsElGetText, qjsElSetText);
    qjsDefineAccessor(ctx, elProto, "innerText", qjsElGetText, qjsElSetText);
    qjsDefineAccessor(ctx, elProto, "innerHTML", qjsElGetInnerHtml, qjsElSetInnerHtml);
    qjsDefineAttrAccessor(ctx, elProto, "src");
    qjsDefineAttrAccessor(ctx, elProto, "href");
    qjsDefineAttrAccessor(ctx, elProto, "type");
    qjsDefineAttrAccessor(ctx, elProto, "value");
    qjsDefineAttrAccessor(ctx, elProto, "name");
    JS_SetClassProto(ctx, g_qjsElementClassId, elProto);

    JSValue stProto = JS_NewObject(ctx);
    for (const char* pn : kCssProps) qjsDefineStyleProp(ctx, stProto, pn);
    JS_SetClassProto(ctx, g_qjsStyleClassId, stProto);

    JSValue evProto = JS_NewObject(ctx);
    qjsDefineAccessor(ctx, evProto, "type", qjsEvtGetType, nullptr);
    qjsDefineAccessor(ctx, evProto, "bubbles", qjsEvtGetBubbles, nullptr);
    qjsDefineAccessor(ctx, evProto, "cancelable", qjsEvtGetCancelable, nullptr);
    qjsDefineAccessor(ctx, evProto, "defaultPrevented", qjsEvtGetDefaultPrevented, nullptr);
    qjsDefineAccessor(ctx, evProto, "eventPhase", qjsEvtGetEventPhase, nullptr);
    qjsDefineAccessor(ctx, evProto, "target", qjsEvtGetTarget, nullptr);
    qjsDefineAccessor(ctx, evProto, "currentTarget", qjsEvtGetCurrentTarget, nullptr);
    JS_SetPropertyStr(ctx, evProto, "preventDefault", JS_NewCFunction(ctx, qjsEvtPreventDefault, "preventDefault", 0));
    JS_SetPropertyStr(ctx, evProto, "stopPropagation", JS_NewCFunction(ctx, qjsEvtStopPropagation, "stopPropagation", 0));
    JS_SetPropertyStr(ctx, evProto, "stopImmediatePropagation", JS_NewCFunction(ctx, qjsEvtStopImmediatePropagation, "stopImmediatePropagation", 0));
    JS_SetClassProto(ctx, g_qjsEventClassId, evProto);

    JSValue xhrProto = JS_NewObject(ctx);
    qjsDefineAccessor(ctx, xhrProto, "readyState", qjsXhrGetReadyState, nullptr);
    qjsDefineAccessor(ctx, xhrProto, "status", qjsXhrGetStatus, nullptr);
    qjsDefineAccessor(ctx, xhrProto, "statusText", qjsXhrGetStatusText, nullptr);
    qjsDefineAccessor(ctx, xhrProto, "responseText", qjsXhrGetResponseText, nullptr);
    qjsDefineAccessor(ctx, xhrProto, "response", qjsXhrGetResponse, nullptr);
    qjsDefineAccessor(ctx, xhrProto, "responseType", qjsXhrGetResponseType, qjsXhrSetResponseType);
    JS_SetPropertyStr(ctx, xhrProto, "open", JS_NewCFunction(ctx, qjsXhrOpen, "open", 3));
    JS_SetPropertyStr(ctx, xhrProto, "setRequestHeader", JS_NewCFunction(ctx, qjsXhrSetRequestHeader, "setRequestHeader", 2));
    JS_SetPropertyStr(ctx, xhrProto, "send", JS_NewCFunction(ctx, qjsXhrSend, "send", 1));
    JS_SetPropertyStr(ctx, xhrProto, "getAllResponseHeaders", JS_NewCFunction(ctx, qjsXhrGetAllResponseHeaders, "getAllResponseHeaders", 0));
    JS_SetPropertyStr(ctx, xhrProto, "getResponseHeader", JS_NewCFunction(ctx, qjsXhrGetResponseHeader, "getResponseHeader", 1));
    JS_SetPropertyStr(ctx, xhrProto, "abort", JS_NewCFunction(ctx, qjsXhrAbort, "abort", 0));
    JS_SetClassProto(ctx, g_qjsXhrClassId, xhrProto);
}

static void qjsAddListener(JSContext* ctx, const std::string& key, JSValueConst fn) {
    if (JsHost* host = qjsHost(ctx)) {
        host->listeners[key].push_back(JS_DupValue(ctx, fn));
    }
}

// Defined below (after the simple dispatcher); declared here for element methods.
static void qjsRemoveListener(JSContext* ctx, const std::string& key, JSValueConst fn);
static bool qjsDispatchEvent(JSContext* ctx, int targetNodeId, JSValueConst evt,
                             const std::string& type, bool bubbles);

static JSValue qjsElAddEventListener(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
    int nid = qjsElNodeId(this_val);
    if (nid < 0 || argc < 2 || !JS_IsFunction(ctx, argv[1])) return JS_UNDEFINED;
    std::string type = jsToUtf8(ctx, argv[0]);
    qjsAddListener(ctx, "node:" + std::to_string(nid) + ":" + type, argv[1]);
    return JS_UNDEFINED;
}

static JSValue qjsElRemoveEventListener(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
    int nid = qjsElNodeId(this_val);
    if (nid < 0 || argc < 2 || !JS_IsFunction(ctx, argv[1])) return JS_UNDEFINED;
    std::string type = jsToUtf8(ctx, argv[0]);
    qjsRemoveListener(ctx, "node:" + std::to_string(nid) + ":" + type, argv[1]);
    return JS_UNDEFINED;
}

// element.dispatchEvent(evt): dispatch an Event through the bubbling path rooted
// at this element. Returns !defaultPrevented.
static JSValue qjsElDispatchEvent(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
    int nid = qjsElNodeId(this_val);
    if (nid < 0 || argc < 1) return JS_NewBool(ctx, 1);

    std::string type;
    bool bubbles = false;
    QjsEventPriv* ep = qjsEvtPriv(argv[0]);
    if (ep) {
        type = ep->type;
        bubbles = ep->bubbles;
    } else {
        // Best-effort for plain-object "events": read .type, assume non-bubbling.
        JSValue tv = JS_GetPropertyStr(ctx, argv[0], "type");
        type = jsToUtf8(ctx, tv);
        JS_FreeValue(ctx, tv);
    }
    bool prevented = qjsDispatchEvent(ctx, nid, argv[0], type, bubbles);
    return JS_NewBool(ctx, !prevented);
}

static JSValue qjsElAppendChild(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
    JsHost* host = qjsHost(ctx);
    if (!host || argc < 1) return JS_UNDEFINED;

    int parentId = qjsElNodeId(this_val);
    auto* childP = (QjsElementPriv*)JS_GetOpaque(argv[0], g_qjsElementClassId);
    if (parentId < 0 || !childP) return JS_DupValue(ctx, argv[0]);
    int childId = childP->nodeId;

    domAppendChild(host->dom, parentId, childId);
    host->domDirty = true;

    // Appending a <script> element executes it (matches browser behavior).
    if (DomNode* child = host->dom.get(childId)) {
        if (child->tag == "script") {
            std::string src = domGetAttr(*child, "src");
            std::string code;
            if (!src.empty()) {
                std::string abs = resolveHref(host->baseUrl, src);
                if (abs.empty()) abs = src;
                code = fetchSubresourceText(abs);
                if (looksLikeHtmlNotJs(code)) code.clear();
            } else {
                code = domTextContent(host->dom, childId);
            }
            if (!trimCopy(code).empty()) {
                JSValue r = JS_Eval(ctx, code.c_str(), code.size(), "<appended>", JS_EVAL_TYPE_GLOBAL);
                if (JS_IsException(r)) jsDumpException(ctx);
                JS_FreeValue(ctx, r);
            }
        }
    }

    return JS_DupValue(ctx, argv[0]);
}

static JSValue qjsElRemoveChild(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
    JsHost* host = qjsHost(ctx);
    if (!host || argc < 1) return JS_UNDEFINED;
    int parentId = qjsElNodeId(this_val);
    auto* childP = (QjsElementPriv*)JS_GetOpaque(argv[0], g_qjsElementClassId);
    if (parentId < 0 || !childP) return JS_DupValue(ctx, argv[0]);
    domRemoveChild(host->dom, parentId, childP->nodeId);
    host->domDirty = true;
    return JS_DupValue(ctx, argv[0]);
}

static JSValue qjsElSetAttribute(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
    JsHost* host = qjsHost(ctx);
    DomNode* n = qjsElNode(ctx, this_val);
    if (!n || argc < 2) return JS_UNDEFINED;
    std::string k = toLowerCopy(jsToUtf8(ctx, argv[0]));
    std::string v = jsToUtf8(ctx, argv[1]);
    if (!k.empty()) {
        domSetAttr(*n, k, v);
        if (k == "style") domCaptureStyleDisplay(*n, v);
        if (host) host->domDirty = true;
    }
    return JS_UNDEFINED;
}

static JSValue qjsElGetAttribute(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
    DomNode* n = qjsElNode(ctx, this_val);
    if (!n || argc < 1) return JS_NULL;
    std::string k = toLowerCopy(jsToUtf8(ctx, argv[0]));
    const std::string* p = domGetAttrPtr(*n, k);
    return p ? JS_NewString(ctx, p->c_str()) : JS_NULL;
}

static JSValue jsGetElementById(JSContext* ctx, JSValueConst /*this_val*/, int argc, JSValueConst* argv) {
    JsHost* host = qjsHost(ctx);
    if (!host || argc < 1) return JS_NULL;
    std::string id = jsToUtf8(ctx, argv[0]);
    if (id.empty()) return JS_NULL;

    int nid = domFindById(host->dom, host->dom.root, id);
    if (nid < 0) {
        // Unknown id: hand back a detached element so getElementById(...).x
        // does not throw. It is not part of the rendered tree.
        nid = host->dom.alloc(DomNodeType::Element);
        host->dom.nodes[nid].tag = "div";
        domSetAttr(host->dom.nodes[nid], "id", id);
    }
    return qjsMakeElement(ctx, nid);
}

static JSValue jsCreateElement(JSContext* ctx, JSValueConst /*this_val*/, int argc, JSValueConst* argv) {
    JsHost* host = qjsHost(ctx);
    if (!host || argc < 1) return JS_NULL;
    std::string tag = toLowerCopy(jsToUtf8(ctx, argv[0]));
    if (tag.empty()) tag = "div";
    int nid = host->dom.alloc(DomNodeType::Element);
    host->dom.nodes[nid].tag = tag;
    return qjsMakeElement(ctx, nid);
}

static JSValue jsQuerySelector(JSContext* ctx, JSValueConst /*this_val*/, int argc, JSValueConst* argv) {
    JsHost* host = qjsHost(ctx);
    if (!host || argc < 1) return JS_NULL;
    std::string sel = trimCopy(jsToUtf8(ctx, argv[0]));
    if (sel.empty() || sel.find(' ') != std::string::npos) return JS_NULL; // no combinators

    int nid = -1;
    if (sel[0] == '#') nid = domFindById(host->dom, host->dom.root, sel.substr(1));
    else if (sel[0] == '.') nid = domFindByClass(host->dom, host->dom.root, sel.substr(1));
    else nid = domFindByTag(host->dom, host->dom.root, toLowerCopy(sel));

    if (nid < 0) return JS_NULL;
    return qjsMakeElement(ctx, nid);
}

static JSValue qjsNodeArray(JSContext* ctx, JsHost* host, const std::vector<int>& nids) {
    JSValue arr = JS_NewArray(ctx);
    uint32_t i = 0;
    for (int nid : nids) JS_SetPropertyUint32(ctx, arr, i++, qjsMakeElement(ctx, nid));
    (void)host;
    return arr;
}

// ---------- Batch 1: DOM traversal / mutation / classList / style ----------

static int qjsSiblingId(JsHost* host, int nid, int dir) {   // dir +1 next, -1 prev
    DomNode* n = host->dom.get(nid);
    if (!n || n->parent < 0) return -1;
    DomNode* p = host->dom.get(n->parent);
    if (!p) return -1;
    auto& cs = p->children;
    for (size_t i = 0; i < cs.size(); ++i) {
        if (cs[i] == nid) {
            int j = (int)i + dir;
            return (j < 0 || j >= (int)cs.size()) ? -1 : cs[j];
        }
    }
    return -1;
}

static JSValue qjsElGetChildNodes(JSContext* ctx, JSValueConst this_val, int, JSValueConst*) {
    JsHost* host = qjsHost(ctx);
    int nid = qjsElNodeId(this_val);
    if (!host || nid < 0) return JS_NewArray(ctx);
    DomNode* n = host->dom.get(nid);
    return qjsNodeArray(ctx, host, n ? n->children : std::vector<int>{});
}
static JSValue qjsElGetChildren(JSContext* ctx, JSValueConst this_val, int, JSValueConst*) {
    JsHost* host = qjsHost(ctx);
    int nid = qjsElNodeId(this_val);
    if (!host || nid < 0) return JS_NewArray(ctx);
    std::vector<int> els;
    if (DomNode* n = host->dom.get(nid))
        for (int c : n->children) {
            DomNode* cn = host->dom.get(c);
            if (cn && cn->type == DomNodeType::Element) els.push_back(c);
        }
    return qjsNodeArray(ctx, host, els);
}
static JSValue qjsElGetFirstChild(JSContext* ctx, JSValueConst this_val, int, JSValueConst*) {
    JsHost* host = qjsHost(ctx);
    int nid = qjsElNodeId(this_val);
    if (!host || nid < 0) return JS_NULL;
    DomNode* n = host->dom.get(nid);
    return (!n || n->children.empty()) ? JS_NULL : qjsMakeElement(ctx, n->children.front());
}
static JSValue qjsElGetLastChild(JSContext* ctx, JSValueConst this_val, int, JSValueConst*) {
    JsHost* host = qjsHost(ctx);
    int nid = qjsElNodeId(this_val);
    if (!host || nid < 0) return JS_NULL;
    DomNode* n = host->dom.get(nid);
    return (!n || n->children.empty()) ? JS_NULL : qjsMakeElement(ctx, n->children.back());
}
static JSValue qjsElGetNextSibling(JSContext* ctx, JSValueConst this_val, int, JSValueConst*) {
    JsHost* host = qjsHost(ctx);
    int nid = qjsElNodeId(this_val);
    if (!host || nid < 0) return JS_NULL;
    int s = qjsSiblingId(host, nid, +1);
    return s < 0 ? JS_NULL : qjsMakeElement(ctx, s);
}
static JSValue qjsElGetPrevSibling(JSContext* ctx, JSValueConst this_val, int, JSValueConst*) {
    JsHost* host = qjsHost(ctx);
    int nid = qjsElNodeId(this_val);
    if (!host || nid < 0) return JS_NULL;
    int s = qjsSiblingId(host, nid, -1);
    return s < 0 ? JS_NULL : qjsMakeElement(ctx, s);
}
static JSValue qjsElGetClassName(JSContext* ctx, JSValueConst this_val, int, JSValueConst*) {
    DomNode* n = qjsElNode(ctx, this_val);
    return JS_NewString(ctx, n ? domGetAttr(*n, "class").c_str() : "");
}
static JSValue qjsElSetClassName(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
    JsHost* host = qjsHost(ctx);
    if (DomNode* n = qjsElNode(ctx, this_val)) {
        domSetAttr(*n, "class", (argc > 0) ? jsToUtf8(ctx, argv[0]) : "");
        if (host) host->domDirty = true;
    }
    return JS_UNDEFINED;
}
static JSValue qjsElInsertBefore(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
    JsHost* host = qjsHost(ctx);
    int pid = qjsElNodeId(this_val);
    if (!host || pid < 0 || argc < 1) return JS_UNDEFINED;
    int newId = qjsElNodeId(argv[0]);
    int refId = (argc >= 2) ? qjsElNodeId(argv[1]) : -1;
    if (newId < 0) return JS_UNDEFINED;
    domInsertBefore(host->dom, pid, newId, refId);
    host->domDirty = true;
    return JS_DupValue(ctx, argv[0]);
}
static JSValue qjsElReplaceChild(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
    JsHost* host = qjsHost(ctx);
    int pid = qjsElNodeId(this_val);
    if (!host || pid < 0 || argc < 2) return JS_UNDEFINED;
    int newId = qjsElNodeId(argv[0]);
    int oldId = qjsElNodeId(argv[1]);
    if (newId < 0 || oldId < 0) return JS_UNDEFINED;
    domInsertBefore(host->dom, pid, newId, oldId);   // place new where old was
    domRemoveChild(host->dom, pid, oldId);
    host->domDirty = true;
    return JS_DupValue(ctx, argv[1]);
}
static JSValue qjsElCloneNode(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
    JsHost* host = qjsHost(ctx);
    int nid = qjsElNodeId(this_val);
    if (!host || nid < 0) return JS_NULL;
    bool deep = (argc > 0) && JS_ToBool(ctx, argv[0]);
    int cl = domCloneSubtree(host->dom, nid, deep);
    return cl < 0 ? JS_NULL : qjsMakeElement(ctx, cl);
}
static JSValue qjsElHasAttribute(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
    DomNode* n = qjsElNode(ctx, this_val);
    if (!n || argc < 1) return JS_FALSE;
    return domGetAttrPtr(*n, jsToUtf8(ctx, argv[0])) ? JS_TRUE : JS_FALSE;
}
static JSValue qjsElRemoveAttribute(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
    JsHost* host = qjsHost(ctx);
    if (DomNode* n = qjsElNode(ctx, this_val)) {
        if (argc >= 1) { domRemoveAttr(*n, jsToUtf8(ctx, argv[0])); if (host) host->domDirty = true; }
    }
    return JS_UNDEFINED;
}

// classList: a plain object whose methods carry the node id via CFunctionData.
static int qjsDataNodeId(JSContext* ctx, JSValue* data) { int v = -1; JS_ToInt32(ctx, &v, data[0]); return v; }
static JSValue qjsClassListAdd(JSContext* ctx, JSValueConst, int argc, JSValueConst* argv, int, JSValue* data) {
    JsHost* host = qjsHost(ctx);
    if (host) if (DomNode* n = host->dom.get(qjsDataNodeId(ctx, data)))
        for (int i = 0; i < argc; ++i) { domClassAdd(*n, jsToUtf8(ctx, argv[i])); host->domDirty = true; }
    return JS_UNDEFINED;
}
static JSValue qjsClassListRemove(JSContext* ctx, JSValueConst, int argc, JSValueConst* argv, int, JSValue* data) {
    JsHost* host = qjsHost(ctx);
    if (host) if (DomNode* n = host->dom.get(qjsDataNodeId(ctx, data)))
        for (int i = 0; i < argc; ++i) { domClassRemove(*n, jsToUtf8(ctx, argv[i])); host->domDirty = true; }
    return JS_UNDEFINED;
}
static JSValue qjsClassListContains(JSContext* ctx, JSValueConst, int argc, JSValueConst* argv, int, JSValue* data) {
    JsHost* host = qjsHost(ctx);
    if (host && argc >= 1) if (DomNode* n = host->dom.get(qjsDataNodeId(ctx, data)))
        return domClassContains(*n, jsToUtf8(ctx, argv[0])) ? JS_TRUE : JS_FALSE;
    return JS_FALSE;
}
static JSValue qjsClassListToggle(JSContext* ctx, JSValueConst, int argc, JSValueConst* argv, int, JSValue* data) {
    JsHost* host = qjsHost(ctx);
    if (!host || argc < 1) return JS_FALSE;
    DomNode* n = host->dom.get(qjsDataNodeId(ctx, data));
    if (!n) return JS_FALSE;
    std::string cls = jsToUtf8(ctx, argv[0]);
    bool add = (argc >= 2) ? (bool)JS_ToBool(ctx, argv[1]) : !domClassContains(*n, cls);
    if (add) domClassAdd(*n, cls); else domClassRemove(*n, cls);
    host->domDirty = true;
    return add ? JS_TRUE : JS_FALSE;
}
static JSValue qjsElGetClassList(JSContext* ctx, JSValueConst this_val, int, JSValueConst*) {
    int nid = qjsElNodeId(this_val);
    JSValue o = JS_NewObject(ctx);
    JSValue idv = JS_NewInt32(ctx, nid);
    JSValueConst data[1] = { idv };
    JS_SetPropertyStr(ctx, o, "add", JS_NewCFunctionData(ctx, qjsClassListAdd, 1, 0, 1, data));
    JS_SetPropertyStr(ctx, o, "remove", JS_NewCFunctionData(ctx, qjsClassListRemove, 1, 0, 1, data));
    JS_SetPropertyStr(ctx, o, "toggle", JS_NewCFunctionData(ctx, qjsClassListToggle, 2, 0, 1, data));
    JS_SetPropertyStr(ctx, o, "contains", JS_NewCFunctionData(ctx, qjsClassListContains, 1, 0, 1, data));
    JS_FreeValue(ctx, idv);
    return o;
}

static JSValue qjsCreateTextNode(JSContext* ctx, JSValueConst, int argc, JSValueConst* argv) {
    JsHost* host = qjsHost(ctx);
    if (!host) return JS_NULL;
    int nid = host->dom.alloc(DomNodeType::Text);
    host->dom.nodes[nid].text = (argc > 0) ? jsToUtf8(ctx, argv[0]) : "";
    return qjsMakeElement(ctx, nid);
}

static JSValue jsGetElementsByTagName(JSContext* ctx, JSValueConst /*this_val*/, int argc, JSValueConst* argv) {
    JsHost* host = qjsHost(ctx);
    if (!host || argc < 1) return JS_NewArray(ctx);
    std::vector<int> found;
    domCollectByTag(host->dom, host->dom.root, toLowerCopy(jsToUtf8(ctx, argv[0])), found);
    return qjsNodeArray(ctx, host, found);
}

static JSValue jsGetElementsByClassName(JSContext* ctx, JSValueConst /*this_val*/, int argc, JSValueConst* argv) {
    JsHost* host = qjsHost(ctx);
    if (!host || argc < 1) return JS_NewArray(ctx);
    std::vector<int> found;
    domCollectByClass(host->dom, host->dom.root, trimCopy(jsToUtf8(ctx, argv[0])), found);
    return qjsNodeArray(ctx, host, found);
}

static JSValue jsQuerySelectorAll(JSContext* ctx, JSValueConst /*this_val*/, int argc, JSValueConst* argv) {
    JsHost* host = qjsHost(ctx);
    if (!host || argc < 1) return JS_NewArray(ctx);
    std::string sel = trimCopy(jsToUtf8(ctx, argv[0]));
    std::vector<int> found;
    if (sel.size() > 1 && sel[0] == '.') domCollectByClass(host->dom, host->dom.root, sel.substr(1), found);
    else if (sel.size() > 1 && sel[0] == '#') { int n = domFindById(host->dom, host->dom.root, sel.substr(1)); if (n >= 0) found.push_back(n); }
    else if (!sel.empty() && sel.find(' ') == std::string::npos) domCollectByTag(host->dom, host->dom.root, toLowerCopy(sel), found);
    return qjsNodeArray(ctx, host, found);
}

static JSValue jsDocAddEventListener(JSContext* ctx, JSValueConst /*this_val*/, int argc, JSValueConst* argv) {
    if (argc < 2 || !JS_IsFunction(ctx, argv[1])) return JS_UNDEFINED;
    qjsAddListener(ctx, "document:" + jsToUtf8(ctx, argv[0]), argv[1]);
    return JS_UNDEFINED;
}

static JSValue jsDocRemoveEventListener(JSContext* ctx, JSValueConst /*this_val*/, int argc, JSValueConst* argv) {
    if (argc < 2 || !JS_IsFunction(ctx, argv[1])) return JS_UNDEFINED;
    qjsRemoveListener(ctx, "document:" + jsToUtf8(ctx, argv[0]), argv[1]);
    return JS_UNDEFINED;
}

static JSValue jsWinAddEventListener(JSContext* ctx, JSValueConst /*this_val*/, int argc, JSValueConst* argv) {
    if (argc < 2 || !JS_IsFunction(ctx, argv[1])) return JS_UNDEFINED;
    qjsAddListener(ctx, "window:" + jsToUtf8(ctx, argv[0]), argv[1]);
    return JS_UNDEFINED;
}

static JSValue jsWinRemoveEventListener(JSContext* ctx, JSValueConst /*this_val*/, int argc, JSValueConst* argv) {
    if (argc < 2 || !JS_IsFunction(ctx, argv[1])) return JS_UNDEFINED;
    qjsRemoveListener(ctx, "window:" + jsToUtf8(ctx, argv[0]), argv[1]);
    return JS_UNDEFINED;
}

static void jsDispatchEventSimple(JSContext* ctx, const std::string& key, JSValueConst evt) {
    JsHost* host = qjsHost(ctx);
    if (!host) return;
    auto it = host->listeners.find(key);
    if (it == host->listeners.end()) return;

    QjsEventPriv* ep = qjsEvtPriv(evt); // may be null for plain-object events
    std::vector<JSValue> fns = it->second; // entries stay owned by host->listeners
    for (auto& fn : fns) {
        JSValueConst args[1] = { evt };
        JSValue r = JS_Call(ctx, fn, JS_UNDEFINED, 1, args);
        if (JS_IsException(r)) jsDumpException(ctx);
        JS_FreeValue(ctx, r);
        if (ep && ep->immediateStopped) break; // stopImmediatePropagation()
    }
}

// Remove every listener stored under `key` whose function is identity-equal to
// fn; the removed entries are freed.
static void qjsRemoveListener(JSContext* ctx, const std::string& key, JSValueConst fn) {
    JsHost* host = qjsHost(ctx);
    if (!host) return;
    auto it = host->listeners.find(key);
    if (it == host->listeners.end()) return;
    auto& vec = it->second;
    for (size_t i = 0; i < vec.size();) {
        if (JS_VALUE_GET_PTR(vec[i]) == JS_VALUE_GET_PTR(fn)) {
            JS_FreeValue(ctx, vec[i]);
            vec.erase(vec.begin() + i);
        } else {
            ++i;
        }
    }
}

// Unified DOM event dispatch with bubbling. Returns evt.defaultPrevented.
static bool qjsDispatchEvent(JSContext* ctx, int targetNodeId, JSValueConst evt,
                             const std::string& type, bool bubbles) {
    JsHost* host = qjsHost(ctx);
    if (!host) return false;
    QjsEventPriv* ep = qjsEvtPriv(evt);
    if (ep) {
        ep->targetNodeId = targetNodeId;
        ep->propagationStopped = false;
        ep->immediateStopped = false;
    }

    // Propagation path: target, then its ancestors up to (not including) root.
    std::vector<int> path;
    if (targetNodeId >= 0) {
        for (int n = targetNodeId; n >= 0 && n != host->dom.root;) {
            path.push_back(n);
            DomNode* dn = host->dom.get(n);
            n = dn ? dn->parent : -1;
        }
    }

    bool stopped = false;
    for (size_t i = 0; i < path.size(); ++i) {
        if (i > 0 && !bubbles) break; // non-bubbling: target only
        if (ep) ep->currentTargetNodeId = path[i];
        jsDispatchEventSimple(ctx, "node:" + std::to_string(path[i]) + ":" + type, evt);
        if (ep && ep->propagationStopped) { stopped = true; break; }
    }

    if ((bubbles || path.empty()) && !stopped) {
        if (ep) ep->currentTargetNodeId = -1;
        jsDispatchEventSimple(ctx, "document:" + type, evt);
        if (!(ep && ep->propagationStopped))
            jsDispatchEventSimple(ctx, "window:" + type, evt);
    }

    return ep ? ep->defaultPrevented : false;
}

static void qjsFreeHostRefs(JsEngine& js) {
    if (!js.ctx) return;
    for (auto& t : js.host.timers) {
        if (!JS_IsUndefined(t.fn)) JS_FreeValue(js.ctx, t.fn);
    }
    js.host.timers.clear();
    for (auto& kv : js.host.listeners) {
        for (auto& fn : kv.second) JS_FreeValue(js.ctx, fn);
    }
    js.host.listeners.clear();
}

static void jsDrainJobs(JsEngine& js) {
    if (!js.rt) return;
    JSContext* c = nullptr;
    for (;;) {
        int r = JS_ExecutePendingJob(js.rt, &c);
        if (r == 0) break;
        if (r < 0) { jsDumpException(c ? c : js.ctx); break; }
    }
}

static void jsPumpTimers(JsEngine& js) {
    if (!js.ctx) return;

    double now = qjsNowMs(&js.host);
    // Collect due timers; intervals fire a dup'd ref and stay armed, one-shots
    // are moved out and erased.
    std::vector<JsHost::TimerItem> due;
    for (auto it = js.host.timers.begin(); it != js.host.timers.end(); ) {
        if (it->dueMs <= now) {
            if (it->isInterval) {
                JsHost::TimerItem copy;
                copy.isCode = it->isCode;
                copy.code = it->code;
                copy.isRaf = it->isRaf;
                copy.fn = JS_IsUndefined(it->fn) ? JS_UNDEFINED : JS_DupValue(js.ctx, it->fn);
                due.push_back(std::move(copy));
                it->dueMs = now + it->intervalMs;
                ++it;
            } else {
                due.push_back(std::move(*it));
                it = js.host.timers.erase(it);
            }
        } else {
            ++it;
        }
    }

    for (auto& t : due) {
        JSValue r;
        if (t.isCode) {
            r = JS_Eval(js.ctx, t.code.c_str(), t.code.size(), "<timeout>", JS_EVAL_TYPE_GLOBAL);
        } else if (!JS_IsUndefined(t.fn)) {
            if (t.isRaf) {
                JSValue arg = JS_NewFloat64(js.ctx, now);
                r = JS_Call(js.ctx, t.fn, JS_UNDEFINED, 1, &arg);
                JS_FreeValue(js.ctx, arg);
            } else {
                r = JS_Call(js.ctx, t.fn, JS_UNDEFINED, 0, nullptr);
            }
        } else {
            r = JS_UNDEFINED;
        }
        if (JS_IsException(r)) jsDumpException(js.ctx);
        JS_FreeValue(js.ctx, r);
        if (!JS_IsUndefined(t.fn)) JS_FreeValue(js.ctx, t.fn);
    }

    if (!due.empty()) jsDrainJobs(js);
}

static JSValue jsAlert(JSContext* ctx, JSValueConst /*this_val*/, int argc, JSValueConst* argv) {
    std::string msg;
    if (argc > 0) {
        const char* s = JS_ToCString(ctx, argv[0]);
        if (s) {
            msg = s;
            JS_FreeCString(ctx, s);
        }
    }

    JsHost* host = (JsHost*)JS_GetContextOpaque(ctx);
    SDL_Window* win = host ? host->window : nullptr;

    SDL_ShowSimpleMessageBox(SDL_MESSAGEBOX_INFORMATION, "alert()", msg.c_str(), win);
    return JS_UNDEFINED;
}

static bool jsInit(JsEngine& js) {
    js.rt = JS_NewRuntime();
    if (!js.rt) return false;
    qjsRegisterDomClasses(js.rt);
    return true;
}

static void jsResetContext(JsEngine& js) {
    if (js.ctx) {
        qjsFreeHostRefs(js);
        JS_FreeContext(js.ctx);
        js.ctx = nullptr;
    }

    js.ctx = JS_NewContext(js.rt);
    JS_SetContextOpaque(js.ctx, &js.host);

    qjsSetupDomProtos(js.ctx);

    JSValue global = JS_GetGlobalObject(js.ctx);

    // window / self / top / parent / frames all refer to the global (no frames).
    for (const char* nm : { "window", "self", "top", "parent", "frames" }) {
        JS_SetPropertyStr(js.ctx, global, nm, JS_DupValue(js.ctx, global));
    }

    // console.log / error / warn / info
    JSValue consoleObj = JS_NewObject(js.ctx);
    JS_SetPropertyStr(js.ctx, consoleObj, "log", JS_NewCFunction(js.ctx, jsConsoleLog, "log", 1));
    JS_SetPropertyStr(js.ctx, consoleObj, "error", JS_NewCFunction(js.ctx, jsConsoleLog, "error", 1));
    JS_SetPropertyStr(js.ctx, consoleObj, "warn", JS_NewCFunction(js.ctx, jsConsoleLog, "warn", 1));
    JS_SetPropertyStr(js.ctx, consoleObj, "info", JS_NewCFunction(js.ctx, jsConsoleLog, "info", 1));
    JS_SetPropertyStr(js.ctx, global, "console", consoleObj);

    // alert()
    JS_SetPropertyStr(js.ctx, global, "alert", JS_NewCFunction(js.ctx, jsAlert, "alert", 1));

    // timers
    JS_SetPropertyStr(js.ctx, global, "setTimeout", JS_NewCFunction(js.ctx, jsSetTimeout, "setTimeout", 2));
    JS_SetPropertyStr(js.ctx, global, "clearTimeout", JS_NewCFunction(js.ctx, jsClearTimeout, "clearTimeout", 1));
    JS_SetPropertyStr(js.ctx, global, "setInterval", JS_NewCFunction(js.ctx, jsSetInterval, "setInterval", 2));
    JS_SetPropertyStr(js.ctx, global, "clearInterval", JS_NewCFunction(js.ctx, jsClearTimeout, "clearInterval", 1));
    JS_SetPropertyStr(js.ctx, global, "requestAnimationFrame", JS_NewCFunction(js.ctx, jsRequestAnimationFrame, "requestAnimationFrame", 1));
    JS_SetPropertyStr(js.ctx, global, "cancelAnimationFrame", JS_NewCFunction(js.ctx, jsClearTimeout, "cancelAnimationFrame", 1));

    // performance.now()
    JSValue perfObj = JS_NewObject(js.ctx);
    JS_SetPropertyStr(js.ctx, perfObj, "now", JS_NewCFunction(js.ctx, jsPerformanceNow, "now", 0));
    JS_SetPropertyStr(js.ctx, global, "performance", perfObj);

    // fetch()
    JS_SetPropertyStr(js.ctx, global, "fetch", JS_NewCFunction(js.ctx, jsFetch, "fetch", 1));

    JS_FreeValue(js.ctx, global);
}

static void jsShutdown(JsEngine& js) {
    if (js.ctx) {
        qjsFreeHostRefs(js);
        JS_FreeContext(js.ctx);
    }
    if (js.rt) JS_FreeRuntime(js.rt);
    js.ctx = nullptr;
    js.rt = nullptr;
}

struct ScriptItem {
    std::string code;
    std::string srcAbs;
    bool isModule = false;
};

static std::vector<ScriptItem> extractScriptsSimple(const std::string& html, const Url& baseUrl) {
    std::vector<ScriptItem> out;

    std::string lower = toLowerCopy(html);
    size_t pos = 0;

    while (true) {
        size_t s = lower.find("<script", pos);
        if (s == std::string::npos) break;

        size_t gt = lower.find('>', s);
        if (gt == std::string::npos) break;

        std::string tagContent = html.substr(s + 1, gt - (s + 1)); // "script ..."

        std::string type = toLowerCopy(getAttrValue(tagContent, "type"));
        bool isModule = (type.find("module") != std::string::npos);

        std::string src = trimCopy(getAttrValue(tagContent, "src"));

        size_t end = lower.find("</script>", gt);
        if (end == std::string::npos) break;

        std::string inlineCode = html.substr(gt + 1, end - (gt + 1));

        ScriptItem it;
        it.isModule = isModule;
        if (!src.empty()) it.srcAbs = resolveHref(baseUrl, src);
        else it.code = inlineCode;

        out.push_back(std::move(it));
        pos = end + 9;
    }

    return out;
}

static void jsSetupPageGlobals(JSContext* ctx, const std::string& url, const std::string& title) {
    JSValue global = JS_GetGlobalObject(ctx);

    JSValue document = JS_NewObject(ctx);
    JS_SetPropertyStr(ctx, document, "title", JS_NewString(ctx, title.c_str()));
    JS_SetPropertyStr(ctx, document, "addEventListener", JS_NewCFunction(ctx, jsDocAddEventListener, "addEventListener", 2));
    JS_SetPropertyStr(ctx, document, "removeEventListener", JS_NewCFunction(ctx, jsDocRemoveEventListener, "removeEventListener", 2));
    JS_SetPropertyStr(ctx, document, "getElementById", JS_NewCFunction(ctx, jsGetElementById, "getElementById", 1));
    JS_SetPropertyStr(ctx, document, "createElement", JS_NewCFunction(ctx, jsCreateElement, "createElement", 1));
    JS_SetPropertyStr(ctx, document, "createTextNode", JS_NewCFunction(ctx, qjsCreateTextNode, "createTextNode", 1));
    JS_SetPropertyStr(ctx, document, "querySelector", JS_NewCFunction(ctx, jsQuerySelector, "querySelector", 1));
    JS_SetPropertyStr(ctx, document, "querySelectorAll", JS_NewCFunction(ctx, jsQuerySelectorAll, "querySelectorAll", 1));
    JS_SetPropertyStr(ctx, document, "getElementsByTagName", JS_NewCFunction(ctx, jsGetElementsByTagName, "getElementsByTagName", 1));
    JS_SetPropertyStr(ctx, document, "getElementsByClassName", JS_NewCFunction(ctx, jsGetElementsByClassName, "getElementsByClassName", 1));

    // document.body / head / documentElement map to the real nodes
    // (created if the page omitted them) so appendChild() actually renders.
    if (JsHost* host = qjsHost(ctx)) {
        JS_SetPropertyStr(ctx, document, "body", qjsMakeElement(ctx, domFindOrCreateTag(host->dom, "body")));
        JS_SetPropertyStr(ctx, document, "head", qjsMakeElement(ctx, domFindOrCreateTag(host->dom, "head")));
        JS_SetPropertyStr(ctx, document, "documentElement", qjsMakeElement(ctx, domFindOrCreateTag(host->dom, "html")));
    }

    JS_SetPropertyStr(ctx, global, "document", document);

    JSValue location = JS_NewObject(ctx);
    JS_SetPropertyStr(ctx, location, "href", JS_NewString(ctx, url.c_str()));
    JS_SetPropertyStr(ctx, global, "location", location);

    JSValue navigator = JS_NewObject(ctx);
    JS_SetPropertyStr(ctx, navigator, "userAgent", JS_NewString(ctx, "NoChrome/0.10 (QuickJS)"));
    JS_SetPropertyStr(ctx, global, "navigator", navigator);

    // window/global addEventListener (window === global here).
    JS_SetPropertyStr(ctx, global, "addEventListener", JS_NewCFunction(ctx, jsWinAddEventListener, "addEventListener", 2));
    JS_SetPropertyStr(ctx, global, "removeEventListener", JS_NewCFunction(ctx, jsWinRemoveEventListener, "removeEventListener", 2));

    // Event / CustomEvent constructors (native, usable with `new`).
    JS_SetPropertyStr(ctx, global, "Event",
                      JS_NewCFunction2(ctx, qjsEventCtor, "Event", 2, JS_CFUNC_constructor, 0));
    JS_SetPropertyStr(ctx, global, "CustomEvent",
                      JS_NewCFunction2(ctx, qjsCustomEventCtor, "CustomEvent", 2, JS_CFUNC_constructor, 0));

    // XMLHttpRequest constructor (native, usable with `new`).
    JS_SetPropertyStr(ctx, global, "XMLHttpRequest",
                      JS_NewCFunction2(ctx, qjsXhrCtor, "XMLHttpRequest", 0, JS_CFUNC_constructor, 0));

    // Image(): minimal HTMLImageElement constructor. Sites use `new Image()`
    // for preloading and tracking pixels (img.src = url). Delegates to
    // createElement so it behaves like a real detached <img> node.
    static const char kImageShim[] =
        "function Image(w,h){var e=document.createElement('img');"
        "if(w!=null)e.setAttribute('width',w);"
        "if(h!=null)e.setAttribute('height',h);return e;}";
    JSValue imgRes = JS_Eval(ctx, kImageShim, sizeof(kImageShim) - 1, "<builtin>", JS_EVAL_TYPE_GLOBAL);
    JS_FreeValue(ctx, imgRes);

    JS_FreeValue(ctx, global);
}

static std::string jsReadDocumentTitle(JSContext* ctx) {
    std::string out;

    JSValue global = JS_GetGlobalObject(ctx);
    JSValue doc = JS_GetPropertyStr(ctx, global, "document");

    if (JS_IsObject(doc)) {
        JSValue t = JS_GetPropertyStr(ctx, doc, "title");
        const char* s = JS_ToCString(ctx, t);
        if (s) {
            out = s;
            JS_FreeCString(ctx, s);
        }
        JS_FreeValue(ctx, t);
    }

    JS_FreeValue(ctx, doc);
    JS_FreeValue(ctx, global);

    return out;
}

static std::string runJavaScriptForHtml(JsEngine& js,
                                       const std::string& html,
                                       const Url& baseUrl,
                                       const std::string& urlString) {
    js.host.currentUrl = urlString;
    js.host.baseUrl = baseUrl;
    js.host.domDirty = false;

    jsResetContext(js);

    // Build the real DOM tree (the source of truth for this page; the renderer
    // walks it directly).
    js.host.dom = domParse(stripNoscriptBlocks(html));

    std::string initialTitle = extractTitleFromHtmlSimple(html);
    jsSetupPageGlobals(js.ctx, urlString, initialTitle);

    auto scripts = extractScriptsSimple(html, baseUrl);

    int externalCount = 0;
    for (auto& sc : scripts) {
        if (sc.isModule) {
            // Modules require an import loader. Skip for now.
            continue;
        }

        std::string code = sc.code;
        std::string filename = "<inline>";

        if (!sc.srcAbs.empty()) {
            if (externalCount >= 16) break;
            code = fetchSubresourceText(sc.srcAbs);
            filename = sc.srcAbs;
            externalCount++;
            if (looksLikeHtmlNotJs(code)) continue;
        }

        if (trimCopy(code).empty()) continue;

        JSValue v = JS_Eval(js.ctx, code.c_str(), code.size(), filename.c_str(), JS_EVAL_TYPE_GLOBAL);
        if (JS_IsException(v)) {
            jsDumpException(js.ctx);
        }
        JS_FreeValue(js.ctx, v);

        // Run any microtasks (e.g. fetch().then(...)) queued by this script.
        jsDrainJobs(js);
    }

    return jsReadDocumentTitle(js.ctx);
}
#endif
#endif


// -------------------- HTML -> Styled tokens --------------------

static void domCollectCssVisit(const DomTree& dom, int id, const Url& baseUrl,
                               std::string& cssAll, int& externalCount) {
    const DomNode* n = dom.get(id);
    if (!n) return;
    if (n->type == DomNodeType::Element) {
        if (n->tag == "style") {
            cssAll += domTextContent(dom, id);
            cssAll.push_back('\n');
        } else if (n->tag == "link") {
            std::string rel = toLowerCopy(domGetAttr(*n, "rel"));
            if (rel.find("stylesheet") != std::string::npos && externalCount < 8) {
                std::string href = trimCopy(domGetAttr(*n, "href"));
                if (!href.empty()) {
                    std::string abs = resolveHref(baseUrl, href);
                    std::string css = abs.empty() ? std::string() : fetchSubresourceText(abs);
                    if (!css.empty()) {
                        cssAll += "\n" + css + "\n";
                        externalCount++;
                    }
                }
            }
        }
    }
    for (int c : n->children) domCollectCssVisit(dom, c, baseUrl, cssAll, externalCount);
}

// -------------------- Fonts --------------------

struct FontSet {
    TTF_Font* f16 = nullptr;
    TTF_Font* f20 = nullptr;
    TTF_Font* f24 = nullptr;
    TTF_Font* f28 = nullptr;
    TTF_Font* f34 = nullptr;
};

static std::vector<std::string> fontCandidates() {
    return {
        "fonts/DejaVuSans.ttf",
        "DejaVuSans.ttf",
#ifdef __APPLE__
        "/System/Library/Fonts/Supplemental/Arial.ttf",
        "/System/Library/Fonts/Supplemental/Helvetica.ttf",
        "/Library/Fonts/Arial.ttf",
#endif
        "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
        "/usr/share/fonts/truetype/liberation/LiberationSans-Regular.ttf",
        "/usr/share/fonts/TTF/DejaVuSans.ttf",
        "/usr/share/fonts/dejavu/DejaVuSans.ttf",
    };
}

static bool loadFontSet(FontSet& fs) {
    // Try each candidate; skip ones that fail to open (e.g. missing or a
    // zero-byte placeholder) and fall through to the next.
    for (const auto& path : fontCandidates()) {
        TTF_Font* probe = TTF_OpenFont(path.c_str(), 16);
        if (!probe) continue;
        TTF_CloseFont(probe);

        fs.f16 = TTF_OpenFont(path.c_str(), 16);
        fs.f20 = TTF_OpenFont(path.c_str(), 20);
        fs.f24 = TTF_OpenFont(path.c_str(), 24);
        fs.f28 = TTF_OpenFont(path.c_str(), 28);
        fs.f34 = TTF_OpenFont(path.c_str(), 34);

        if (fs.f16 && fs.f20 && fs.f24 && fs.f28 && fs.f34) return true;

        // Partial open: close whatever opened and try the next candidate.
        if (fs.f16) TTF_CloseFont(fs.f16);
        if (fs.f20) TTF_CloseFont(fs.f20);
        if (fs.f24) TTF_CloseFont(fs.f24);
        if (fs.f28) TTF_CloseFont(fs.f28);
        if (fs.f34) TTF_CloseFont(fs.f34);
        fs = {};
    }
    return false;
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

static SDL_Surface* renderTextWithStyle(TTF_Font* font, const std::string& text, const TextStyle& st) {
    if (!font) return nullptr;

    int old = TTF_GetFontStyle(font);
    int style = TTF_STYLE_NORMAL;
    if (st.bold) style |= TTF_STYLE_BOLD;

    TTF_SetFontStyle(font, style);
    SDL_Surface* surf = TTF_RenderUTF8_Blended(font, text.c_str(), st.color);
    TTF_SetFontStyle(font, old);

    return surf;
}

// -------------------- Layout blocks --------------------

struct StyledWord {
    std::string text;
    std::string href;
    TextStyle style;
    std::string elementId;
};

struct RenderSpan {
    std::string text;
    std::string href;
    TextStyle style;
    std::string elementId;

    SDL_Texture* texture = nullptr;
    int w = 0;
    int h = 0;
};

enum class ItemKind { Box, Text, Image };

// A positioned paint primitive in content coordinates (absolute, pre-scroll).
struct RenderItem {
    ItemKind kind = ItemKind::Text;
    SDL_Rect rect {0, 0, 0, 0};
    // Box:
    bool hasBg = false;
    SDL_Color bg {0, 0, 0, 0};
    int borderW = 0;
    SDL_Color borderColor {120, 120, 120, 255};
    // Text / Image:
    SDL_Texture* tex = nullptr;
    bool underline = false;
    SDL_Color underlineColor {0, 0, 0, 255};
    bool clipSrc = false; // clip texture to rect width (left-aligned) instead of scaling
};

struct LinkHit {
    SDL_Rect rect; // Content coordinates
    std::string href;
};

struct ElementHit {
    SDL_Rect rect; // Content coordinates (bounding box of an element)
    std::string id;
};

enum class ControlType { Text, Password, TextArea, Button, Submit, Checkbox, Radio, Select };

struct ControlHit {
    SDL_Rect rect;       // Content coordinates
    int nodeId = -1;     // DOM node of the control
    ControlType type = ControlType::Text;
};

static void destroyItems(std::vector<RenderItem>& items) {
    for (auto& it : items) {
        if (it.tex) { SDL_DestroyTexture(it.tex); it.tex = nullptr; }
    }
    items.clear();
}

static std::vector<RenderSpan> groupWordsToSpans(const std::vector<StyledWord>& words) {
    std::vector<RenderSpan> spans;
    if (words.empty()) return spans;

    RenderSpan cur;
    cur.text = words[0].text;
    cur.href = words[0].href;
    cur.style = words[0].style;
    cur.elementId = words[0].elementId;

    for (size_t i = 1; i < words.size(); ++i) {
        bool sameHref = (words[i].href == cur.href);
        bool sameStyle = styleEquals(words[i].style, cur.style);
        bool sameId = (words[i].elementId == cur.elementId);

        if (sameHref && sameStyle && sameId) {
            cur.text += " " + words[i].text;
        } else {
            spans.push_back(cur);
            cur.text = words[i].text;
            cur.href = words[i].href;
            cur.style = words[i].style;
            cur.elementId = words[i].elementId;
        }
    }

    spans.push_back(cur);
    return spans;
}

static SDL_Texture* loadImageTexture(SDL_Renderer* renderer,
                                     const std::string& imgBytes,
                                     int* outW,
                                     int* outH) {
    if (outW) *outW = 0;
    if (outH) *outH = 0;
    if (imgBytes.empty()) return nullptr;

    SDL_RWops* rw = SDL_RWFromConstMem(imgBytes.data(), (int)imgBytes.size());
    if (!rw) return nullptr;

    SDL_Surface* surf = IMG_Load_RW(rw, 1);
    if (!surf) return nullptr;

    SDL_Texture* tex = SDL_CreateTextureFromSurface(renderer, surf);
    if (tex) {
        if (outW) *outW = surf->w;
        if (outH) *outH = surf->h;
    }

    SDL_FreeSurface(surf);
    return tex;
}

static int domIntAttr(const std::string& s) {
    std::string v = trimCopy(s);
    if (v.empty()) return 0;
    try { return std::max(0, std::stoi(v)); } catch (...) { return 0; }
}

static bool isFormControl(const std::string& tag) {
    return tag == "input" || tag == "textarea" || tag == "button" || tag == "select";
}

// Genuinely inline elements. Everything else (including unknown wrappers like
// <center> and block elements) is laid out as a block, so block content is
// never mistakenly funneled through inline collection.
static bool isInlineTag(const std::string& tag) {
    static const std::unordered_set<std::string> inl = {
        "a","b","i","em","strong","span","small","code","sub","sup","mark","u",
        "s","strike","tt","big","abbr","cite","q","var","samp","kbd","font","time",
        "ins","del","bdi","bdo","wbr","ruby","rt","rp","br","img"
    };
    return inl.count(tag) > 0;
}

// -------------------- Block box layout --------------------
// Walks the DOM tree producing positioned RenderItems (block boxes + inline
// text/images). Block elements get margins/padding/border/background/width/
// text-align; inline descendants flow into wrapped lines within each block.
struct BoxLayout {
    SDL_Renderer* renderer;
    const FontSet& fonts;
    const std::vector<StyleRule>& rules;
    const DomTree& dom;
    Url baseUrl;
    int baseLineHeight;
    std::vector<RenderItem>& items;
    std::vector<LinkHit>& links;
    std::vector<ControlHit>& controls;
    std::unordered_map<std::string, SDL_Rect>& idRects;

    void recordHit(const std::string& id, const SDL_Rect& r) {
        auto it = idRects.find(id);
        if (it == idRects.end()) { idRects[id] = r; return; }
        SDL_Rect& u = it->second;
        int x0 = std::min(u.x, r.x), y0 = std::min(u.y, r.y);
        int x1 = std::max(u.x + u.w, r.x + r.w), y1 = std::max(u.y + u.h, r.y + r.h);
        u = SDL_Rect{ x0, y0, x1 - x0, y1 - y0 };
    }

    // Gather inline tokens (words / <br> / <img>) from an inline subtree.
    void collectInline(int nodeId, TextStyle style, std::string href,
                       std::string eid, std::vector<StyledToken>& toks) {
        const DomNode* n = dom.get(nodeId);
        if (!n) return;

        if (n->type == DomNodeType::Text) {
            std::istringstream iss(n->text);
            std::string w;
            while (iss >> w) {
                StyledToken t; t.kind = TokenKind::Word; t.text = w;
                t.href = href; t.style = style; t.elementId = eid;
                toks.push_back(std::move(t));
            }
            return;
        }

        const std::string& tag = n->tag;
        if (tag == "br") { StyledToken t; t.kind = TokenKind::Break; t.breakCount = 1; toks.push_back(t); return; }
        if (tag == "img") {
            std::string src = trimCopy(domGetAttr(*n, "src"));
            if (!src.empty()) {
                StyledToken it; it.kind = TokenKind::Image;
                it.imgSrcAbs = resolveHref(baseUrl, src);
                it.imgAlt = domGetAttr(*n, "alt");
                it.imgAttrW = domIntAttr(domGetAttr(*n, "width"));
                it.imgAttrH = domIntAttr(domGetAttr(*n, "height"));
                toks.push_back(std::move(it));
            }
            return;
        }
        if (tag == "script" || tag == "style" || tag == "head" || tag == "title" || tag == "noscript") return;

        TextStyle st = style;
        std::string id = trimCopy(domGetAttr(*n, "id"));
        auto classes = parseClassList(domGetAttr(*n, "class"));
        applyTagDefaults(tag, st);
        applyRulesForElement(rules, tag, toLowerCopy(id), classes, st);
        std::string inlineCss = domGetAttr(*n, "style");
        if (!inlineCss.empty()) applyInlineStyle(inlineCss, st);

        std::string childHref = (tag == "a") ? trimCopy(domGetAttr(*n, "href")) : href;
        std::string childEid = id.empty() ? eid : id;
        for (int c : n->children) collectInline(c, st, childHref, childEid, toks);
    }

    int layoutImageToken(const StyledToken& t, int contentX, int y, int contentW) {
        if (t.imgSrcAbs.empty()) return y;
        std::string bytes = fetchSubresourceBytes(t.imgSrcAbs);
        int iw = 0, ih = 0;
        SDL_Texture* tex = loadImageTexture(renderer, bytes, &iw, &ih);

        if (!tex || iw <= 0 || ih <= 0) {
            std::string alt = t.imgAlt.empty() ? "[image]" : ("[image: " + t.imgAlt + "]");
            TextStyle st;
            TTF_Font* f = pickFont(fonts, st.fontSize);
            SDL_Surface* surf = renderTextWithStyle(f, alt, st);
            if (surf) {
                RenderItem it; it.kind = ItemKind::Text;
                it.rect = { contentX, y, surf->w, surf->h };
                it.tex = SDL_CreateTextureFromSurface(renderer, surf);
                int h = surf->h;
                SDL_FreeSurface(surf);
                items.push_back(it);
                y += std::max(baseLineHeight, h + 6);
            }
            return y;
        }

        int tw = iw, th = ih;
        if (t.imgAttrW > 0 && t.imgAttrH > 0) { tw = t.imgAttrW; th = t.imgAttrH; }
        else if (t.imgAttrW > 0) { float s = (float)t.imgAttrW / iw; tw = t.imgAttrW; th = std::max(1, (int)std::lround(ih * s)); }
        else if (t.imgAttrH > 0) { float s = (float)t.imgAttrH / ih; th = t.imgAttrH; tw = std::max(1, (int)std::lround(iw * s)); }
        if (tw > contentW && tw > 0) { float s = (float)contentW / tw; tw = contentW; th = std::max(1, (int)std::lround(th * s)); }

        RenderItem it; it.kind = ItemKind::Image; it.rect = { contentX, y, tw, th }; it.tex = tex;
        items.push_back(it);
        return y + th + 8;
    }

    // Lay out a stream of inline tokens into wrapped lines within [contentX, contentX+contentW).
    int layoutInline(const std::vector<StyledToken>& toks, int contentX, int startY, int contentW, int textAlign) {
        int y = startY;
        int maxLineW = std::max(10, contentW);

        std::vector<StyledWord> line;
        int lineW = 0;

        auto flush = [&]() {
            if (line.empty()) return;
            auto spans = groupWordsToSpans(line);
            int maxH = 0;
            for (auto& sp : spans) {
                TTF_Font* f = pickFont(fonts, sp.style.fontSize);
                SDL_Surface* surf = renderTextWithStyle(f, sp.text, sp.style);
                if (surf) {
                    sp.w = surf->w; sp.h = surf->h;
                    sp.texture = SDL_CreateTextureFromSurface(renderer, surf);
                    SDL_FreeSurface(surf);
                }
                maxH = std::max(maxH, sp.h);
            }
            int total = 0;
            for (size_t i = 0; i < spans.size(); ++i) {
                total += spans[i].w;
                if (i + 1 < spans.size()) {
                    TTF_Font* f = pickFont(fonts, spans[i].style.fontSize);
                    total += textWidth(f, " ");
                }
            }
            int lineH = std::max(baseLineHeight, maxH + 6);
            int xoff = 0;
            if (textAlign == 1) xoff = std::max(0, (contentW - total) / 2);
            else if (textAlign == 2) xoff = std::max(0, contentW - total);
            int x = contentX + xoff;
            for (auto& sp : spans) {
                SDL_Rect r { x, y, sp.w, sp.h };
                if (sp.texture) {
                    RenderItem it; it.kind = ItemKind::Text; it.rect = r; it.tex = sp.texture;
                    if (!sp.href.empty()) { it.underline = true; it.underlineColor = sp.style.color; }
                    items.push_back(it);
                }
                if (!sp.href.empty() && sp.w > 0) links.push_back({ r, sp.href });
                if (!sp.elementId.empty() && sp.w > 0) recordHit(sp.elementId, r);
                TTF_Font* f = pickFont(fonts, sp.style.fontSize);
                x += sp.w + textWidth(f, " ");
            }
            y += lineH;
            line.clear();
            lineW = 0;
        };

        for (const auto& t : toks) {
            if (t.kind == TokenKind::Break) {
                if (line.empty()) y += baseLineHeight; else flush();
                continue;
            }
            if (t.kind == TokenKind::Image) { flush(); y = layoutImageToken(t, contentX, y, contentW); continue; }

            TTF_Font* f = pickFont(fonts, t.style.fontSize);
            int wW = textWidth(f, t.text);
            int spaceW = textWidth(f, " ");
            int add = line.empty() ? wW : (spaceW + wW);
            if (!line.empty() && lineW + add > maxLineW) flush();
            if (line.empty()) lineW = wW; else lineW += add;
            line.push_back(StyledWord{ t.text, t.href, t.style, t.elementId });
        }
        flush();
        return y;
    }

    // Render a form control (input / button / textarea / select) as a box and
    // record a hit-rect so the UI can focus / click / submit it.
    int layoutControl(int nodeId, const std::string& tag, int x, int y, int availWidth,
                      TextStyle st, const BoxStyle& box, const std::string& elemId) {
        const DomNode* node = dom.get(nodeId);
        if (!node) return y;
        std::string type = toLowerCopy(domGetAttr(*node, "type"));
        // Hidden inputs carry form data but render nothing and take no space.
        if (tag == "input" && type == "hidden") return y;
        int left = x + box.mLeft;
        int top = y + box.mTop;
        int avail = std::max(0, availWidth - box.mLeft - box.mRight);

        auto makeText = [&](const std::string& s, SDL_Color col, int* outW, int* outH) -> SDL_Texture* {
            TextStyle ts = st; ts.color = col;
            TTF_Font* f = pickFont(fonts, ts.fontSize);
            SDL_Surface* surf = renderTextWithStyle(f, s, ts);
            if (!surf) { *outW = 0; *outH = 0; return nullptr; }
            *outW = surf->w; *outH = surf->h;
            SDL_Texture* t = SDL_CreateTextureFromSurface(renderer, surf);
            SDL_FreeSurface(surf);
            return t;
        };
        auto emitText = [&](SDL_Texture* tex, int tx, int ty, int tw, int th, int maxW) {
            if (!tex) return;
            RenderItem it; it.kind = ItemKind::Text; it.tex = tex;
            if (tw > maxW && maxW > 0) { it.clipSrc = true; tw = maxW; }
            it.rect = { tx, ty, tw, th };
            items.push_back(it);
        };
        auto recordCtrl = [&](const SDL_Rect& r, ControlType ct) {
            controls.push_back(ControlHit{ r, nodeId, ct });
            if (!elemId.empty()) recordHit(elemId, r);
        };

        if (tag == "input" && (type == "checkbox" || type == "radio")) {
            int sz = 18;
            SDL_Rect r{ left, top, sz, sz };
            RenderItem b; b.kind = ItemKind::Box; b.rect = r; b.hasBg = true; b.bg = {255,255,255,255};
            b.borderW = 2; b.borderColor = {120,120,120,255}; items.push_back(b);
            if (domGetAttrPtr(*node, "checked")) {
                RenderItem c; c.kind = ItemKind::Box; c.rect = { left+4, top+4, sz-8, sz-8 };
                c.hasBg = true; c.bg = {60,100,220,255}; items.push_back(c);
            }
            recordCtrl(r, type == "radio" ? ControlType::Radio : ControlType::Checkbox);
            return top + sz + std::max(6, box.mBottom);
        }

        bool isBtn = (tag == "button") || (tag == "input" && (type == "submit" || type == "button" || type == "reset"));
        if (isBtn) {
            std::string label = (tag == "button") ? domTextContent(dom, nodeId) : domGetAttr(*node, "value");
            if (label.empty()) label = (type == "submit" || (tag == "button" && type.empty())) ? "Submit" : "Button";
            int tw = 0, th = 0;
            SDL_Texture* tex = makeText(label, SDL_Color{20,20,25,255}, &tw, &th);
            int h = std::max(32, th + 12);
            int w = (box.width >= 0) ? box.width : std::min(avail, tw + 28);
            SDL_Rect r{ left, top, w, h };
            RenderItem b; b.kind = ItemKind::Box; b.rect = r; b.hasBg = true; b.bg = {228,228,232,255};
            b.borderW = 1; b.borderColor = {140,140,140,255}; items.push_back(b);
            emitText(tex, left + std::max(8, (w - tw) / 2), top + (h - th) / 2, tw, th, w - 12);
            ControlType ct = ControlType::Button;
            if (type == "submit" || (tag == "button" && (type.empty() || type == "submit"))) ct = ControlType::Submit;
            recordCtrl(r, ct);
            return top + h + std::max(6, box.mBottom);
        }

        if (tag == "textarea") {
            int w = (box.width >= 0) ? box.width : std::min(avail, 460);
            int rows = domIntAttr(domGetAttr(*node, "rows")); if (rows <= 0) rows = 4;
            int h = rows * (st.fontSize + 8) + 12;
            SDL_Rect r{ left, top, w, h };
            RenderItem b; b.kind = ItemKind::Box; b.rect = r; b.hasBg = true; b.bg = {255,255,255,255};
            b.borderW = 1; b.borderColor = {150,150,150,255}; items.push_back(b);
            std::string val = domGetAttrPtr(*node, "value") ? domGetAttr(*node, "value") : domTextContent(dom, nodeId);
            if (!val.empty()) {
                std::vector<StyledToken> toks;
                std::istringstream iss(val); std::string wtok;
                while (iss >> wtok) { StyledToken t; t.kind = TokenKind::Word; t.text = wtok; t.style = st; toks.push_back(std::move(t)); }
                layoutInline(toks, left + 8, top + 6, w - 16, 0);
            }
            recordCtrl(r, ControlType::TextArea);
            return top + h + std::max(6, box.mBottom);
        }

        if (tag == "select") {
            std::string label;
            for (int c : node->children) {
                const DomNode* opt = dom.get(c);
                if (opt && opt->type == DomNodeType::Element && opt->tag == "option") {
                    std::string t = domTextContent(dom, c);
                    if (label.empty()) label = t;
                    if (domGetAttrPtr(*opt, "selected")) { label = t; break; }
                }
            }
            int tw = 0, th = 0;
            SDL_Texture* tex = makeText(label.empty() ? " " : label, SDL_Color{30,30,30,255}, &tw, &th);
            int h = std::max(32, th + 12);
            int w = (box.width >= 0) ? box.width : std::min(avail, std::max(120, tw + 40));
            SDL_Rect r{ left, top, w, h };
            RenderItem b; b.kind = ItemKind::Box; b.rect = r; b.hasBg = true; b.bg = {245,245,247,255};
            b.borderW = 1; b.borderColor = {150,150,150,255}; items.push_back(b);
            emitText(tex, left + 8, top + (h - th) / 2, tw, th, w - 28);
            recordCtrl(r, ControlType::Select);
            return top + h + std::max(6, box.mBottom);
        }

        // text-like input (text/search/email/url/tel/number/password/empty/unknown)
        int w = (box.width >= 0) ? box.width : std::min(avail, 300);
        int h = std::max(34, st.fontSize + 16);
        SDL_Rect r{ left, top, w, h };
        RenderItem b; b.kind = ItemKind::Box; b.rect = r; b.hasBg = true; b.bg = {255,255,255,255};
        b.borderW = 1; b.borderColor = {150,150,150,255}; items.push_back(b);
        std::string raw = domGetAttr(*node, "value");
        std::string shown = raw;
        SDL_Color col{30,30,30,255};
        if (shown.empty()) { shown = domGetAttr(*node, "placeholder"); col = {165,165,170,255}; }
        if (type == "password" && !raw.empty()) shown = std::string(raw.size(), '*');
        if (!shown.empty()) {
            int tw = 0, th = 0;
            SDL_Texture* tex = makeText(shown, col, &tw, &th);
            emitText(tex, left + 8, top + (h - th) / 2, tw, th, w - 16);
        }
        recordCtrl(r, type == "password" ? ControlType::Password : ControlType::Text);
        return top + h + std::max(6, box.mBottom);
    }

    // Lay out a block element; returns the y just below it (incl. bottom margin).
    int layoutBlock(int nodeId, int x, int y, int availWidth,
                    TextStyle inheritStyle, int inheritAlign, std::string inheritEid) {
        const DomNode* node = dom.get(nodeId);
        if (!node || node->type != DomNodeType::Element) return y;
        const std::string& tag = node->tag;

        if (tag == "head" || tag == "script" || tag == "style" ||
            tag == "title" || tag == "meta" || tag == "link") return y;
#ifdef NOCHROME_ENABLE_JS
        if (tag == "noscript") return y;
#endif

        std::string id = trimCopy(domGetAttr(*node, "id"));
        auto classes = parseClassList(domGetAttr(*node, "class"));
        std::string styleAttr = domGetAttr(*node, "style");

        BoxStyle box;
        applyBoxDefaults(tag, box);
        applyBoxRulesForElement(rules, tag, toLowerCopy(id), classes, box);
        if (!styleAttr.empty()) { StyleRule tmp; applyDeclarationsToRule(tmp, styleAttr); applyBoxRuleProps(tmp, box); }
        if (box.displayNone) return y;

        TextStyle st = inheritStyle;
        applyTagDefaults(tag, st);
        applyRulesForElement(rules, tag, toLowerCopy(id), classes, st);
        if (!styleAttr.empty()) applyInlineStyle(styleAttr, st);

        int effAlign = (box.textAlign >= 0) ? box.textAlign : inheritAlign;
        std::string elemId = id.empty() ? inheritEid : id;

        if (tag == "hr") {
            int top = y + box.mTop;
            int w = std::max(0, availWidth - box.mLeft - box.mRight);
            int h = std::max(1, box.borderW);
            RenderItem it; it.kind = ItemKind::Box;
            it.rect = { x + box.mLeft, top, w, h };
            it.hasBg = true; it.bg = box.borderColor;
            items.push_back(it);
            return top + h + box.mBottom;
        }

        if (isFormControl(tag)) {
            return layoutControl(nodeId, tag, x, y, availWidth, st, box, elemId);
        }

        int avail = std::max(0, availWidth - box.mLeft - box.mRight);
        int borderBoxW;
        if (box.width >= 0) borderBoxW = box.width + box.pLeft + box.pRight + 2 * box.borderW;
        else if (box.widthPct >= 0) borderBoxW = avail * box.widthPct / 100;
        else borderBoxW = avail;
        borderBoxW = std::clamp(borderBoxW, 0, avail);

        int boxLeft = x + box.mLeft;
        if (box.marginAuto && (box.width >= 0 || box.widthPct >= 0))
            boxLeft = x + box.mLeft + std::max(0, (avail - borderBoxW) / 2);

        int contentW = std::max(0, borderBoxW - 2 * box.borderW - box.pLeft - box.pRight);
        int boxTop = y + box.mTop;
        int contentLeft = boxLeft + box.borderW + box.pLeft;
        int contentTop = boxTop + box.borderW + box.pTop;

        bool drawBox = box.hasBg || box.borderW > 0;
        size_t boxIdx = (size_t)-1;
        if (drawBox) { boxIdx = items.size(); items.push_back(RenderItem{}); }

        int curY = contentTop;
        std::vector<StyledToken> inlineToks;
        auto flushInline = [&]() {
            if (inlineToks.empty()) return;
            curY = layoutInline(inlineToks, contentLeft, curY, contentW, effAlign);
            inlineToks.clear();
        };

        if (tag == "li") {
            StyledToken b; b.kind = TokenKind::Word; b.text = "\xE2\x80\xA2"; b.style = st; b.elementId = elemId;
            inlineToks.push_back(b);
        }

        for (int c : node->children) {
            const DomNode* cn = dom.get(c);
            if (!cn) continue;
            bool childBlock = (cn->type == DomNodeType::Element) && !isInlineTag(cn->tag);
            if (childBlock) {
                flushInline();
                curY = layoutBlock(c, contentLeft, curY, contentW, st, effAlign, elemId);
            } else {
                collectInline(c, st, "", elemId, inlineToks);
            }
        }
        flushInline();

        int contentBottom = curY;
        int boxBottom = contentBottom + box.pBottom + box.borderW;

        if (drawBox) {
            RenderItem it; it.kind = ItemKind::Box;
            it.rect = { boxLeft, boxTop, borderBoxW, std::max(0, boxBottom - boxTop) };
            it.hasBg = box.hasBg; it.bg = box.bg;
            it.borderW = box.borderW; it.borderColor = box.borderColor;
            items[boxIdx] = it;
        }

        if (!id.empty())
            recordHit(id, SDL_Rect{ boxLeft, boxTop, borderBoxW, std::max(0, boxBottom - boxTop) });

        return boxBottom + box.mBottom;
    }
};

static int layoutDocument(SDL_Renderer* renderer, const FontSet& fonts, const DomTree& dom,
                          const Url& baseUrl, int contentWidth, int padding, int baseLineHeight,
                          std::vector<RenderItem>& items, std::vector<LinkHit>& links,
                          std::vector<ElementHit>& elements, std::vector<ControlHit>& controls,
                          SDL_Color* outPageBg) {
    items.clear(); links.clear(); elements.clear(); controls.clear();

    std::string cssAll; int ext = 0;
    domCollectCssVisit(dom, dom.root, baseUrl, cssAll, ext);
    auto rules = parseCssRules(cssAll);
    if (outPageBg) *outPageBg = extractPageBackgroundFromRules(rules);

    std::unordered_map<std::string, SDL_Rect> idRects;
    BoxLayout bl{ renderer, fonts, rules, dom, baseUrl, baseLineHeight, items, links, controls, idRects };

    int availWidth = std::max(10, contentWidth - 2 * padding);
    TextStyle base;
    int bottom = bl.layoutBlock(dom.root, padding, padding, availWidth, base, -1, "");

    for (auto& kv : idRects) elements.push_back(ElementHit{ kv.second, kv.first });
    return bottom + padding;
}

// -------------------- Page state --------------------

struct Page {
    Url baseUrl;
    std::string urlString;
    std::string body;
    DomTree dom;   // parsed / post-JS DOM tree; the renderer walks this

    SDL_Color background {245, 245, 245, 255};

    std::vector<RenderItem> items;
    std::vector<LinkHit> linkHits;
    std::vector<ElementHit> elementHits;
    std::vector<ControlHit> controlHits;
    int contentHeight = 0;
};

static std::string loadPageBodyText(const std::string& urlString, Url& outUrl) {
    std::string normalized = normalizeUserUrl(urlString);
    Url u = parseUrl(normalized);
    outUrl = u;

    try {
        std::string headers;
        std::string body = httpFetchProcessed(u, outUrl, &headers); // redirects + gzip
        return decodeHtmlToUtf8(headers, body);
    } catch (const std::exception& ex) {
        return std::string("<h2>Network error</h2><p>") + ex.what() + "</p>";
    }
}

static void rebuildLayout(Page& page,
                          SDL_Renderer* renderer,
                          const FontSet& fonts,
                          int contentWidth,
                          int padding,
                          int baseLineHeight) {
    destroyItems(page.items);

    SDL_Color bg = page.background;
    page.contentHeight = layoutDocument(renderer, fonts, page.dom, page.baseUrl,
                                        contentWidth, padding, baseLineHeight,
                                        page.items, page.linkHits, page.elementHits,
                                        page.controlHits, &bg);
    page.background = bg;
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

// -------------------- Form submission --------------------

static std::string urlEncode(const std::string& s) {
    static const char* hex = "0123456789ABCDEF";
    std::string out;
    out.reserve(s.size());
    for (unsigned char c : s) {
        if (std::isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') out.push_back((char)c);
        else if (c == ' ') out.push_back('+');
        else { out.push_back('%'); out.push_back(hex[c >> 4]); out.push_back(hex[c & 0xF]); }
    }
    return out;
}

// Collect successful form fields (name=value) under a node into a query string.
static void collectFormFields(const DomTree& dom, int nodeId, std::string& query) {
    const DomNode* n = dom.get(nodeId);
    if (!n) return;

    if (n->type == DomNodeType::Element) {
        const std::string& tag = n->tag;
        std::string name = domGetAttr(*n, "name");
        if (!name.empty()) {
            std::string type = toLowerCopy(domGetAttr(*n, "type"));
            bool include = false;
            std::string value;
            if (tag == "input") {
                if (type == "checkbox" || type == "radio") {
                    if (domGetAttrPtr(*n, "checked")) {
                        include = true;
                        value = domGetAttr(*n, "value");
                        if (value.empty()) value = "on";
                    }
                } else if (type == "submit" || type == "button" || type == "reset" ||
                           type == "file" || type == "image") {
                    // not a successful control on its own here
                } else {
                    include = true;
                    value = domGetAttr(*n, "value");
                }
            } else if (tag == "textarea") {
                include = true;
                value = domGetAttrPtr(*n, "value") ? domGetAttr(*n, "value") : domTextContent(dom, nodeId);
            } else if (tag == "select") {
                include = true;
                for (int c : n->children) {
                    const DomNode* o = dom.get(c);
                    if (o && o->type == DomNodeType::Element && o->tag == "option") {
                        std::string v = domGetAttrPtr(*o, "value") ? domGetAttr(*o, "value") : domTextContent(dom, c);
                        if (value.empty()) value = v;
                        if (domGetAttrPtr(*o, "selected")) { value = v; break; }
                    }
                }
            }
            if (include) {
                if (!query.empty()) query += "&";
                query += urlEncode(name) + "=" + urlEncode(value);
            }
        }
    }
    for (int c : n->children) collectFormFields(dom, c, query);
}

// -------------------- main --------------------

int main(int argc, char** argv) {
    std::string startUrl = "https://example.com/";
    if (argc >= 2) startUrl = argv[1];

    if (SDL_Init(SDL_INIT_VIDEO) != 0) {
        SDL_LogError(SDL_LOG_CATEGORY_APPLICATION, "SDL init failed: %s", SDL_GetError());
        return 1;
    }
    if (TTF_Init() != 0) {
        SDL_LogError(SDL_LOG_CATEGORY_APPLICATION, "TTF init failed: %s", TTF_GetError());
        SDL_Quit();
        return 1;
    }

    int imgFlags = IMG_INIT_PNG | IMG_INIT_JPG;
    if ((IMG_Init(imgFlags) & imgFlags) != imgFlags) {
        SDL_LogError(SDL_LOG_CATEGORY_APPLICATION, "SDL_image init failed: %s", IMG_GetError());
        // We can still run without images, but user wants img support, so abort.
        TTF_Quit();
        SDL_Quit();
        return 1;
    }

    SDL_Window* window = SDL_CreateWindow(
        "NoChrome",
        SDL_WINDOWPOS_CENTERED, SDL_WINDOWPOS_CENTERED,
        1100, 750,
        SDL_WINDOW_RESIZABLE
    );
    if (!window) {
        SDL_LogError(SDL_LOG_CATEGORY_APPLICATION, "Window create failed: %s", SDL_GetError());
        IMG_Quit();
        TTF_Quit();
        SDL_Quit();
        return 1;
    }

    SDL_Renderer* renderer = SDL_CreateRenderer(window, -1,
        SDL_RENDERER_ACCELERATED | SDL_RENDERER_PRESENTVSYNC);
    if (!renderer) {
        SDL_LogError(SDL_LOG_CATEGORY_APPLICATION, "Renderer create failed: %s", SDL_GetError());
        SDL_DestroyWindow(window);
        IMG_Quit();
        TTF_Quit();
        SDL_Quit();
        return 1;
    }

    FontSet fonts;
    if (!loadFontSet(fonts)) {
        SDL_LogError(SDL_LOG_CATEGORY_APPLICATION, "Could not load a font. Add ./fonts/DejaVuSans.ttf");
        SDL_DestroyRenderer(renderer);
        SDL_DestroyWindow(window);
        IMG_Quit();
        TTF_Quit();
        SDL_Quit();
        return 1;
    }


#ifdef NOCHROME_ENABLE_JS
    JsEngine js;
    if (!jsInit(js)) {
        SDL_LogError(SDL_LOG_CATEGORY_APPLICATION, "QuickJS init failed");
        freeFontSet(fonts);
        SDL_DestroyRenderer(renderer);
        SDL_DestroyWindow(window);
        IMG_Quit();
        TTF_Quit();
        SDL_Quit();
        return 1;
    }
    js.host.window = window;
#endif

    const int tabBarH = 34;
    const int topBarH = 56;
    const int chromeH = tabBarH + topBarH;
    const int padding = 18;

    int winW = 1100, winH = 750;
    SDL_GetWindowSize(window, &winW, &winH);

    int contentWidth = winW;
    int baseLineHeight = 32;

    auto calcAddressRect = [&](int w){
        SDL_Rect r;
        r.x = 12;
        r.y = tabBarH + 10;
        r.w = std::max(200, w - 24);
        r.h = topBarH - 20;
        return r;
    };

    SDL_Rect addressRect = calcAddressRect(winW);

    struct TabState {
        Page page;
        std::string title;
        std::string addressInput;
        float scrollYf = 0.0f;
        int layoutWidth = 0;
    };

    std::vector<TabState> tabs;
    int activeTab = 0;
#ifdef NOCHROME_ENABLE_JS
    int activeJsTab = -1; // which tab the shared JS context currently belongs to
#endif

    int focusedCtrl = -1;   // DOM node id of the focused form control (active tab)
    int lastActiveTab = 0;  // detect tab switches to drop control focus

    bool addressFocused = false;

    auto blurAddress = [&](){
        addressFocused = false;
        SDL_StopTextInput();
    };

    auto focusAddress = [&](){
        addressFocused = true;
        SDL_StartTextInput();
        if (!tabs.empty()) tabs[activeTab].addressInput = tabs[activeTab].page.urlString;
    };

    auto setWindowTitleFromActive = [&](){
        if (tabs.empty()) {
            SDL_SetWindowTitle(window, "NoChrome");
            return;
        }

        auto& t = tabs[activeTab];
        std::string shown = (!t.title.empty()) ? t.title : t.page.urlString;
        if (shown.empty()) shown = "NoChrome";
        SDL_SetWindowTitle(window, ("NoChrome - " + shown).c_str());
    };

    auto maxScroll = [&](){
        if (tabs.empty()) return 0;
        int viewH = std::max(10, winH - chromeH);
        return std::max(0, tabs[activeTab].page.contentHeight - viewH);
    };

    auto clampScroll = [&](){
        if (tabs.empty()) return;
        int ms = maxScroll();
        auto& t = tabs[activeTab];
        if (t.scrollYf < 0.0f) t.scrollYf = 0.0f;
        if (t.scrollYf > (float)ms) t.scrollYf = (float)ms;
    };

    auto rebuildTabLayout = [&](int idx){
        if (idx < 0 || idx >= (int)tabs.size()) return;
        rebuildLayout(tabs[idx].page, renderer, fonts, contentWidth, padding, baseLineHeight);
        tabs[idx].layoutWidth = contentWidth;
    };

    auto loadUrlIntoTab = [&](int idx, const std::string& rawUrl){
        if (idx < 0 || idx >= (int)tabs.size()) return;

        auto& t = tabs[idx];

        std::string norm = normalizeUserUrl(rawUrl);
        Url u;
        std::string body = loadPageBodyText(norm, u);

        t.page.baseUrl = u;
        t.page.urlString = norm;
        t.page.body = body;

        std::string pageTitle = extractTitleFromHtmlSimple(t.page.body);
#ifdef NOCHROME_ENABLE_JS
        {
            std::string jsTitle = runJavaScriptForHtml(js, t.page.body, t.page.baseUrl, t.page.urlString);
            if (!jsTitle.empty()) pageTitle = jsTitle;

            // The renderer walks the DOM tree; take the post-JS tree from the host.
            t.page.dom = js.host.dom;
            js.host.domDirty = false;
            activeJsTab = idx;
        }
#else
        t.page.dom = domParse(t.page.body);
#endif

        t.title = pageTitle;

        rebuildTabLayout(idx);

        t.addressInput = t.page.urlString;
        t.scrollYf = 0.0f;
        if (idx == activeTab) focusedCtrl = -1;

        if (idx == activeTab) {
            setWindowTitleFromActive();
        }
    };

    // Submit the form enclosing the given control node (GET; POST is best-effort).
    auto submitForm = [&](int ctrlNode){
        if (tabs.empty()) return;
        Page& pg = tabs[activeTab].page;
        DomTree& d = pg.dom;

        int formId = -1;
        for (int n = ctrlNode; n >= 0; ) {
            DomNode* nd = d.get(n);
            if (!nd) break;
            if (nd->tag == "form") { formId = n; break; }
            n = nd->parent;
        }

        std::string query;
        collectFormFields(d, formId >= 0 ? formId : d.root, query);

        std::string action;
        if (formId >= 0) action = trimCopy(domGetAttr(*d.get(formId), "action"));
        std::string target = action.empty() ? pg.urlString : resolveHref(pg.baseUrl, action);
        if (target.empty()) target = pg.urlString;

        if (!query.empty())
            target += (target.find('?') == std::string::npos ? "?" : "&") + query;

        focusedCtrl = -1;
        loadUrlIntoTab(activeTab, target);
        clampScroll();
    };

    auto openNewTab = [&](const std::string& url, bool activate){
        TabState t;
        tabs.push_back(std::move(t));
        int idx = (int)tabs.size() - 1;

        if (activate) {
            activeTab = idx;
            blurAddress();
        }

        loadUrlIntoTab(idx, url);
        clampScroll();
    };

    auto closeTab = [&](int idx){
        if (idx < 0 || idx >= (int)tabs.size()) return;

        destroyItems(tabs[idx].page.items);
        tabs.erase(tabs.begin() + idx);

        if (tabs.empty()) {
            openNewTab("https://example.com/", true);
            return;
        }

        if (activeTab >= (int)tabs.size()) activeTab = (int)tabs.size() - 1;
        if (idx == activeTab) blurAddress();

        // Ensure active tab is laid out for current window size
        if (tabs[activeTab].layoutWidth != contentWidth) rebuildTabLayout(activeTab);

        clampScroll();
        setWindowTitleFromActive();
    };

    // Initial tab
    tabs.push_back(TabState{});
    activeTab = 0;
    loadUrlIntoTab(0, startUrl);
    setWindowTitleFromActive();

    TTF_Font* uiFont = fonts.f16;

    auto renderUiText = [&](const std::string& text, SDL_Color col){
        if (!uiFont) return (SDL_Texture*)nullptr;
        SDL_Surface* surf = TTF_RenderUTF8_Blended(uiFont, text.c_str(), col);
        if (!surf) return (SDL_Texture*)nullptr;
        SDL_Texture* tex = SDL_CreateTextureFromSurface(renderer, surf);
        SDL_FreeSurface(surf);
        return tex;
    };

    auto drawXIcon = [&](const SDL_Rect& r, SDL_Color col){
        SDL_SetRenderDrawColor(renderer, col.r, col.g, col.b, col.a);
        SDL_RenderDrawLine(renderer, r.x, r.y, r.x + r.w, r.y + r.h);
        SDL_RenderDrawLine(renderer, r.x + r.w, r.y, r.x, r.y + r.h);
    };

    auto drawPlusIcon = [&](const SDL_Rect& r, SDL_Color col){
        SDL_SetRenderDrawColor(renderer, col.r, col.g, col.b, col.a);
        int cx = r.x + r.w / 2;
        int cy = r.y + r.h / 2;
        SDL_RenderDrawLine(renderer, cx - 6, cy, cx + 6, cy);
        SDL_RenderDrawLine(renderer, cx, cy - 6, cx, cy + 6);
    };

    auto tabRectFor = [&](int i){
        const int tabX0 = 10;
        const int tabY0 = 4;
        const int tabH = tabBarH - 8;
        const int tabW = 180;
        const int gap = 6;
        SDL_Rect r { tabX0 + i * (tabW + gap), tabY0, tabW, tabH };
        return r;
    };

    auto tabCloseRectFor = [&](const SDL_Rect& tr){
        SDL_Rect r { tr.x + tr.w - 20, tr.y + (tr.h - 14) / 2, 14, 14 };
        return r;
    };

    auto plusRect = [&](){
        SDL_Rect last = tabRectFor((int)tabs.size());
        last.w = 36;
        return last;
    };

    auto hitTestTabIndex = [&](int mx, int my)->int {
        if (my < 0 || my >= tabBarH) return -1;
        for (int i = 0; i < (int)tabs.size(); i++) {
            SDL_Rect tr = tabRectFor(i);
            if (pointInRect(mx, my, tr)) return i;
        }
        return -1;
    };

    auto hitTestTabClose = [&](int mx, int my, int tabIdx)->bool {
        SDL_Rect tr = tabRectFor(tabIdx);
        SDL_Rect cr = tabCloseRectFor(tr);
        return pointInRect(mx, my, cr);
    };

    auto hitTestPlus = [&](int mx, int my)->bool {
        SDL_Rect pr = plusRect();
        return pointInRect(mx, my, pr);
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

                        rebuildTabLayout(activeTab);
                        clampScroll();
                    }
                    break;

                case SDL_MOUSEWHEEL: {
                    float dy = (e.wheel.preciseY != 0.0f) ? e.wheel.preciseY : (float)e.wheel.y;
                    tabs[activeTab].scrollYf -= dy * (float)baseLineHeight * 2.0f;
                    clampScroll();
                    break;
                }

                case SDL_MOUSEBUTTONDOWN: {
                    int mx = e.button.x;
                    int my = e.button.y;

                    
                    // Tabs bar interactions
                    if (my < tabBarH) {
                        if (e.button.button == SDL_BUTTON_LEFT) {
                            if (hitTestPlus(mx, my)) {
                                openNewTab("https://example.com/", true);
                                break;
                            }
                            int idx = hitTestTabIndex(mx, my);
                            if (idx != -1) {
                                if (hitTestTabClose(mx, my, idx)) {
                                    closeTab(idx);
                                    break;
                                }

                                if (idx != activeTab) {
                                    activeTab = idx;
                                    blurAddress();

                                    if (tabs[activeTab].layoutWidth != contentWidth) rebuildTabLayout(activeTab);
                                    clampScroll();
                                    setWindowTitleFromActive();
                                }
                                break;
                            }
                        } else if (e.button.button == SDL_BUTTON_MIDDLE) {
                            int idx = hitTestTabIndex(mx, my);
                            if (idx != -1) {
                                closeTab(idx);
                                break;
                            }
                        }

                        break;
                    }

                    // Address bar focus
                    if (pointInRect(mx, my, addressRect)) {
                        focusAddress();
                        break;
                    } else {
                        blurAddress();
                    }

                    // Content click
                    if (my >= chromeH && e.button.button == SDL_BUTTON_LEFT) {
                        int scrollY = (int)tabs[activeTab].scrollYf;
                        int contentY = (my - chromeH) + scrollY;

                        auto& page = tabs[activeTab].page;

                        // Whether a JS click handler called preventDefault(); if so the
                        // built-in link navigation / form submit below is suppressed.
                        bool clickDefaultPrevented = false;

#ifdef NOCHROME_ENABLE_JS
                        // Dispatch a click to the innermost element with an id under the cursor.
                        if (js.ctx && activeJsTab == activeTab) {
                            std::string hitId;
                            long bestArea = -1;
                            for (const auto& eh : page.elementHits) {
                                const SDL_Rect& r = eh.rect;
                                if (mx >= r.x && mx < r.x + r.w &&
                                    contentY >= r.y && contentY < r.y + r.h) {
                                    long area = (long)r.w * (long)r.h;
                                    if (bestArea < 0 || area < bestArea) {
                                        bestArea = area;
                                        hitId = eh.id;
                                    }
                                }
                            }
                            // Resolve the hit element's nodeId (-1 => document/window only).
                            int hitNid = hitId.empty()
                                ? -1 : domFindById(page.dom, page.dom.root, hitId);
#if defined(NOCHROME_USE_JSC)
                            g_jsHost = &js.host;
                            JSObjectRef evt = jscMakeEvent(js.ctx, "click", true, true);
                            JSStringRef cxn = JSStringCreateWithUTF8CString("clientX");
                            JSObjectSetProperty(js.ctx, evt, cxn, JSValueMakeNumber(js.ctx, mx), kJSPropertyAttributeNone, nullptr);
                            JSStringRelease(cxn);
                            JSStringRef cyn = JSStringCreateWithUTF8CString("clientY");
                            JSObjectSetProperty(js.ctx, evt, cyn, JSValueMakeNumber(js.ctx, my), kJSPropertyAttributeNone, nullptr);
                            JSStringRelease(cyn);
                            clickDefaultPrevented = jscDispatchEvent(js.ctx, hitNid, evt, "click", true);
#else
                            JSValue evt = qjsMakeEvent(js.ctx, "click", true, true);
                            JS_SetPropertyStr(js.ctx, evt, "clientX", JS_NewInt32(js.ctx, mx));
                            JS_SetPropertyStr(js.ctx, evt, "clientY", JS_NewInt32(js.ctx, my));
                            clickDefaultPrevented = qjsDispatchEvent(js.ctx, hitNid, evt, "click", true);
                            JS_FreeValue(js.ctx, evt);
                            jsDrainJobs(js);
#endif
                        }
#endif

                        // Form controls take priority over links / text.
                        bool ctrlHandled = false;
                        for (const auto& ch : page.controlHits) {
                            const SDL_Rect& r = ch.rect;
                            if (!(mx >= r.x && mx < r.x + r.w && contentY >= r.y && contentY < r.y + r.h)) continue;
                            ctrlHandled = true;
                            blurAddress();
                            DomNode* n = page.dom.get(ch.nodeId);
                            if (ch.type == ControlType::Text || ch.type == ControlType::Password ||
                                ch.type == ControlType::TextArea) {
                                focusedCtrl = ch.nodeId;
                                SDL_StartTextInput();
                            } else if (ch.type == ControlType::Checkbox || ch.type == ControlType::Radio) {
                                focusedCtrl = -1;
                                if (n) {
                                    if (domGetAttrPtr(*n, "checked")) domRemoveAttr(*n, "checked");
                                    else domSetAttr(*n, "checked", "");
                                    rebuildTabLayout(activeTab);
                                }
                            } else if (ch.type == ControlType::Submit) {
                                focusedCtrl = -1;
                                if (!clickDefaultPrevented) submitForm(ch.nodeId);
                            } else {
                                focusedCtrl = -1; // button / select: no action yet
                            }
                            break;
                        }
                        if (!ctrlHandled && focusedCtrl >= 0) {
                            focusedCtrl = -1;
                            if (!addressFocused) SDL_StopTextInput();
                        }

                        if (!ctrlHandled && !clickDefaultPrevented)
                        for (const auto& hit : page.linkHits) {
                            SDL_Rect r = hit.rect;

                            if (mx >= r.x && mx < r.x + r.w &&
                                contentY >= r.y && contentY < r.y + r.h) {

                                std::string abs = resolveHref(page.baseUrl, hit.href);
                                if (abs.empty()) break;

                                bool ctrl = (SDL_GetModState() & KMOD_CTRL);

                                if (ctrl) {
                                    openNewTab(abs, true);
                                } else {
                                    loadUrlIntoTab(activeTab, abs);
                                }

                                clampScroll();
                                break;
                            }
                        }
                    }

                    break;
                }

                case SDL_TEXTINPUT:
                    if (focusedCtrl >= 0) {
                        DomNode* n = tabs[activeTab].page.dom.get(focusedCtrl);
                        if (n) {
                            domSetAttr(*n, "value", domGetAttr(*n, "value") + e.text.text);
                            rebuildTabLayout(activeTab);
                        }
                    } else if (addressFocused) {
                        tabs[activeTab].addressInput += e.text.text;
                    }
                    break;

                case SDL_KEYDOWN: {
                    bool ctrl = (e.key.keysym.mod & KMOD_CTRL);
                    bool shift = (e.key.keysym.mod & KMOD_SHIFT);

                    // Set when a JS keydown handler called preventDefault(); used to
                    // suppress the built-in ENTER-causes-submit behaviour below.
                    bool keyDefaultPrevented = false;

#ifdef NOCHROME_ENABLE_JS
                    // Target the focused control (so the event bubbles to document/window);
                    // otherwise dispatch straight to document + window.
                    int keyTargetNid = (focusedCtrl >= 0) ? focusedCtrl : -1;
                    const char* keyName = SDL_GetKeyName(e.key.keysym.sym);
#if defined(NOCHROME_USE_JSC)
                    if (js.ctx) {
                        g_jsHost = &js.host;
                        JSObjectRef evt = jscMakeEvent(js.ctx, "keydown", true, true);
                        JSStringRef kn = JSStringCreateWithUTF8CString("key");
                        JSObjectSetProperty(js.ctx, evt, kn, JSValueMakeString(js.ctx, JSStringCreateWithUTF8CString(keyName ? keyName : "")), kJSPropertyAttributeNone, nullptr);
                        JSStringRelease(kn);
                        JSStringRef cn = JSStringCreateWithUTF8CString("ctrlKey");
                        JSObjectSetProperty(js.ctx, evt, cn, JSValueMakeBoolean(js.ctx, ctrl), kJSPropertyAttributeNone, nullptr);
                        JSStringRelease(cn);
                        JSStringRef sn = JSStringCreateWithUTF8CString("shiftKey");
                        JSObjectSetProperty(js.ctx, evt, sn, JSValueMakeBoolean(js.ctx, shift), kJSPropertyAttributeNone, nullptr);
                        JSStringRelease(sn);
                        keyDefaultPrevented = jscDispatchEvent(js.ctx, keyTargetNid, evt, "keydown", true);
                    }
#else
                    if (js.ctx) {
                        JSValue evt = qjsMakeEvent(js.ctx, "keydown", true, true);
                        JS_SetPropertyStr(js.ctx, evt, "key", JS_NewString(js.ctx, keyName ? keyName : ""));
                        JS_SetPropertyStr(js.ctx, evt, "ctrlKey", JS_NewBool(js.ctx, ctrl));
                        JS_SetPropertyStr(js.ctx, evt, "shiftKey", JS_NewBool(js.ctx, shift));
                        keyDefaultPrevented = qjsDispatchEvent(js.ctx, keyTargetNid, evt, "keydown", true);
                        JS_FreeValue(js.ctx, evt);
                        jsDrainJobs(js);
                    }
#endif
#endif

                    if (e.key.keysym.sym == SDLK_ESCAPE) {
                        if (focusedCtrl >= 0) { focusedCtrl = -1; if (!addressFocused) SDL_StopTextInput(); break; }
                        if (addressFocused) { blurAddress(); break; }
                        running = false;
                        break;
                    }

                    // Tabs shortcuts
                    if (ctrl && e.key.keysym.sym == SDLK_t) {
                        openNewTab("https://example.com/", true);
                        break;
                    }
                    if (ctrl && e.key.keysym.sym == SDLK_w) {
                        if (!tabs.empty()) closeTab(activeTab);
                        break;
                    }
                    if (ctrl && e.key.keysym.sym == SDLK_TAB) {
                        if (!tabs.empty()) {
                            int n = (int)tabs.size();
                            if (shift) activeTab = (activeTab - 1 + n) % n;
                            else activeTab = (activeTab + 1) % n;

                            blurAddress();
                            if (tabs[activeTab].layoutWidth != contentWidth) rebuildTabLayout(activeTab);
                            clampScroll();
                            setWindowTitleFromActive();
                        }
                        break;
                    }
                    if (ctrl && e.key.keysym.sym == SDLK_r) {
                        if (!tabs.empty()) {
                            loadUrlIntoTab(activeTab, tabs[activeTab].page.urlString);
                            clampScroll();
                        }
                        break;
                    }

                    // Address focus shortcut
                    if (ctrl && e.key.keysym.sym == SDLK_l) {
                        focusAddress();
                        break;
                    }

                    if (addressFocused) {
                        if (e.key.keysym.sym == SDLK_BACKSPACE) {
                            auto& s = tabs[activeTab].addressInput;
                            if (!s.empty()) s.pop_back();
                        } else if (e.key.keysym.sym == SDLK_RETURN || e.key.keysym.sym == SDLK_KP_ENTER) {
                            loadUrlIntoTab(activeTab, tabs[activeTab].addressInput);
                            tabs[activeTab].scrollYf = 0.0f;
                            clampScroll();
                            blurAddress();
                        }
                    } else if (focusedCtrl >= 0) {
                        DomNode* fn = tabs[activeTab].page.dom.get(focusedCtrl);
                        if (fn) {
                            if (e.key.keysym.sym == SDLK_BACKSPACE) {
                                std::string v = domGetAttr(*fn, "value");
                                if (!v.empty()) {
                                    size_t k = v.size();
                                    do { k--; } while (k > 0 && ((unsigned char)v[k] & 0xC0) == 0x80);
                                    v.erase(k);
                                    domSetAttr(*fn, "value", v);
                                    rebuildTabLayout(activeTab);
                                }
                            } else if (e.key.keysym.sym == SDLK_RETURN || e.key.keysym.sym == SDLK_KP_ENTER) {
                                if (fn->tag == "textarea") {
                                    domSetAttr(*fn, "value", domGetAttr(*fn, "value") + "\n");
                                    rebuildTabLayout(activeTab);
                                } else if (!keyDefaultPrevented) {
                                    submitForm(focusedCtrl);
                                }
                            }
                        }
                    } else {
                        // Scrolling shortcuts
                        if (e.key.keysym.sym == SDLK_DOWN) { tabs[activeTab].scrollYf += baseLineHeight; clampScroll(); }
                        else if (e.key.keysym.sym == SDLK_UP) { tabs[activeTab].scrollYf -= baseLineHeight; clampScroll(); }
                        else if (e.key.keysym.sym == SDLK_PAGEDOWN) { tabs[activeTab].scrollYf += (winH - chromeH) * 0.9f; clampScroll(); }
                        else if (e.key.keysym.sym == SDLK_PAGEUP) { tabs[activeTab].scrollYf -= (winH - chromeH) * 0.9f; clampScroll(); }
                        else if (e.key.keysym.sym == SDLK_HOME) { tabs[activeTab].scrollYf = 0.0f; clampScroll(); }
                        else if (e.key.keysym.sym == SDLK_END) { tabs[activeTab].scrollYf = (float)maxScroll(); clampScroll(); }
                    }

                    break;
                }
            }
        }

#ifdef NOCHROME_ENABLE_JS
        // Run due timers + microtasks, then re-render if JS mutated the active tab's DOM.
        jsPumpTimers(js);
        if (js.host.domDirty) {
            js.host.domDirty = false;
            if (activeJsTab == activeTab && !tabs.empty()) {
                // The handler mutated the DOM tree; copy it over and re-render.
                tabs[activeTab].page.dom = js.host.dom;
                rebuildTabLayout(activeTab);
                clampScroll();

                std::string jsTitle = jsReadDocumentTitle(js.ctx);
                if (!jsTitle.empty() && jsTitle != tabs[activeTab].title) {
                    tabs[activeTab].title = jsTitle;
                    setWindowTitleFromActive();
                }
            }
        }
#endif

        // Dropping control focus when the active tab changes.
        if (lastActiveTab != activeTab) { focusedCtrl = -1; lastActiveTab = activeTab; }

        // ---------- Render ----------
        SDL_SetRenderDrawColor(renderer, 16, 16, 18, 255);
        SDL_RenderClear(renderer);

        // Tab bar
        SDL_Rect tabBar { 0, 0, winW, tabBarH };
        drawFilledRect(renderer, tabBar, 20, 20, 24);

        for (int i = 0; i < (int)tabs.size(); i++) {
            SDL_Rect tr = tabRectFor(i);
            if (tr.x > winW - 60) break;

            bool active = (i == activeTab);
            drawFilledRect(renderer, tr,
                           active ? 40 : 28,
                           active ? 40 : 28,
                           active ? 50 : 34);

            // Close icon
            SDL_Rect cr = tabCloseRectFor(tr);
            drawXIcon(cr, SDL_Color{200, 200, 200, 255});

            // Title
            std::string label = tabs[i].title.empty() ? tabs[i].page.urlString : tabs[i].title;
            if (label.empty()) label = "New Tab";
            if ((int)label.size() > 22) label = label.substr(0, 22) + "...";

            SDL_Color col { 230, 230, 235, 255 };
            SDL_Texture* tex = renderUiText(label, col);
            if (tex) {
                int tw=0, th=0;
                SDL_QueryTexture(tex, nullptr, nullptr, &tw, &th);

                SDL_Rect dst {
                    tr.x + 10,
                    tr.y + (tr.h - th) / 2,
                    std::min(tw, tr.w - 34),
                    th
                };
                SDL_RenderCopy(renderer, tex, nullptr, &dst);
                SDL_DestroyTexture(tex);
            }
        }

        // Plus button
        SDL_Rect pr = plusRect();
        if (pr.x + pr.w < winW - 10) {
            drawFilledRect(renderer, pr, 28, 28, 34);
            SDL_Rect iconR { pr.x + (pr.w - 14) / 2, pr.y + (pr.h - 14) / 2, 14, 14 };
            drawPlusIcon(iconR, SDL_Color{230,230,235,255});
        }

        // Address bar
        SDL_Rect topBar { 0, tabBarH, winW, topBarH };
        drawFilledRect(renderer, topBar, 24, 24, 28);

        drawFilledRect(renderer, addressRect,
                       addressFocused ? 38 : 32,
                       addressFocused ? 38 : 32,
                       addressFocused ? 44 : 40);

        SDL_SetRenderDrawColor(renderer,
                               addressFocused ? 90 : 60,
                               addressFocused ? 140 : 60,
                               addressFocused ? 255 : 90, 255);

        SDL_RenderDrawRect(renderer, &addressRect);

        // Address text
        {
            SDL_Color col = addressFocused ? SDL_Color{230,230,240,255} : SDL_Color{200,200,210,255};
            std::string shown = tabs[activeTab].addressInput;
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

        // Content background
        SDL_Rect contentBg { 0, chromeH, winW, winH - chromeH };
        auto& page = tabs[activeTab].page;
        drawFilledRect(renderer, contentBg,
                       page.background.r,
                       page.background.g,
                       page.background.b,
                       page.background.a);

        int scrollY = (int)tabs[activeTab].scrollYf;

        for (const auto& it : page.items) {
            int yScreen = chromeH + it.rect.y - scrollY;

            if (yScreen + it.rect.h < chromeH - 50) continue;
            if (yScreen > winH + 50) break;

            SDL_Rect dst { it.rect.x, yScreen, it.rect.w, it.rect.h };

            if (it.kind == ItemKind::Box) {
                if (it.hasBg) {
                    drawFilledRect(renderer, dst, it.bg.r, it.bg.g, it.bg.b, it.bg.a ? it.bg.a : 255);
                }
                if (it.borderW > 0) {
                    int bw = it.borderW;
                    SDL_SetRenderDrawColor(renderer, it.borderColor.r, it.borderColor.g, it.borderColor.b, 255);
                    SDL_Rect sides[4] = {
                        { dst.x, dst.y, dst.w, bw },
                        { dst.x, dst.y + dst.h - bw, dst.w, bw },
                        { dst.x, dst.y, bw, dst.h },
                        { dst.x + dst.w - bw, dst.y, bw, dst.h }
                    };
                    for (auto& s : sides) SDL_RenderFillRect(renderer, &s);
                }
            } else if (it.tex) {
                if (it.clipSrc) {
                    SDL_Rect src { 0, 0, it.rect.w, it.rect.h };
                    SDL_RenderCopy(renderer, it.tex, &src, &dst);
                } else {
                    SDL_RenderCopy(renderer, it.tex, nullptr, &dst);
                }
                if (it.underline) {
                    SDL_SetRenderDrawColor(renderer, it.underlineColor.r, it.underlineColor.g, it.underlineColor.b, 255);
                    SDL_Rect ul { dst.x, dst.y + dst.h + 2, dst.w, 1 };
                    SDL_RenderFillRect(renderer, &ul);
                }
            }
        }

        // Focus ring on the active form control.
        if (focusedCtrl >= 0) {
            for (const auto& ch : page.controlHits) {
                if (ch.nodeId != focusedCtrl) continue;
                int ys = chromeH + ch.rect.y - scrollY;
                SDL_SetRenderDrawColor(renderer, 70, 130, 255, 255);
                SDL_Rect a { ch.rect.x - 1, ys - 1, ch.rect.w + 2, ch.rect.h + 2 };
                SDL_Rect b { ch.rect.x, ys, ch.rect.w, ch.rect.h };
                SDL_RenderDrawRect(renderer, &a);
                SDL_RenderDrawRect(renderer, &b);
                break;
            }
        }

        SDL_RenderPresent(renderer);
    }

    for (auto& t : tabs) {
        destroyItems(t.page.items);
    }

    freeFontSet(fonts);

#ifdef NOCHROME_ENABLE_JS
    jsShutdown(js);
#endif

    SDL_DestroyRenderer(renderer);
    SDL_DestroyWindow(window);

    IMG_Quit();
    TTF_Quit();
    SDL_Quit();
    return 0;
}
