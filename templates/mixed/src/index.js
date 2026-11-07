// Mixed package: one script, two sources with their own contentKinds (shinsou.plugin.json).
//   - manga source: IMAGE_SEQUENCE  → getPageList returns image pages
//   - novel source: PLAIN_TEXT      → getChapterText returns the chapter text string
// `var sources` must stay a top-level declaration. Each entry's `id` must equal the sourceId in
// shinsou.plugin.json (init filled them in): the host selects a source by exact id, never by position.

var MANGA_BASE = "https://example.com";
var NOVEL_BASE = "https://novel.example.com";

function absolute(base, url) {
  return url.indexOf("http") === 0 ? url : base + url;
}

var mangaSource = {
  id: "__MANGA_SOURCE_ID__",
  baseUrl: MANGA_BASE,
  supportsLatest: true,

  getPopularManga: function (page) {
    var html = bridge.httpGet(MANGA_BASE + "/popular?page=" + page);
    if (!html) return new MangasPage([], false);
    var doc = Jsoup.parse(html, MANGA_BASE);
    var mangas = doc.select(".manga-item").map(function (el) {
      var m = SManga.create();
      m.url = el.selectFirst("a").attr("href");
      m.title = el.selectFirst(".title").text();
      m.thumbnailUrl = el.selectFirst("img").absUrl("src");
      return m;
    });
    return new MangasPage(mangas, doc.selectFirst("a.next") !== null);
  },

  getLatestUpdates: function (page) {
    return this.getPopularManga(page);
  },

  getSearchManga: function (page, query, filters) {
    var html = bridge.httpGet(MANGA_BASE + "/search?q=" + encodeURIComponent(query) + "&page=" + page);
    if (!html) return new MangasPage([], false);
    var doc = Jsoup.parse(html, MANGA_BASE);
    var mangas = doc.select(".manga-item").map(function (el) {
      var m = SManga.create();
      m.url = el.selectFirst("a").attr("href");
      m.title = el.selectFirst(".title").text();
      return m;
    });
    return new MangasPage(mangas, false);
  },

  getMangaDetails: function (manga) {
    var doc = Jsoup.parse(bridge.httpGet(absolute(MANGA_BASE, manga.url)) || "", MANGA_BASE);
    manga.description = doc.select(".description").text();
    manga.author = doc.select(".author").text();
    manga.status = SManga.ONGOING;
    manga.initialized = true;
    return manga;
  },

  getChapterList: function (manga) {
    var doc = Jsoup.parse(bridge.httpGet(absolute(MANGA_BASE, manga.url)) || "", MANGA_BASE);
    return doc.select(".chapter-list a").map(function (el) {
      var ch = SChapter.create();
      ch.url = el.attr("href");
      ch.name = el.text();
      return ch;
    });
  },

  getPageList: function (chapter) {
    var doc = Jsoup.parse(bridge.httpGet(absolute(MANGA_BASE, chapter.url)) || "", MANGA_BASE);
    return doc.select(".page-img img").map(function (img, i) {
      var url = img.absUrl("data-src") || img.absUrl("src");
      return new Page(i, "", url);
    });
  },

  getFilterList: function () {
    return [];
  }
};

function listBooks(path) {
  var html = bridge.httpGet(NOVEL_BASE + path);
  if (!html) return new MangasPage([], false);
  var doc = Jsoup.parse(html, NOVEL_BASE);
  var books = doc.select(".book").map(function (el) {
    var m = SManga.create();
    m.url = el.selectFirst("a").attr("href");
    m.title = el.selectFirst("a").text();
    m.author = el.select(".author").text() || null;
    return m;
  });
  return new MangasPage(books, doc.selectFirst("a.next") !== null);
}

var novelSource = {
  id: "__NOVEL_SOURCE_ID__",
  baseUrl: NOVEL_BASE,
  supportsLatest: true,

  getPopularManga: function (page) {
    return listBooks("/rank?page=" + page);
  },

  getLatestUpdates: function (page) {
    return listBooks("/latest?page=" + page);
  },

  getSearchManga: function (page, query, filters) {
    return listBooks("/search?q=" + encodeURIComponent(query) + "&page=" + page);
  },

  getMangaDetails: function (book) {
    var doc = Jsoup.parse(bridge.httpGet(absolute(NOVEL_BASE, book.url)) || "", NOVEL_BASE);
    book.description = doc.select(".intro").text();
    book.initialized = true;
    return book;
  },

  getChapterList: function (book) {
    var doc = Jsoup.parse(bridge.httpGet(absolute(NOVEL_BASE, book.url)) || "", NOVEL_BASE);
    return doc.select(".toc a").map(function (el) {
      var ch = SChapter.create();
      ch.url = el.attr("href");
      ch.name = el.text();
      return ch;
    });
  },

  // Returns the chapter text itself: paragraphs separated by a blank line.
  getChapterText: function (chapter) {
    var doc = Jsoup.parse(bridge.httpGet(absolute(NOVEL_BASE, chapter.url)) || "", NOVEL_BASE);
    var paragraphs = doc.select(".content p").map(function (p) { return p.text(); });
    return paragraphs.join("\n\n");
  }
};

var sources = [mangaSource, novelSource];
