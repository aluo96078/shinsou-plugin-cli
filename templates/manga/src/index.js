// Manga source template. `var source` must stay a top-level declaration: the host looks it up by name.
// Network access is limited to the exact origins in shinsou.plugin.json (sources[].requestOrigins).

var BASE = "https://example.com";

function absolute(url) {
  return url.indexOf("http") === 0 ? url : BASE + url;
}

var source = {
  baseUrl: BASE,
  supportsLatest: true,

  getPopularManga: function (page) {
    var html = bridge.httpGet(BASE + "/popular?page=" + page);
    if (!html) return new MangasPage([], false);
    var doc = Jsoup.parse(html, BASE);
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
    var html = bridge.httpGet(BASE + "/search?q=" + encodeURIComponent(query) + "&page=" + page);
    if (!html) return new MangasPage([], false);
    var doc = Jsoup.parse(html, BASE);
    var mangas = doc.select(".manga-item").map(function (el) {
      var m = SManga.create();
      m.url = el.selectFirst("a").attr("href");
      m.title = el.selectFirst(".title").text();
      return m;
    });
    return new MangasPage(mangas, false);
  },

  getMangaDetails: function (manga) {
    var doc = Jsoup.parse(bridge.httpGet(absolute(manga.url)) || "", BASE);
    manga.description = doc.select(".description").text();
    manga.author = doc.select(".author").text();
    manga.status = SManga.ONGOING;
    manga.initialized = true;
    return manga;
  },

  getChapterList: function (manga) {
    var doc = Jsoup.parse(bridge.httpGet(absolute(manga.url)) || "", BASE);
    return doc.select(".chapter-list a").map(function (el) {
      var ch = SChapter.create();
      ch.url = el.attr("href");
      ch.name = el.text();
      return ch;
    });
  },

  getPageList: function (chapter) {
    var doc = Jsoup.parse(bridge.httpGet(absolute(chapter.url)) || "", BASE);
    return doc.select(".page-img img").map(function (img, i) {
      var url = img.absUrl("data-src") || img.absUrl("src");
      return new Page(i, "", url);
    });
  },

  getFilterList: function () {
    return [];
  }
};
