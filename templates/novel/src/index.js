// Novel source template: getPageList returns text pages ({ text, content }) instead of images.

var BASE = "https://example.com";

function absolute(url) {
  return url.indexOf("http") === 0 ? url : BASE + url;
}

function listBooks(path) {
  var html = bridge.httpGet(BASE + path);
  if (!html) return new MangasPage([], false);
  var doc = Jsoup.parse(html, BASE);
  var books = doc.select(".book").map(function (el) {
    var m = SManga.create();
    m.url = el.selectFirst("a").attr("href");
    m.title = el.selectFirst("a").text();
    m.author = el.select(".author").text() || null;
    return m;
  });
  return new MangasPage(books, doc.selectFirst("a.next") !== null);
}

var source = {
  baseUrl: BASE,
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
    var doc = Jsoup.parse(bridge.httpGet(absolute(book.url)) || "", BASE);
    book.description = doc.select(".intro").text();
    book.initialized = true;
    return book;
  },

  getChapterList: function (book) {
    var doc = Jsoup.parse(bridge.httpGet(absolute(book.url)) || "", BASE);
    return doc.select(".toc a").map(function (el) {
      var ch = SChapter.create();
      ch.url = el.attr("href");
      ch.name = el.text();
      return ch;
    });
  },

  getPageList: function (chapter) {
    var doc = Jsoup.parse(bridge.httpGet(absolute(chapter.url)) || "", BASE);
    var paragraphs = doc.select(".content p").map(function (p) { return p.text(); });
    var text = paragraphs.join("\n\n");
    return [{ index: 0, url: chapter.url, imageUrl: null, text: text, content: text }];
  }
};
