// Async (JSON API) template: hooks may return Promises and use the non-blocking bridge.net.fetch.
// Modules are allowed: build bundles imports into one script.
import { toManga } from "./mapping.js";

var API = "https://api.example.com";

async function getJson(path) {
  var res = await bridge.net.fetch(API + path, { method: "GET", headers: { Accept: "application/json" } });
  if (res.status !== 200) throw new Error("SHINSOU_SOURCE_HTTP_UNAVAILABLE");
  return JSON.parse(res.body);
}

var source = {
  baseUrl: "https://example.com",
  supportsLatest: false,

  getPopularManga: async function (page) {
    var data = await getJson("/titles?sort=popular&page=" + page);
    return new MangasPage(data.items.map(toManga), data.hasNext);
  },

  getSearchManga: async function (page, query) {
    var data = await getJson("/titles?q=" + encodeURIComponent(query) + "&page=" + page);
    return new MangasPage(data.items.map(toManga), data.hasNext);
  },

  getMangaDetails: async function (manga) {
    var data = await getJson("/titles/" + encodeURIComponent(manga.url));
    var m = toManga(data);
    m.description = data.description || null;
    m.initialized = true;
    return m;
  },

  getChapterList: async function (manga) {
    var data = await getJson("/titles/" + encodeURIComponent(manga.url) + "/chapters");
    return data.items.map(function (c) {
      var ch = SChapter.create();
      ch.url = c.id;
      ch.name = c.title;
      ch.chapterNumber = c.number;
      return ch;
    });
  },

  getPageList: async function (chapter) {
    var data = await getJson("/chapters/" + encodeURIComponent(chapter.url) + "/pages");
    return data.pages.map(function (url, i) { return new Page(i, "", url); });
  }
};
