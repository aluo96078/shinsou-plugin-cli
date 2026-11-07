export function toManga(item) {
  var m = SManga.create();
  m.url = String(item.id);
  m.title = item.title;
  m.thumbnailUrl = item.cover || null;
  return m;
}
