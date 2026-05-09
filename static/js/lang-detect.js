(function () {
  var KEY = 'lang-pref';
  var isEnPage = location.pathname.startsWith('/en/') || location.pathname === '/en';
  var pref = null;
  try { pref = localStorage.getItem(KEY); } catch (e) {}

  if (pref === 'en' && !isEnPage) {
    location.replace('/en' + location.pathname);
    return;
  }
  if (pref === 'zh' && isEnPage) {
    location.replace(location.pathname.replace(/^\/en\/?/, '/'));
    return;
  }

  if (!pref) {
    var lang = (navigator.language || '').toLowerCase();
    if (!lang.startsWith('zh') && !isEnPage) {
      location.replace('/en' + location.pathname);
      return;
    }
  }

  document.addEventListener('click', function (e) {
    var link = e.target.closest('.lang-switch');
    if (!link) return;
    var href = link.getAttribute('href');
    try {
      localStorage.setItem(KEY, href.startsWith('/en') ? 'en' : 'zh');
    } catch (e) {}
  });
})();
