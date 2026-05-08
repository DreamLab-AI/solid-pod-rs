//! Mashlib / SolidOS data-browser integration.
//!
//! When a browser navigates to an RDF resource on a Solid server, the
//! `Accept: text/html` header signals that the user wants a rendered
//! view, not raw triples.  This module generates a thin HTML wrapper
//! that loads the SolidOS **mashlib** bundle (from a CDN, a local path,
//! or an ES module URL) and lets it fetch + render the underlying data.
//!
//! The approach is called the **"databrowser hack"** in the SolidOS
//! community: the server never renders RDF itself — it delegates to the
//! client-side pane system inside mashlib.
//!
//! ## Data-island optimisation
//!
//! When the resource is small enough (≤ [`DATA_ISLAND_MAX_BYTES`]), its
//! JSON-LD representation is embedded inline as a
//! `<script type="application/ld+json">` block.  A companion reader
//! script patches `$rdf.fetcher.load()` to resolve from that island
//! first, eliminating one HTTP round-trip on every page load.
//!
//! ## Modes
//!
//! | Mode | HTML template | Use case |
//! |------|---------------|----------|
//! | [`MashlibMode::Cdn`] | `<script src="unpkg.com/mashlib@{version}/…">` | Zero-config default |
//! | [`MashlibMode::Local`] | `<script defer src="/mashlib.min.js">` | Operator bundles assets with `actix-files` |
//! | [`MashlibMode::Module`] | `<script type="module" src="{url}">` | LOSOS / custom shell |

/// Cap on how much JSON-LD we inline as a data island.  256 KiB covers
/// any realistic profile, type index, or container listing.
pub const DATA_ISLAND_MAX_BYTES: usize = 256 * 1024;

// -------------------------------------------------------------------------
// Configuration
// -------------------------------------------------------------------------

/// How to load the mashlib bundle.
#[derive(Debug, Clone)]
pub enum MashlibMode {
    /// Load from unpkg CDN.  `version` is e.g. `"2.0.0"`.
    Cdn {
        version: String,
    },
    /// Serve from a local directory (operator sets up `actix-files` /
    /// `tower-http::ServeDir`).  The HTML references `/mashlib.min.js`
    /// and `/mash.css` at the server root.
    Local,
    /// ES module entry point (the LOSOS pattern).  The server emits
    /// `<div id="mashlib">` and a `<script type="module" src="{url}">`.
    Module {
        url: String,
    },
}

impl Default for MashlibMode {
    fn default() -> Self {
        Self::Cdn {
            version: "2.0.0".to_string(),
        }
    }
}

/// Mashlib integration configuration.
#[derive(Debug, Clone)]
pub struct MashlibConfig {
    pub enabled: bool,
    pub mode: MashlibMode,
    pub data_island_max_bytes: usize,
    pub round_trip_optimization: bool,
}

impl Default for MashlibConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            mode: MashlibMode::default(),
            data_island_max_bytes: DATA_ISLAND_MAX_BYTES,
            round_trip_optimization: true,
        }
    }
}

// -------------------------------------------------------------------------
// Decision: should we serve mashlib for this request?
// -------------------------------------------------------------------------

/// RDF content types that mashlib can render.
const MASHLIB_RENDERABLE: &[&str] = &[
    "text/turtle",
    "application/ld+json",
    "application/json",
    "text/n3",
    "application/n-triples",
    "application/rdf+xml",
    "text/markdown",
    "audio/mpegurl",
    "application/vnd.apple.mpegurl",
    "audio/x-scpls",
];

/// RDF types whose presence *before* `text/html` in the Accept header
/// indicates the client prefers raw RDF over an HTML wrapper.
const RDF_ACCEPT_TYPES: &[&str] = &[
    "application/rdf+xml",
    "text/turtle",
    "application/ld+json",
    "text/n3",
    "application/n-triples",
];

/// Determine whether the server should return the mashlib HTML wrapper
/// instead of the raw resource body.
///
/// The decision mirrors JSS `mashlib/index.js::shouldServeMashlib`:
///
/// 1. `enabled` must be true.
/// 2. `Sec-Fetch-Dest` (when present) must be `document` — this
///    distinguishes top-level browser navigation from `fetch()` / XHR.
/// 3. `Accept` must include `text/html` and no RDF type may appear
///    before it (otherwise the client prefers raw data).
/// 4. The resource's stored content type must be renderable by mashlib.
pub fn should_serve(
    accept: &str,
    sec_fetch_dest: Option<&str>,
    resource_content_type: &str,
    enabled: bool,
) -> bool {
    if !enabled {
        return false;
    }

    if let Some(dest) = sec_fetch_dest {
        if !dest.is_empty() && dest != "document" {
            return false;
        }
    }

    if !accept.contains("text/html") {
        return false;
    }

    let html_pos = match accept.find("text/html") {
        Some(p) => p,
        None => return false,
    };
    for rdf_type in RDF_ACCEPT_TYPES {
        if let Some(pos) = accept.find(rdf_type) {
            if pos < html_pos {
                return false;
            }
        }
    }

    let base_type = resource_content_type
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    MASHLIB_RENDERABLE.contains(&base_type.as_str())
}

// -------------------------------------------------------------------------
// Data-island escaping
// -------------------------------------------------------------------------

/// Escape a JSON-LD string for embedding inside
/// `<script type="application/ld+json">`.
///
/// Replaces every literal `<` with the JSON unicode escape `<`.
/// The HTML parser scans raw bytes for `</script` — by eliminating all
/// `<` bytes we guarantee no end-tag can form.  JSON-LD parsers decode
/// `<` back to `<` natively, so document semantics are preserved.
pub fn escape_for_script_block(json_ld: &str) -> String {
    json_ld.replace('<', "\\u003c")
}

/// Build the `<script type="application/ld+json">` data-island block.
///
/// Returns an empty string when `json_ld` is `None` or exceeds the
/// byte cap (checked both pre- and post-escape).
fn data_island(resource_url: &str, json_ld: Option<&str>, max_bytes: usize) -> String {
    let raw = match json_ld {
        Some(s) if !s.is_empty() => s,
        _ => return String::new(),
    };
    if raw.len() > max_bytes {
        return String::new();
    }
    let safe_body = escape_for_script_block(raw);
    if safe_body.len() > max_bytes {
        return String::new();
    }
    let safe_uri = escape_html(resource_url);
    format!(
        r#"<script type="application/ld+json" id="dataisland" data-uri="{safe_uri}">{safe_body}</script>"#
    )
}

// -------------------------------------------------------------------------
// Round-trip optimisation reader
// -------------------------------------------------------------------------

/// Inline `<script>` that patches `$rdf.fetcher.load()` to resolve from
/// the data island before hitting the network.  Three detection paths
/// cover the full timing space (synchronous, setter, polling).
fn round_trip_script() -> &'static str {
    r#"<script>
(function(){
  if(typeof window==='undefined')return;
  var di=window.__dataIsland;
  if(di===null||di===undefined||(typeof di!=='object'&&typeof di!=='function'))di=window.__dataIsland={};
  if(typeof di.get!=='function'){
    di.get=function(uri){
      if(!uri)return null;
      try{var el=document.getElementById('dataisland');
        if(el&&el.type==='application/ld+json'&&el.getAttribute('data-uri')===String(uri))
          return{contentType:'application/ld+json',content:el.textContent};
      }catch(e){}return null;
    };
  }
  function patch(rdf){
    if(!rdf||!rdf.fetcher||!rdf.fetcher.load)return;
    if(rdf.fetcher.__diPatched)return;rdf.fetcher.__diPatched=true;
    var f=rdf.fetcher,orig=f.load.bind(f);
    f.load=function(uri,opts){
      var s=(uri&&uri.uri)||(uri&&uri.value)||String(uri);
      var d=window.__dataIsland.get(s);
      if(d)return new Promise(function(ok,fail){
        rdf.parse(d.content,f.store,s,d.contentType,function(err){
          if(err){fail(err);return;}
          try{if(f.requested&&typeof f.requested==='object')f.requested[s]='done';
            var r=typeof Response==='function'?new Response(d.content,{status:200,headers:{'content-type':d.contentType}}):{ok:true,status:200,url:s,headers:{get:function(n){return n&&n.toLowerCase()==='content-type'?d.contentType:null}}};
            try{Object.defineProperty(r,'url',{value:s,configurable:true})}catch(e){}ok(r);
          }catch(e){fail(e);}
        });
      }).catch(function(){return orig(uri,opts);});
      return orig(uri,opts);
    };
  }
  if(typeof $rdf!=='undefined')patch($rdf);
  try{var c=typeof $rdf!=='undefined'?$rdf:undefined;
    Object.defineProperty(window,'$rdf',{configurable:true,get:function(){return c;},set:function(v){c=v;patch(v);}});
  }catch(e){}
  var n=0;(function p(){if(++n>100)return;if(typeof $rdf!=='undefined'&&$rdf&&$rdf.fetcher&&$rdf.fetcher.__diPatched)return;if(typeof $rdf!=='undefined')patch($rdf);setTimeout(p,100);})();
})();
</script>"#
}

// -------------------------------------------------------------------------
// HTML generators
// -------------------------------------------------------------------------

/// Generate the mashlib HTML wrapper page.
///
/// When `embed_json_ld` is provided and within the byte cap, it is
/// inlined as a data island for the round-trip optimisation.
pub fn generate_html(
    resource_url: &str,
    config: &MashlibConfig,
    embed_json_ld: Option<&str>,
) -> String {
    let island = data_island(resource_url, embed_json_ld, config.data_island_max_bytes);
    let reader = if config.round_trip_optimization {
        round_trip_script()
    } else {
        ""
    };

    match &config.mode {
        MashlibMode::Cdn { version } => {
            let base = format!("https://unpkg.com/mashlib@{version}/dist");
            format!(
                r#"<!doctype html><html><head><meta charset="utf-8"/><title>SolidOS Web App</title>
<link href="{base}/mash.css" rel="stylesheet"></head>
<body id="PageBody">{island}{reader}<header id="PageHeader"></header>
<div class="TabulatorOutline" id="DummyUUID" role="main"><table id="outline"></table><div id="GlobalDashboard"></div></div>
<footer id="PageFooter"></footer>
<script>
(function(){{var s=document.createElement('script');s.src='{base}/mashlib.min.js';s.onload=function(){{panes.runDataBrowser()}};s.onerror=function(){{document.body.innerHTML='<p>Failed to load Mashlib from CDN</p>'}};document.head.appendChild(s)}})();
</script></body></html>"#
            )
        }
        MashlibMode::Local => {
            format!(
                r#"<!doctype html><html><head><meta charset="utf-8"/><title>SolidOS Web App</title><script>document.addEventListener('DOMContentLoaded',function(){{panes.runDataBrowser()}})</script><script defer="defer" src="/mashlib.min.js"></script><link href="/mash.css" rel="stylesheet"></head><body id="PageBody">{island}{reader}<header id="PageHeader"></header><div class="TabulatorOutline" id="DummyUUID" role="main"><table id="outline"></table><div id="GlobalDashboard"></div></div><footer id="PageFooter"></footer></body></html>"#
            )
        }
        MashlibMode::Module { url } => {
            let css_url = if url.ends_with(".js") {
                format!("{}.css", &url[..url.len() - 3])
            } else {
                format!("{url}.css")
            };
            format!(
                r#"<!doctype html><html lang="en"><head><meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Solid Data Browser</title>
<link rel="stylesheet" href="{css_url}"></head>
<body>{island}{reader}<div id="mashlib"></div>
<script type="module" src="{url}"></script>
</body></html>"#
            )
        }
    }
}

// -------------------------------------------------------------------------
// Utilities
// -------------------------------------------------------------------------

fn escape_html(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

// -------------------------------------------------------------------------
// Tests
// -------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn default_cdn_config() -> MashlibConfig {
        MashlibConfig {
            enabled: true,
            ..Default::default()
        }
    }

    // -- should_serve -------------------------------------------------------

    #[test]
    fn serves_html_for_browser_navigation() {
        assert!(should_serve(
            "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            Some("document"),
            "text/turtle",
            true,
        ));
    }

    #[test]
    fn rejects_when_disabled() {
        assert!(!should_serve("text/html", Some("document"), "text/turtle", false));
    }

    #[test]
    fn rejects_xhr_fetch() {
        assert!(!should_serve("text/html", Some("empty"), "text/turtle", true));
    }

    #[test]
    fn rejects_no_html_in_accept() {
        assert!(!should_serve(
            "application/ld+json, */*;q=0.1",
            None,
            "text/turtle",
            true,
        ));
    }

    #[test]
    fn rejects_rdf_preferred_over_html() {
        assert!(!should_serve(
            "text/turtle, text/html;q=0.5",
            None,
            "text/turtle",
            true,
        ));
    }

    #[test]
    fn rejects_non_renderable_content_type() {
        assert!(!should_serve(
            "text/html",
            Some("document"),
            "image/png",
            true,
        ));
    }

    #[test]
    fn accepts_jsonld_content_type() {
        assert!(should_serve(
            "text/html",
            Some("document"),
            "application/ld+json; charset=utf-8",
            true,
        ));
    }

    #[test]
    fn accepts_markdown_content_type() {
        assert!(should_serve(
            "text/html",
            Some("document"),
            "text/markdown",
            true,
        ));
    }

    #[test]
    fn accepts_absent_sec_fetch_dest() {
        assert!(should_serve("text/html", None, "text/turtle", true));
    }

    // -- escape_for_script_block -------------------------------------------

    #[test]
    fn escapes_angle_brackets() {
        let input = r#"{"@id": "</script>"}"#;
        let escaped = escape_for_script_block(input);
        assert!(!escaped.contains('<'));
        assert!(escaped.contains("\\u003c"));
    }

    // -- data_island -------------------------------------------------------

    #[test]
    fn island_empty_when_none() {
        assert!(data_island("http://x", None, DATA_ISLAND_MAX_BYTES).is_empty());
    }

    #[test]
    fn island_empty_when_oversized() {
        let big = "x".repeat(DATA_ISLAND_MAX_BYTES + 1);
        assert!(data_island("http://x", Some(&big), DATA_ISLAND_MAX_BYTES).is_empty());
    }

    #[test]
    fn island_contains_json_ld_type() {
        let island = data_island("http://x/r", Some(r#"{"@id":"x"}"#), DATA_ISLAND_MAX_BYTES);
        assert!(island.contains("application/ld+json"));
        assert!(island.contains("dataisland"));
    }

    // -- generate_html -----------------------------------------------------

    #[test]
    fn cdn_mode_references_unpkg() {
        let cfg = default_cdn_config();
        let html = generate_html("http://pod/resource", &cfg, None);
        assert!(html.contains("unpkg.com/mashlib@2.0.0"));
        assert!(html.contains("mashlib.min.js"));
        assert!(html.contains("mash.css"));
    }

    #[test]
    fn local_mode_uses_root_relative_paths() {
        let cfg = MashlibConfig {
            enabled: true,
            mode: MashlibMode::Local,
            ..Default::default()
        };
        let html = generate_html("http://pod/resource", &cfg, None);
        assert!(html.contains(r#"src="/mashlib.min.js""#));
        assert!(html.contains(r#"href="/mash.css""#));
    }

    #[test]
    fn module_mode_emits_mashlib_div() {
        let cfg = MashlibConfig {
            enabled: true,
            mode: MashlibMode::Module {
                url: "https://host/path/mashlib.js".into(),
            },
            ..Default::default()
        };
        let html = generate_html("http://pod/resource", &cfg, None);
        assert!(html.contains(r#"id="mashlib""#));
        assert!(html.contains(r#"type="module""#));
        assert!(html.contains("https://host/path/mashlib.js"));
        assert!(html.contains("https://host/path/mashlib.css"));
    }

    #[test]
    fn embeds_data_island_when_provided() {
        let cfg = default_cdn_config();
        let json_ld = r#"{"@id":"http://pod/r","@type":"foaf:Person"}"#;
        let html = generate_html("http://pod/r", &cfg, Some(json_ld));
        assert!(html.contains("dataisland"));
        assert!(html.contains("foaf:Person"));
    }

    #[test]
    fn round_trip_script_present_by_default() {
        let cfg = default_cdn_config();
        let html = generate_html("http://pod/r", &cfg, Some("{}"));
        assert!(html.contains("__dataIsland"));
    }

    #[test]
    fn round_trip_script_absent_when_disabled() {
        let cfg = MashlibConfig {
            enabled: true,
            round_trip_optimization: false,
            ..Default::default()
        };
        let html = generate_html("http://pod/r", &cfg, Some("{}"));
        assert!(!html.contains("__dataIsland"));
    }
}
