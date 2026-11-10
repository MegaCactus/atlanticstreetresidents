# 355 Atlantic Street maintenance record

A residents' record of maintenance at 355 Atlantic Street, Stamford, compiled from the building's own notices and from tickets residents have shared. The site is a single static page; the data lives in data/incidents.json.

Nothing here identifies a unit or a person. Resident tickets are shown by month and floor range only.

## Files

- `index.html`, `submit.html`: the site, served by GitHub Pages.
- `data/incidents.json`: the archived record. Each row has a fixed `id`, so its link never changes.
- `api/worker.js`: the Cloudflare Worker behind api.atlanticstreetresidents.com. It also answers three paths on the site's own address: `/` (the homepage, with the record written into it), `/entry/*` (a page per entry) and `/sitemap.xml`. Without those routes the site still works; `sitemap.xml` here is the fallback.
- `api/gen-site.mjs`: copies the parts of `index.html` that the Worker needs into `api/worker.js`. Run `node api/gen-site.mjs` after changing `index.html`.
