# Vendored third-party assets

Bundled locally so the generated dashboard has zero CDN/external dependencies at
report-view time (spec section 5: "Everything runs locally"). Both are MIT licensed.

| Library | Version | Files | Source |
|---|---|---|---|
| Bootstrap | 5.3.3 | `bootstrap/bootstrap.min.css`, `bootstrap/bootstrap.bundle.min.js` | https://getbootstrap.com/ |
| Chart.js | 4.4.4 | `chartjs/chart.umd.min.js` | https://www.chartjs.org/ |

Fetched from jsDelivr on 2026-07-28. `Export-SAWDashboard.ps1` copies this whole
`vendor/` directory alongside the generated `index.html` so the report output folder
is self-contained and can be zipped up and handed to a client without needing internet
access to render correctly.

To update a version: replace the file(s) above with the new release and update this
table. Do not switch to loading these from a CDN in the generated HTML - that would
reintroduce an external dependency the report shouldn't have.
