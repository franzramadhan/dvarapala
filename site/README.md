# site

The GitHub Pages site, published by `.github/workflows/pages.yml` on pushes
to `main`. `index.html` is the landing page (plain HTML); `docs/` holds the
documentation pages in markdown, rendered by Jekyll with
`_layouts/doc.html`.

`build.sh` writes `docs/configuration.md`, `docs/roadmap.md` and
`docs/examples.md` from `CONFIG.md`, `ROADMAP.md` and `examples/*.toml`, so
those stay the only source. The generated files are not committed.

Preview locally:

```sh
site/build.sh
gem install jekyll kramdown-parser-gfm
jekyll serve -s site
```
