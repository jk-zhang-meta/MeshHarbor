# The blog

Posts published at `https://meshharbor.itachi.fans/blog/<slug>/`, built by the docs generator
(`ui/docs/build.ts`, [FR-87](../../docs/fr/FR-87-blog-and-google-indexing.md)).

- **`posts/<slug>.md`** — one file per post. The file name is the URL, so it is
  kebab-case. **A file here is published**: there are no drafts. Unpublished copy
  stays in the private promo repo.
- **`assets/`** — the posts' images. A post looks here first, then in the shared
  docs artwork (`ui/docs/assets/`, `ui/src/assets/tutorial/`).

With no file in `posts/`, the site has no `/blog/` at all: no pages, no Blog
link, no feed, no sitemap entry.

## Front-matter

| Key | | |
|---|---|---|
| `title` | required | the H1; a title over 60 chars needs a `seoTitle` |
| `seoTitle` | | the whole `<title>`, at most 60 chars |
| `subtitle` | | the dek under the title |
| `description` | required | at most 160 chars |
| `date` | required | ISO 8601 timestamp with its offset, `2026-09-25T22:45:13Z`; never in the future |
| `updated` | | a timestamp, not before `date`; bump it only for a substantive edit |
| `author` | required | a key in `AUTHORS` (`ui/docs/site.ts`) |
| `tags` | required | lowercase, hyphenated |
| `hero`, `heroAlt` | | the image above the text, and what it shows. Leave it out when the first image belongs inside the text |
| `ogImage` | unless the hero is raster | the share image: PNG, JPEG or WebP, at least 1200 px wide |
| `ogImageAlt` | with `ogImage` and no hero | what the share image shows |
| `related` | | site-absolute URLs, shown as cards; each must exist |
| `syndication` | | where else it is published, e.g. the Medium copy |
| `canonical` | | only for a post whose original lives on another site |

Any other key fails the build. So do an image without alt text, a remote image,
a raw `<img>`, and a link to a page or heading that does not exist.
