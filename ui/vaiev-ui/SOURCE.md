# @vaiev/ui v4 (vendored)

`tokens/tokens.css`, `tokens/components.css` and `tokens/fonts.css` are the @vaiev/ui design system v4 of
2026-10-13, byte-identical to the files vaikor.com serves under `/assets/tokens/`. The comments inside them are
upstream text and stay as published. `fonts/` holds the IBM Plex Sans and Mono subsets those stylesheets reference,
under the SIL Open Font License (`fonts/OFL-LICENSE.txt`).

`vaikor-theme.css` is the Vaikor sub-brand: the same roles filled with the accent "Sodium", dark only, as on
vaikor.com. Principle of the system: content is flat and tonal; navigation and floating controls form exactly one
glass layer; anything pressed or floating is a pill; touch targets are 48 px.

Consumers copy these files; nothing loads them from another origin:

- `companion/vaikor-companion-app/ui/vendor/` (checked to be identical by `scripts/tests/companion_ui_check.sh`)
- the vaikor.com build (`scripts/build-vaikor-site.sh` writes them to `/assets/`)

`ui/shell/` keeps its own token copy (vaiev/ui commit 0bb03ba) and its own checks.

| File | SHA-256 |
|---|---|
| `tokens/tokens.css` | `9e44019ead15b526f86e9f0fcadeddc2044e19d79487d079da0908a51c5c32af` |
| `tokens/components.css` | `9fdb3b096930a193cf9eedf557c2f41af3513dcfb04e396b6f6e3bf9ebcdf11e` |
| `tokens/fonts.css` | `401d474f479e6d7e730710b770756ae47ac069b3a25bc4de900d69791ac2103e` |
| `fonts/OFL-LICENSE.txt` | `b7281c58df5d3b75d98dfa9a6a598705042f4cd8f90b92d9edb1c2db1b8275b9` |
| `fonts/ibm-plex-mono-latin-400-normal.woff2` | `3c5a451f9ec27a354b0c2bcca636c6ec17a651281aabf29f8427e210a1d31e85` |
| `fonts/ibm-plex-mono-latin-500-normal.woff2` | `756026ff72eb76fd971ac4b7504cec55eef62109d2684c2cad8da32170b80b37` |
| `fonts/ibm-plex-sans-latin-400-normal.woff2` | `db71f8a28ad8501544fb4e7668e3c6d0b731760b6f20de3525ebaeba597f1922` |
| `fonts/ibm-plex-sans-latin-500-normal.woff2` | `5ef914e59b0047a261844d96acabb60c34d3acab6b85ea24198726ce4781fd37` |
| `fonts/ibm-plex-sans-latin-600-normal.woff2` | `31535a91ce3f6b8ed3ddedadab1e49957e2220263a640df1a3f14f6fdfe15eb6` |
