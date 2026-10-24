# Token source

The tokens in `shell.css` follow `vaiev/ui` commit `0bb03ba`, files
`tokens/tokens.css` and `tokens/fonts.css`. Custom-property names are checked
against `vaiev-ui-0bb03ba-token-names.txt`, a names-only fixture extracted from
the supplied token, font and core component stylesheets. The shell uses the
upstream light and dark values with explicit theme blocks.

The font families are IBM Plex Sans and IBM Plex Mono with the upstream system
fallback stacks. No font files or font-face rules are shipped; IBM Plex is used
only when installed locally, otherwise the system fallback applies.

The two icons remain simple placeholder SVG paths drawn for this shell.

WCAG 2.2 AA text contrast of the main token pairs is checked in `runtime/sidged-guard/tests/ui_shell.rs`.

Finding to raise with `vaiev/ui`: in the dark theme, `error` #F2716C on `error-container` #6B1B1E is 4.08:1,
below the 4.5:1 AA minimum for normal text. The values are kept as given; the shell renders status notes with
`on-surface` text and uses the status colour only for the border.
