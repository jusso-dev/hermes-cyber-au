# Pins

Checked on 2026-10-08.

- Oh My Hermes: `d17ce54816fcc90e5ef8e662135871f75580f65b`
- Hermes agent main at the time the docs were read: `3f97b91aae2bc9a3d533634d54039018e1d224ec`
- Plugin APIs used here match the Hermes build that exposes `register_tool`, `register_skill`, and `register_cli_command`. This pack was not installed into a live Hermes home during development.
- ISM OSCAL June 2026: `d3bd1735a992a988d3e4e337b3e41f856a76368e`
- ISM OSCAL September 2026: `9f77120a7f8671c73da02431cdc299fac264edab`

The daily job resolves `ism-oscal` main. If that SHA is newer than the current pin, the refresh branch adds the snapshot. Merging the pull request is the pin update.
