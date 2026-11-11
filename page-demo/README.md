# Project website

Static GitHub Pages site with recorded task trajectories, benchmark filters and a channel-authorization example. Assets and data are stored locally.

The browser displays records and evaluates synthetic examples. It makes no model requests or native tool calls. Twelve synthetic combinations were checked against the Python runtime. Results are recorded in `data/boundary-examples.json`.

Local preview uses `python -m http.server 8765 --bind 127.0.0.1` from this directory. JetBrains Mono uses the included OFL license.
