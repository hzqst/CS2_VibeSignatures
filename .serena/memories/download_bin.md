# download_bin

## Overview
Downloads CS2 binary files from AlliedMods SourceBins, stores them by version/module directories based on module configuration in `config.yaml`, supports platform filtering, and outputs a summary.

## Responsibilities
- Parse command-line arguments and validate the configuration file.
- Read the module list from `config.yaml` and normalize module metadata.
- Build download URLs for each module/platform, download files, and save them to disk.
- Count success/failure totals and reflect results via exit code.

## Files Involved (no line numbers)
- download_bin.py
- config.yaml

## Architecture
Overall flow is a single-script serial pipeline:
```
parse_args
  -> parse_config (load modules)
    -> for each module
        -> process_module
            -> build_download_url
            -> download_file (GET and write to bin_dir/gamever/module/filename)
  -> summarize success/failure and decide exit code
```
Key points: `process_module` handles platform selection, target path assembly, and skipping existing files; `download_file` first reads the response into memory, then writes to disk to avoid corruption from partial downloads.

## Dependencies
- PyYAML (`yaml.safe_load`)
- requests (HTTP downloads)
- File system access (create directories/write files)
- External network resource: SourceBins base URL (default `https://sourcebins.alliedmods.net/cs2`)

## Notes
- `download_file` reads full content into memory before writing; large files may consume more memory.
- Existing target files are skipped directly (counted as success).
- If `config.yaml` is missing, the script exits immediately; module entries missing `name` are skipped.
- If any download fails, exit code is 1; if there are no modules, exit code is 0.

## Callers (optional)
- Direct CLI invocation: `python download_bin.py -gamever=<version> ...`