# Third-party notices shipped with REPOCACHE v0.4.0

REPOCACHE's **original code** is licensed under Apache-2.0; see the
separately distributed `LICENSE` file. This document does **not** grant
additional rights to third-party dependencies.

The authenticated v0.4.0 offline wheelhouse redistributes exact pinned
third-party binary distributions. Most original license/notice files are
already present in their unchanged `.dist-info/licenses/` directories.
The two versions below have **no license file detected at that location**
by the current wheel metadata auditor, so their **unmodified upstream**
copyright and permission notices are copied here from the corresponding
version-tagged public source repositories. This file is included **both** in the independently authenticated source
archive and the separately downloadable, SHA-256-pinned offline wheelhouse.
The wheelhouse's original third-party .whl files remain byte-for-byte
unchanged and separately hash-verified. The notice bytes must match across
both release assets before the owner can sign the candidate.

**Evidence only, not legal clearance.** Maintainers must still inspect
all exact third-party wheel contents, notices and any vendored code, confirm
the obligations for redistribution of both assets together, and record
the human approval in the v0.4.0 rights gate (#6). The file does not
replace legal review or claim that every dependency's notices are complete.

## Third-party runtime wheel inventory

| Distribution | Version | Declared license | Where to inspect license and notices |
| --- | --- | --- | --- |
| annotated-doc | 0.0.5 | MIT | unchanged wheel `.dist-info/licenses/` |
| linkify-it-py | 2.2.0 | MIT | unchanged wheel `.dist-info/licenses/` |
| markdown-it-py | 4.2.0 | MIT | unchanged wheel `.dist-info/licenses/` (multiple notices) |
| mdit-py-plugins | 0.6.1 | MIT | unchanged wheel `.dist-info/licenses/` |
| mdurl | 0.1.2 | MIT | full original-version notice copied below |
| platformdirs | 4.13.5 | MIT | unchanged wheel `.dist-info/licenses/` |
| Pygments | 2.21.0 | BSD-2-Clause | unchanged wheel `.dist-info/licenses/` (multiple notices) |
| rich | 15.0.0 | MIT | unchanged wheel `.dist-info/licenses/` |
| shellingham | 1.5.4 | ISC | full original-version notice copied below |
| textual | 8.2.8 | MIT | unchanged wheel `.dist-info/licenses/` |
| typer | 0.27.3 | MIT | unchanged wheel `.dist-info/licenses/` |
| typing_extensions | 4.16.0 | PSF-2.0 | unchanged wheel `.dist-info/licenses/` |

REPOCACHE's own `repocache-control 0.4.0` wheel includes Apache-2.0
attribution. The native v0.4.0 build also uses hash-pinned **build-only**
`setuptools 80.9.0` and `wheel 0.45.1` (declared MIT);
their wheel SHA-256 hashes and versions are in the build-tool inventory
and SBOM. They are **not** included as separate wheels in the runtime
wheelhouse; inspect the actual final package before assuming otherwise.
For the precise current wheel filenames/hashes and platform evidence,
see `deps/runtime-wheels.lock`, `deps/build-wheels.lock` and
`docs/THIRD_PARTY_RIGHTS_REVIEW.md` in the reviewed repository.

## mdurl 0.1.2 — upstream MIT license and additional upstream notice

Source: https://github.com/executablebooks/mdurl/blob/0.1.2/LICENSE

```text
Copyright (c) 2015 Vitaly Puzrin, Alex Kocharin.
Copyright (c) 2021 Taneli Hukkinen

Permission is hereby granted, free of charge, to any person
obtaining a copy of this software and associated documentation
files (the "Software"), to deal in the Software without
restriction, including without limitation the rights to use,
copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the
Software is furnished to do so, subject to the following
conditions:

The above copyright notice and this permission notice shall be
included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
OTHER DEALINGS IN THE SOFTWARE.

--------------------------------------------------------------------------------

.parse() is based on Joyent's node.js `url` code:

Copyright Joyent, Inc. and other Node contributors. All rights reserved.
Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to
deal in the Software without restriction, including without limitation the
rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
sell copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
IN THE SOFTWARE.
```

## shellingham 1.5.4 — upstream ISC license

Source: https://github.com/sarugaku/shellingham/blob/1.5.4/LICENSE

```text
Copyright (c) 2018, Tzu-ping Chung <uranusjr@gmail.com>

Permission to use, copy, modify, and distribute this software for any
purpose with or without fee is hereby granted, provided that the above
copyright notice and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
```

## Publication control

Release documentation must record that this notice is present in both the
source archive and independently downloadable wheelhouse, that the wheelhouse
and SBOM correspond to the exact approved signed release
and that no redistributed license file is removed by packaging. The notice is part of the **source archive and wheelhouse** SHA-256
identities and must fail verification if missing or changed. If the copyright owners or licensing terms in
any dependency differ from those recorded here, **stop publication and
remediate with a reviewed PR**, rather than asserting legal compliance.
