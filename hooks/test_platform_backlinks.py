"""Regression tests for the platform doorway hook (hooks/platform_backlinks.py).

Run:  python3 hooks/test_platform_backlinks.py
      (or: python3 -m unittest discover -s hooks -p 'test_*.py')

The strict build proves the links resolve. What it cannot prove is that the
right pages get chips and the wrong ones do not — a Core header quietly
labelled with a platform, or a platform page silently missing its doorway,
builds perfectly well.
"""

import glob
import os
import sys
import types
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import platform_backlinks as h  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONFIG = {"config_file_path": os.path.join(ROOT, "mkdocs.yml")}


def page_of(src_uri):
    return types.SimpleNamespace(file=types.SimpleNamespace(src_uri=src_uri))


def render(src_uri, markdown="# Title\n\nBody.\n"):
    return h.on_page_markdown(markdown, page_of(src_uri), CONFIG, None)


class GeneratedApiPages(unittest.TestCase):
    def test_a_platform_header_is_labelled_with_its_platform(self):
        out = render("api/SolidSyslogMbedTlsStream_8h.md")
        self.assertIn("[Mbed TLS platform](../platforms/mbedtls/index.md){ .ss-chip .ss-chip--platform }", out)

    def test_the_label_is_the_platform_pages_own_heading(self):
        # Not the registry token, which is "LwipRaw".
        self.assertIn("[lwIP (Raw API) platform]", render("api/SolidSyslogLwipRawTcpStream_8h.md"))

    def test_a_platform_data_structure_is_labelled_too(self):
        out = render("api/structSolidSyslogMbedTlsStreamConfig.md")
        self.assertIn("[Mbed TLS platform](../platforms/mbedtls/index.md)", out)

    def test_a_core_data_structure_is_not_labelled(self):
        # Only the platform Interface directories are scanned, so a Core struct
        # cannot pick up a platform label.
        markdown = "# Config\n\nBody.\n"
        self.assertEqual(render("api/structSolidSyslogConfig.md", markdown), markdown)

    def test_a_forward_declaration_does_not_claim_the_struct(self):
        # SolidSyslogMbedTlsStream.h forward-declares struct SolidSyslogStream;
        # only definitions map, or Core's Stream would be labelled Mbed TLS.
        headers, _slugs, _labels, _manifest = h._index(CONFIG)
        self.assertNotIn("SolidSyslogStream", headers)

    def test_a_core_header_is_not_labelled(self):
        markdown = "# Core\n\nBody.\n"
        self.assertEqual(render("api/SolidSyslogConfig_8h.md", markdown), markdown)

    def test_a_generated_index_is_not_labelled(self):
        markdown = "# Files\n"
        self.assertEqual(render("api/files.md", markdown), markdown)


class PlatformPages(unittest.TestCase):
    def test_chips_go_under_the_title_not_above_it(self):
        out = render("platforms/mbedtls/index.md")
        self.assertTrue(out.startswith("# Title\n\n["), out[:40])

    def test_a_platform_with_a_setup_guide_gets_the_setup_chip(self):
        out = render("platforms/mbedtls/index.md")
        self.assertIn("[Setup](setup.md){ .ss-chip .ss-chip--setup }", out)

    def test_no_chip_points_at_a_group_page(self):
        # The groups are dropped from the build; a chip to one would 404.
        for slug in h._index(CONFIG)[1]:
            self.assertNotIn("group__platform__", render(f"platforms/{slug}/index.md"), slug)

    def test_every_platform_has_its_setup_chip_today(self):
        _, slugs, _labels, _manifest = h._index(CONFIG)
        for slug in slugs:
            self.assertIn(".ss-chip--setup", render(f"platforms/{slug}/index.md"), slug)

    def test_the_setup_chip_appears_only_when_the_page_does(self):
        # Every platform has a setup page now, so the absent case has to be
        # constructed. The chip must never point at a page that is not there.
        root = os.path.dirname(CONFIG["config_file_path"])
        headers, slugs, labels, manifest = h._index(CONFIG)
        h._CACHE[root] = (headers, {**slugs, "posix": False}, labels, manifest)
        try:
            out = render("platforms/posix/index.md")
        finally:
            h._CACHE.pop(root, None)
        self.assertNotIn(".ss-chip--setup", out)

    def test_the_platforms_overview_is_not_a_platform(self):
        markdown = "# Platforms\n\nBody.\n"
        self.assertEqual(render("platforms/index.md", markdown), markdown)

    def test_a_setup_page_gets_a_chip_back_to_its_platform(self):
        out = render("platforms/mbedtls/setup.md", "# Mbed TLS setup\n\nBody.\n")
        self.assertIn("[Mbed TLS platform](index.md){ .ss-chip .ss-chip--platform }", out)

    def test_the_back_chip_goes_under_the_title(self):
        out = render("platforms/mbedtls/setup.md", "# Mbed TLS setup\n\nBody.\n")
        self.assertTrue(out.startswith("# Mbed TLS setup\n\n["), out[:40])

    def test_every_setup_page_can_get_back_to_its_platform(self):
        _, slugs, _labels, _manifest = h._index(CONFIG)
        for slug in slugs:
            out = render(f"platforms/{slug}/setup.md", "# Setup\n\nBody.\n")
            self.assertIn("(index.md){ .ss-chip .ss-chip--platform }", out, slug)

    def test_an_ordinary_page_is_untouched(self):
        markdown = "# Porting\n\nBody.\n"
        self.assertEqual(render("porting.md", markdown), markdown)


class ShipsManifest(unittest.TestCase):
    """The *What it ships* table is generated from the platform's own headers,
    so a header added to a pack cannot go unlisted and a brief cannot go stale."""

    PAGE = "# Mbed TLS\n\nIntro.\n\n## What it ships\n\n## Requirements\n\nNeeds things.\n"

    def ships(self, slug="mbedtls", markdown=None):
        body = render(f"platforms/{slug}/index.md", markdown or self.PAGE)
        return body.split("## What it ships")[1].split("## ")[0]

    def test_every_header_is_listed_by_filename(self):
        table = self.ships()
        for name in ("SolidSyslogMbedTlsStream.h", "SolidSyslogMbedTlsAesGcmPolicy.h",
                     "SolidSyslogMbedTlsHmacSha256Policy.h"):
            self.assertIn(f"[`{name}`]", table)

    def test_error_headers_are_listed_too(self):
        # The group page listed these; nothing else on the platform route did.
        self.assertIn("[`SolidSyslogMbedTlsStreamErrors.h`]", self.ships())

    def test_a_filename_links_to_its_generated_page(self):
        self.assertIn("(../../api/SolidSyslogMbedTlsStream_8h.md)", self.ships())

    def test_the_brief_is_the_headers_own_first_sentence(self):
        self.assertIn(
            "Source identity for the MbedTlsStream adapter; the detail codes it reports are"
            " the portable ones in SolidSyslogTlsStreamErrors.h.",
            self.ships(),
        )

    def test_a_brief_naming_a_standard_header_keeps_it(self):
        # <stdatomic.h> is an HTML tag to the Markdown renderer, so unescaped it
        # vanished and took the sentence's sense with it.
        self.assertIn("C11 &lt;stdatomic.h&gt;", self.ships("stdatomic"))

    def test_a_cell_escapes_what_would_break_it(self):
        self.assertEqual(h._cell("a <b> c | d & e"), r"a &lt;b&gt; c \| d &amp; e")

    def test_a_multi_sentence_brief_stops_at_the_first_sentence(self):
        row = [line for line in self.ships("stdatomic").splitlines()
               if "SolidSyslogStdAtomicCounter.h" in line]
        self.assertEqual(len(row), 1)
        self.assertIn("backing the RFC 5424 sequenceId.", row[0])
        self.assertNotIn("Increment runs", row[0])

    def test_the_heading_survives_and_the_body_is_replaced(self):
        out = render("platforms/mbedtls/index.md", self.PAGE)
        self.assertIn("## What it ships", out)
        self.assertIn("## Requirements", out)
        self.assertIn("Needs things.", out)

    def test_every_platform_lists_every_header_it_ships(self):
        root = os.path.dirname(CONFIG["config_file_path"])
        _, _slugs, _labels, manifest = h._index(CONFIG)
        for slug, entries in manifest.items():
            interface = glob.glob(os.path.join(root, "Platform", "*", "Interface"))
            interface = [p for p in interface if os.path.basename(os.path.dirname(p)).lower() == slug]
            expected = sorted(n[: -len(".h")] for n in os.listdir(interface[0]) if n.endswith(".h"))
            self.assertEqual(sorted(stem for stem, _ in entries), expected, slug)

    def test_a_pipe_in_a_brief_cannot_break_the_table(self):
        self.assertNotIn("| |", h._ships([("X", "a | b")]).splitlines()[-1].replace("| X", ""))


class DroppedGroupPages(unittest.TestCase):
    """A platform answers "what is this" in one place. The group pages said it
    a second time, worse, so they never reach the site."""

    def files_after(self, *src_uris):
        kept = h.on_files([types.SimpleNamespace(src_uri=u) for u in src_uris], CONFIG)
        return [f.src_uri for f in kept]

    def test_every_group_page_is_dropped(self):
        _, slugs, _labels, _manifest = h._index(CONFIG)
        pages = [f"api/group__platform__{slug}.md" for slug in slugs]
        self.assertEqual(self.files_after(*pages), [])

    def test_the_modules_index_goes_with_them(self):
        # It exists only to list the groups, so it would link ten dead pages.
        self.assertEqual(self.files_after("api/modules.md"), [])

    def test_a_header_page_is_kept(self):
        self.assertEqual(
            self.files_after("api/SolidSyslogMbedTlsStream_8h.md"),
            ["api/SolidSyslogMbedTlsStream_8h.md"],
        )

    def test_a_platform_page_is_kept(self):
        self.assertEqual(self.files_after("platforms/mbedtls/index.md"), ["platforms/mbedtls/index.md"])

    def test_a_similarly_named_page_is_not_caught(self):
        # group__platform__* only — a Core group, were one added, would stay.
        self.assertEqual(self.files_after("api/group__core.md"), ["api/group__core.md"])

    def test_the_index_of_indexes_stops_linking_modules(self):
        raw = "  - [Related Pages](pages.md)\n  - [Modules](modules.md)\n  - [Files](files.md)\n"
        out = render("api/links.md", raw)
        self.assertNotIn("modules.md", out)
        self.assertIn("[Files](files.md)", out)
        self.assertIn("[Related Pages](pages.md)", out)


class Registry(unittest.TestCase):
    def test_every_registered_platform_has_a_docs_folder(self):
        _, slugs, _labels, _manifest = h._index(CONFIG)
        for slug in slugs:
            self.assertTrue(
                os.path.isfile(os.path.join(ROOT, "docs", "platforms", slug, "index.md")),
                f"registry names {slug} but docs/platforms/{slug}/index.md is missing",
            )

    def test_the_registry_yields_all_ten_platforms(self):
        _, slugs, _labels, _manifest = h._index(CONFIG)
        self.assertEqual(len(slugs), 10, sorted(slugs))


if __name__ == "__main__":
    unittest.main()
