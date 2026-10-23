"""Repair exact upstream SmPL defects in private copies, retaining the changes."""

import hashlib


def adapt(rule, text):
    original = text
    digest = hashlib.sha256(original.encode()).hexdigest()
    changes = []
    if (rule.name == "add_namespace.cocci" and digest ==
            "0315f99b173db1169fb955717b630b82d3cf93c6d6bc292271c5cd4b15711dbd"):
        # This wrapper only runs report mode. The namespace transformation has
        # no report diagnostics, but its declarer changes parsing even when
        # nsdeps is disabled and makes a real #undef MODULE_IMPORT_NS fail.
        # Retain the report clause and parse every original source as usual.
        start = text.index("@has_ns_import@")
        end = text.index("// Dummy rule for report mode")
        text = text[:start] + text[end:]
        changes.append("Omit nsdeps-only clauses from the dummy namespace report rule.")
    if rule.name == "stream_open.cocci":
        anchor = "@ stream_reader @\n"
        symbols = "symbol noop_llseek, nonseekable_open;\n"
        if text.count(anchor) == 1 and symbols not in text:
            text = text.replace(anchor, anchor + symbols, 1)
            changes.append("Declare noop_llseek/nonseekable_open as literal symbols.")
        empty = ("@ has_no_llseek @\nidentifier fops0.fops;\n@@\n"
                 "  struct file_operations fops = {\n  };\n\n")
        if text.count(empty) == 1 and text.count(" || has_no_llseek") == 1:
            text = text.replace(empty, "").replace(" || has_no_llseek", "")
            changes.append("Remove the empty has_no_llseek alternative matching custom seekers.")
    return text, {"source": str(rule),
                  "source_sha256": digest,
                  "adapted_sha256": hashlib.sha256(text.encode()).hexdigest(),
                  "changes": changes}
