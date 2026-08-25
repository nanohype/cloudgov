# strip-comments.awk — blank out comments while preserving line numbering.
#
# Every text-matching gate in this repo needs this, and needs it for the same
# reason. A gate that reads comments as code fails in exactly the case it exists
# for: the thing standing where a missing implementation should be is very often
# a comment saying so, and the token a gate excludes on is very often mentioned
# in a trailing comment beside the violation it was meant to catch.
#
# Comment bodies are replaced by spaces rather than removed, so a reported line
# number still points at the right source line and a `next`-style skip cannot
# swallow code sharing the line with a comment.
#
# Quote-aware: a comment marker inside a string literal is not a comment. Go raw
# strings (backticks) and both quote styles are honoured. Escapes are respected
# inside double quotes.
#
# Usage: awk -v style=go|hash|css [-v strings=blank] -f strip-comments.awk <file>
#
#   go    // and /* */, respecting "..." '...' `...`
#   hash  #, respecting "..." '...'      (YAML, shell, JSON-with-comments)
#   css   /* */ only
#
# The styles differ only in which markers open a comment; the quoting machinery
# is shared, because that is the half a hand-rolled stripper gets wrong.
#
# strings=blank additionally empties string bodies, keeping the delimiters. Use
# it where the gate looks for a CALL or a DECLARATION: a token inside a string
# literal is neither, so matching it is a false positive. Leave it off where the
# string content is the subject — a URL, a required tag key, a template name.

BEGIN {
  if (style == "") style = "hash"
}

{
  line = $0
  out = ""
  i = 1
  n = length(line)

  while (i <= n) {
    c = substr(line, i, 1)
    two = substr(line, i, 2)

    # Inside a block comment, consume until it closes.
    if (inblock) {
      if (two == "*/") { inblock = 0; out = out "  "; i += 2; continue }
      out = out " "
      i++
      continue
    }

    # Inside a string literal, copy through until it closes.
    if (instr) {
      if (quote == "\"" && c == "\\" && i < n) {
        out = out (strings == "blank" ? "  " : c substr(line, i + 1, 1))
        i += 2
        continue
      }
      if (c == quote) { instr = 0; out = out c; i++; continue }
      out = out (strings == "blank" ? " " : c)
      i++
      continue
    }

    # A raw string may span lines; a quoted one may not, so an unterminated
    # quote ends with the line rather than swallowing the file.
    if (inraw) {
      if (c == "`") { inraw = 0; out = out c; i++; continue }
      out = out (strings == "blank" ? " " : c)
      i++
      continue
    }

    if (style == "go" || style == "css") {
      if (two == "/*") { inblock = 1; out = out "  "; i += 2; continue }
    }
    if (style == "go") {
      if (two == "//") { while (i <= n) { out = out " "; i++ }; continue }
      if (c == "`") { inraw = 1; out = out c; i++; continue }
    }
    if (style == "hash") {
      if (c == "#") { while (i <= n) { out = out " "; i++ }; continue }
    }

    if (style != "css" && (c == "\"" || c == "'")) {
      instr = 1; quote = c; out = out c; i++; continue
    }

    out = out c
    i++
  }

  # A quoted string does not continue onto the next line.
  instr = 0
  print out
}
