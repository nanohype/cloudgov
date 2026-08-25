# blank-heredocs.awk — empty heredoc bodies, preserving line numbering.
#
# A heredoc body is not the code of the script that writes it. A gate that plants
# a fixture writes it as a heredoc, and the constructs inside belong to the file
# being written — so a scanner reading them as uses makes a gate unable to carry
# a fixture for the rule it enforces.
#
# Lines are blanked rather than removed so a citation still names the line the
# reader will find in the source.
#
# Usage: awk -f blank-heredocs.awk <file>

delim != "" {
  stripped = $0
  sub(/^[[:space:]]+/, "", stripped)
  # <<- permits a tab-indented delimiter; << requires it at column one. Accepting
  # the indented form under both is the safe direction: ending a body early
  # exposes real code to the scanner, and running past the end hides it.
  if ($0 == delim || stripped == delim) {
    delim = ""
    print ""
    next
  }
  print ""
  next
}

{
  line = $0
  if (match(line, /<<-?[[:space:]]*['"]?[A-Za-z_][A-Za-z0-9_]*['"]?/)) {
    tag = substr(line, RSTART, RLENGTH)
    sub(/^<<-?[[:space:]]*/, "", tag)
    gsub(/['"]/, "", tag)
    delim = tag
  }
  print line
}
