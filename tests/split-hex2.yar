rule t {
strings:
  $hex = { 41 42 } /* comment */ { 43 44 }
condition:
  all of them
}
