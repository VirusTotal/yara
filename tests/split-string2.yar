rule t {
strings:
  $str = "AB" /* comment */ "CD"
condition:
  all of them
}
