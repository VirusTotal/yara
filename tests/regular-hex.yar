rule t {
strings:
  $hex = { 31 32 33 34 }
condition:
  all of them
}
