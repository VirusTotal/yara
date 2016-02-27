rule t {
strings:
  $hex = { 61 62 } // comment
         { 63 64 }
condition:
  all of them
}
