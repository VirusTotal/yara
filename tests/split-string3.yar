rule t {
strings:
  $str = "ab" // comment
         "cd"
condition:
  all of them
}
