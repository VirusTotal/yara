rule t {
strings:
  $str = "12" "34"
condition:
  all of them
}
