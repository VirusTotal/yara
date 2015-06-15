rule HelloWorld {
  meta:
    name = "InstallsDriver"
    description = "The file attempted to install a driver"
    categories = "Process Creation"
    type = "external"
    behaviors = "InstallsDriver"
    output = "([^\"]*)$"
    template = "%s"

  strings:
    $a = "Hello World"

  condition:
    $a
}