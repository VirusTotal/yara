Generating a module from a Protocol Buffer


[Protocol Buffers](https://developers.google.com/protocol-buffers) (protobufs)
are Google's language-neutral, platform-idependent mechanism for serializing
structured data. The first thing you need to do for using protobuf is defining
your data structures, for example:

message Employee {
  int32 id = 1;
  string name = 2;
  int32 age = 3
  string email = 4;
}

Once you have defined your data structure, you use a protobuf compiler to
automatically generate the code that will marshal/unmarshall the data structure
into/from a bytes sequence. The protobuf compiler is able to generate code in
multiple languages, including C/C++, Python, Java and Go.

Now imagine that you can pass the marshalled data structure to YARA, and create
rules based in that data. Like for example:

import "vt_employee"

rule virustotal_employee_under_25
{
  condition:
    vt_employee.age < 25 and
    vt_employee.email matches /*.@virustotal\.com/
}

Neat, right?
