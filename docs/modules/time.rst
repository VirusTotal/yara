
.. _time-module:

############
Time module
############

.. versionadded:: 3.7.0

The Time module allows you to use temporal conditions in your YARA rules.

.. c:function:: now()

    Function returning an integer which is the number of seconds since January
    1, 1970.

    *Example: pe.timestamp > time.now()*
