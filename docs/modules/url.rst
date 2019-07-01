
.. _url-module:

###########
URL module
###########

.. versionadded:: x.xx.x

The URL module allows you to write rules that depend on matching URL
components.

.. important::
    This module is not built into YARA by default, to learn how to include it
    refer to :ref:`compiling-yara`.

    Depends on libcurl. (>= 7.62.0)

Let's say you only want to match if a url's hostname is `example.com`:

.. code-block:: yara

    import "url"

    rule example_com_host
    {
        condition:
            url.host == "example.com"
    }

Or if the hostname contains the word `example`:

.. code-block:: yara

    import "url"

    rule example_host
    {
        condition:
            url.match.host(/example/)
    }


Usage
-----

The URL should be passed in as `modules_data`:

.. code-block:: python

    import yara

    rules = yara.compile(source='...')
    rules.match(data='...', modules_data={'url': 'https://example.com/'})


Reference
---------

.. default-domain:: c

All values default to an empty string unless otherwise specified.

.. type:: url

    Full URL provided to the module

.. type:: scheme

    Scheme extracted from the URL. (ex: ftp, http, gopher, etc)

    Default: 'https'

.. type:: user

    Username extracted from the URL.

.. type:: password

    Password extracted from the URL.

.. type:: options

    Options extracted from the URL.

.. type:: host

    Host extracted from the URL.

.. type:: port

    Port extracted from the URL. (as an integer)

    Default: 443

.. type:: path

    Path extracted from the URL.

    Default: '/'

.. type:: query

    Query extracted from the URL.

.. type:: fragment

    Fragment extracted from the URL.

.. type:: zoneid

    Zoneid extracted from the URL.

.. type:: match

    .. function:: url(regexp)

        Test if url matches `regexp`

    .. function:: scheme(regexp)

        Test if scheme matches `regexp`

    .. function:: user(regexp)

        Test if user matches `regexp`

    .. function:: password(regexp)

        Test if password matches `regexp`

    .. function:: options(regexp)

        Test if options matches `regexp`

    .. function:: host(regexp)

        Test if host matches `regexp`

    .. function:: port(regexp)

        Test if port matches `regexp`

    .. function:: path(regexp)

        Test if path matches `regexp`

    .. function:: query(regexp)

        Test if query matches `regexp`

    .. function:: fragment(regexp)

        Test if fragment matches `regexp`

    .. function:: zoneid(regexp)

        Test if zoneid matches `regexp`
