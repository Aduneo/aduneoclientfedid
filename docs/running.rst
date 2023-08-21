Running aduneoclientfedid
=========================

Once the packages are successfully installed, create a root directory where the configuration and logs will be created. This root directory can be located anywhere on the disk. The natural option is the directory where the Python virtual environment (*venv*) has been created.

If you want to create a new root directory:

.. code-block:: console

    mkdir clientfedid
    cd clientfedid

Two directories will be created in this directory:

* *conf* where a default configuration file is generated
* *log*

Make sure the current user is allowed to create these items.

There are several ways of launching the server:

.. code-block:: console

    clientfedid
    aduneoclientfedid
    python -m aduneoclientfedid

If successfull, a similar line is displayed:

.. code-block:: console

    Fri Jan 6 18:15:52 2023 Server UP - https://localhost:443

On Unix/Linux systems, non-administrative users are prevented by default to start a server on ports below 1024.

HTTPS running on port 443, the server won't launch, with the following error:

.. Error::

    PermissionError: [Errno 13] Permission denied

The easiest way out is to modify the port to a value larger than 1024, for instance 8443.

To change the port, just had the -port argument. Launching the server on port 8443 becomes:

.. code-block:: console

    clientfedid -port 8443

When you use the previous command to launch the client for the first time (when the conf directory has not yet been created), the port is configured in the configuration file (the file clientfedid.cnf in the conf directory). Now you don't have to specify the port in the command line for the next execution.

You can also change the listening interface, with the -host argument.

By default, the server only listens on the localhost interface (127.0.0.1), meaning you can only reach it from the same computer (with a web browser on https://localhost). If you want to access it from another computer, you have to change the listening network interface.

To listen on any interface, run the server with an empty host:

.. code-block:: console

    clientfedid -host ""

Now you can point a browser to something like https://mycomputer.domain.com.

Once the server is running, stop it with Ctrl+C.

This server is only meant to be running for the time when the tests are conducted. It is not optimized to run for a long time. It is not optimized to run as a demon. It is definitely not secure enough.

It is usually run on the tester's computer or on a computer controlled by the tester.