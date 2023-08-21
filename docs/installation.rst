Installation
============

**aduneoclientfedid** is a web server that is installed locally, most of the time on localhost and accessed with a web browser.

Python must be installed on the system which will run the web server. It is compatible with Python 3.6 and later.

.. note::
    
    There's an exception however: the xmlsec library required for SAML does not exist at the moment for Python 3.11 on Windows

It has been tested on Windows and various Linux systems. On Windows, it can be executed from a command line prompt or in a Powershell window.

The simpliest way to install it is to download it from PyPI.

First, it is advisable to create a virtual environment in a directory where you want to install the software.

.. code-block:: console

     $ mkdir clientfedid
     $ cd clientfedid
     $ python -m venv my-env

.. note::

    Depending on your operating system, you might have to use python3 instead of python, or use a different command - virtualenv -p python3 my-env for instance

and activate it. Depending on the system:

.. code-block:: console

     > source my-env/bin/activate

or 

.. code-block:: console

     > my-env\Script\activate

then install it with pip:

.. code-block:: console

    (my-env) $ pip install aduneoclientfedid

You may have to manually install some Linux packages. Please refer to the `xmlsec documentation <https://pypi.org/project/xmlsec>`_ for more information.