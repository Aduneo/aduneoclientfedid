Running from sources
====================

There are situations where it is not possible to install the server with pip.

It's still possible to run it from the sources.

1. First, the following packages must be manually installed:

* certifi
* charset_normalizer (at the time of writing, urllib3 is only compatible with version 2, not the newer version 3)
* idna
* urllib3
* requests
* cffi
* pycparser
* cryptography
* pyopenssl
* deprecated
* wrapt
* jwcrypto
  
1. Additionaly (for SAML):

* lxml
* xmlsec
* Sources are downloaded from `Aduneo Github Repository <https://github.com/Aduneo/aduneoclientfedid>`_, usually as a ZIP download through the Code button.

3. Create a root directory.

4. Create a Python virtual environment, activate it and install all necessary packages, in the order given earlier.

5. Unzip the sources, go to the directory containing the aduneoclientfedid folder and run:

.. code-block:: console

    python -m aduneoclientfedid