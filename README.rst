botocore
========

.. image:: https://secure.travis-ci.org/boto/botocore.png?branch=develop
   :target: http://travis-ci.org/boto/botocore

.. image:: https://codecov.io/github/boto/botocore/coverage.svg?branch=develop
    :target: https://codecov.io/github/boto/botocore?branch=develop


A low-level interface to a growing number of Amazon Web Services. The
botocore package is the foundation for the
`AWS CLI <https://github.com/aws/aws-cli>`__ as well as
`boto3 <https://github.com/boto/boto3>`__.

`Documentation <https://botocore.readthedocs.io/en/latest/>`__


Getting Set Up
==============

First make sure you have python3 installed::

    $ python3 --version
    Python 3.5.1

You should have **version 3.5.0 or later.**  If not, try ``brew install
python3`` on a mac.

Next create a virtualenv.  This is an interpreter specific to your project.
From the root directory of this project run:

    $ python3 -m venv venv
    $ . venv/bin/activate

You can double check this worked by verifying that the python executable now
points to a file in your ``./venv/`` directory::

    $ which python
    /Users/username/Source/botocore/venv/bin/python

Next install the dependencies (again run this from the repo root dir)::

    $ pip install -e .
    Collecting websockets==3.2 (from insight-server==0.0.1)
      Using cached websockets-3.2-py33.py34.py35-none-any.whl
      Installing collected packages: websockets, insight-server
        Running setup.py develop for botocore
        Successfully installed botocore websockets-3.2

You can test that you have botocore installed::

    $ python
    Python 3.5.1 (default, Jan 22 2016, 08:54:32)
    >>> import botocore
    >>> botocore
    <module 'botocore' from '/Users/jamessar/Source/botocore/botocore/__init__.py'>

You can now use botocore to create clients.  There's
a ``driver.py`` script that shows you some example calls.
You'll need to edit the table values and region to work
with your own data.  Once you edit the data you can run::

    $ python driver.py


Cleaning up
-----------

When you're done developing, you can deactive your environment by running::


    $ deactivate


You'll now see your python executable is back to normal::

    $ which python
    /usr/local/bin/python

Now whenever you want to work on this project again, just cd to this directory
and run::

    $ . venv/bin/activate
