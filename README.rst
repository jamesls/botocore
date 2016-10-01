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
