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

WARNING
=======

This is a special branch of botocore not meant for general purpose usage.
If you set `INSIGHT_SERVER`, then a handler will automatically configured
to send data to insight, e.g `export INSIGHT_SERVER=ws://foo:1234/publish`.
