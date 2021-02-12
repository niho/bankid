BankID
======

Swedish BankID Relaying Party v5.1 implementation in Erlang.

Documentation
-------------

See the generated edoc [documentation](https://niho.github.io/bankid/) for usage.

Tests
-----

There is a common test suite included that you can run against the BankID test
environment. The test suite requires user interaction and that you have a BankID
for test installed in your BankID client. See [How to get a test BankID](https://www.bankid.com/assets/bankid/rp/how-to-get-bankid-for-test-v1.7.pdf)
for more information.

The personal number to use for the tests can be specified using the `BANKID_PNR`
environment variable:

```
BANKID_PNR=190001010101 rebar3 ct
```

Copyright and License
---------------------

Copyright (c) 2021, Niklas Holmgren.

Released under the terms of the Apache License 2.0. See [LICENSE](./LICENSE) for details.

