# nexxt-lan-native

This distribution supplies the optional CFFI binding to the upstream KCP C
implementation for `nexxt-lan`.  It is installed automatically by
`pip install 'nexxt-lan[native]'`.

The base `nexxt-lan` distribution remains pure Python and works without this
package.  Building this package from source requires a supported C compiler.

The vendored KCP source in `vendor/kcp` is distributed under its MIT license;
see `vendor/kcp/LICENSE`.
