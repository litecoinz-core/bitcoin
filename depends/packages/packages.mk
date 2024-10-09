packages:= openssl libsodium curl zlib rust vendored-sources

boost_packages = boost

libevent_packages = libevent

qrencode_linux_packages = qrencode
qrencode_darwin_packages = qrencode
qrencode_mingw32_packages = qrencode

qt_linux_packages:=qt expat libxcb xcb_proto libXau xproto freetype fontconfig libxkbcommon libxcb_util libxcb_util_render libxcb_util_keysyms libxcb_util_image libxcb_util_wm
qt_darwin_packages=qt
qt_mingw32_packages=qt

bdb_packages=bdb

zmq_packages=zeromq

upnp_packages=miniupnpc

$(host_arch)_$(host_os)_native_packages += native_b2
