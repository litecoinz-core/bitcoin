package=curl
$(package)_version=7.50.3
$(package)_file_name=$(package)-$($(package)_version).tar.gz
$(package)_download_path=https://curl.haxx.se/download
$(package)_sha256_hash=3991c2234986178af3b3f693e5afa35d49da2ab4ba61292e3817222446dca7e1
$(package)_dependencies=openssl

define $(package)_set_vars
  $(package)_config_opts=--disable-shared --disable-ipv6 --disable-manual --disable-ldap --disable-ldaps --disable-rtsp --disable-dict --disable-telnet --disable-tftp --disable-pop3 --disable-imap --disable-smb --disable-smtp --disable-gopher --enable-http --enable-ftp --without-random --with-ssl
endef

define $(package)_config_cmds
  $($(package)_autoconf)
endef

define $(package)_build_cmds
  $(MAKE)
endef

define $(package)_stage_cmds
  $(MAKE) DESTDIR=$($(package)_staging_dir) install
endef
