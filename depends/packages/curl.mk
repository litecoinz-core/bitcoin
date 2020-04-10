package=curl
$(package)_version=7.66.0
$(package)_file_name=$(package)-$($(package)_version).tar.gz
$(package)_download_path=https://curl.haxx.se/download
$(package)_sha256_hash=d0393da38ac74ffac67313072d7fe75b1fa1010eb5987f63f349b024a36b7ffb
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
