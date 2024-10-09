package=curl
$(package)_version=7.88.1
$(package)_file_name=$(package)-$($(package)_version).tar.gz
$(package)_download_path=https://curl.haxx.se/download
$(package)_sha256_hash=cdb38b72e36bc5d33d5b8810f8018ece1baa29a8f215b4495e495ded82bbf3c7
$(package)_dependencies=openssl

define $(package)_set_vars
  $(package)_cflags=
  $(package)_config_opts=--disable-manual --disable-ldap --disable-ldaps --disable-rtsp --disable-dict --disable-telnet --disable-tftp --disable-pop3 --disable-imap --disable-smb --disable-smtp --disable-gopher --enable-http --enable-ftp --without-random --with-openssl --enable-static --disable-shared
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
