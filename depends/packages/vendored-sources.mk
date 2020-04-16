package=vendored-sources
$(package)_version=0.1
$(package)_download_path=https://litecoinz.org/depends-sources
$(package)_file_name=$(package)-$($(package)_version).tar.gz
$(package)_sha256_hash=4870b14fab8f96ca19dd4634f36a5041977d2abf95a7468bd2247843c329d5c9

define $(package)_stage_cmds
  mkdir -p $($(package)_staging_prefix_dir)/$(package) && \
  cp -r $($(package)_extract_dir)/. $($(package)_staging_prefix_dir)/$(package)/
endef
