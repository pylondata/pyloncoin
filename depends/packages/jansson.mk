package=jansson
$(package)_version=2.11
$(package)_download_path=http://www.digip.org/jansson/releases/
$(package)_file_name=$(package)-$($(package)_version).tar.bz2
$(package)_sha256_hash=783132e2fc970feefc2fa54199ef65ee020bd8e0e991a78ea44b8586353a0947

define $(package)_config_cmds
  ./configure --prefix=$($(package)_staging_prefix_dir)
endef

define $(package)_build_cmds
  $(MAKE)
endef

define $(package)_stage_cmds
  $(MAKE) install
endef
