include $(TOPDIR)/rules.mk

PKG_NAME:=ci-odhcpd
PKG_RELEASE:=1

PKG_BUILD_DIR:=../../
PKG_VERSION:=@GITHUB_SHA@

PKG_CONFIG_DEPENDS:=CONFIG_PACKAGE_ci_odhcpd_$(BUILD_VARIANT)_ext_cer_id
PKG_ASLR_PIE_REGULAR:=1

include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/cmake.mk

define Package/ci-odhcpd/default
  SECTION:=net
  CATEGORY:=Network
  TITLE:=OpenWrt DHCPv6(-PD)/RA Server & Relay
  DEPENDS:=+libjson-c +libubox +libuci +libubus +libnl-tiny
endef

define Package/ci-odhcpd/default/description
 odhcpd is a daemon for serving and relaying IP management protocols to
 configure clients and downstream routers. It tries to follow the RFC 6204
 requirements for IPv6 home routers.
endef

define Package/ci-odhcpd/default/config
menu "Configuration"
	depends on PACKAGE_$(1)

config PACKAGE_ci_odhcpd_$(2)_ext_cer_id
	int
	default 0
	prompt "CER-ID Extension ID (0 = disabled)"
endmenu
endef

define Package/ci-odhcpd
  $(call Package/ci-odhcpd/default)
  TITLE += and DHCPv4 server
  VARIANT:=full
endef

Package/ci-odhcpd/config=$(call Package/ci-odhcpd/default/config,odhcpd,full)

define Package/ci-odhcpd/description
 $(call Package/ci-odhcpd/default/description)

 This is a variant providing server services for DHCPv4, RA, stateless and
 stateful DHCPv6, prefix delegation and can be used to relay RA, DHCPv6 and
 NDP between routed (non-bridged) interfaces in case no delegated prefixes
 are available.
endef

define Package/ci-odhcpd-ipv6only
  $(call Package/ci-odhcpd/default)
  VARIANT:=ipv6only
  DEPENDS+= @IPV6
endef

Package/ci-odhcpd-ipv6only/config=$(call Package/ci-odhcpd/default/config,odhcpd-ipv6only,ipv6only)

define Package/ci-odhcpd-ipv6only/description
 $(call Package/ci-odhcpd/default/description)

 This is a variant providing server services for RA, stateless and stateful
 DHCPv6,  prefix delegation and can be used to relay RA, DHCPv6 and NDP between
 routed (non-bridged) interfaces in case no delegated prefixes are available.
endef

CMAKE_OPTIONS += -DUBUS=1

ifeq ($(BUILD_VARIANT),full)
  CMAKE_OPTIONS += -DDHCPV4_SUPPORT=1
endif

ifneq ($(CONFIG_PACKAGE_ci_odhcpd_$(BUILD_VARIANT)_ext_cer_id),0)
  CMAKE_OPTIONS += -DEXT_CER_ID=$(CONFIG_PACKAGE_ci_odhcpd_$(BUILD_VARIANT)_ext_cer_id)
endif

define Package/ci-odhcpd/install
	$(INSTALL_DIR) $(1)/usr/sbin/
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/usr/sbin/odhcpd $(1)/usr/sbin/ci-odhcpd
endef

Package/ci-odhcpd-ipv6only/install = $(Package/ci-odhcpd/install)

$(eval $(call BuildPackage,ci-odhcpd))
$(eval $(call BuildPackage,ci-odhcpd-ipv6only))
