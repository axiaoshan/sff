# theos 编译配置（fishhook 源码随项目自带，自包含）
TARGET := iphone:clang:latest:14.0
ARCHS = arm64

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = SFHook

SFHook_FILES = Tweak.xm fishhook.c
SFHook_CFLAGS = -fobjc-arc -Wno-error -I.
SFHook_LDFLAGS = -lsubstrate

include $(THEOS_MAKE_PATH)/tweak.mk

after-install::
	install.exec "killall -9 顺丰速运 2>/dev/null || true"
