APP_PLATFORM := android-8
#APP_ABI := armeabi-v7a
#APP_ABI := arm64-v8a x86_64
APP_ABI := arm64-v8a
LOCAL_ARM_NEON=true
ARCH_ARM_HAVE_NEON=true
# TODO: Have libjpeg do this
APP_CFLAGS := -D__ARM_HAVE_NEON=1
APP_STL := stlport_static
APP_BUILD_SCRIPT := Android.mk


