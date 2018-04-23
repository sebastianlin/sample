
LOCAL_PATH := $(call my-dir)
include $(CLEAR_VARS)

LOCAL_CFLAGS += -pie -fPIE
LOCAL_LDFLAGS += -pie -fPIE

LOCAL_SRC_FILES := \
			main.c
LOCAL_MODULE := main.out

include $(BUILD_EXECUTABLE)

