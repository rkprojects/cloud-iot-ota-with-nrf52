PROJECT_NAME     := ota_app
TARGETS          := nrf52840_xxaa
OUTPUT_DIRECTORY := _build

SDK_ROOT := ../../../../../../..
PROJ_DIR := ../../../..

$(OUTPUT_DIRECTORY)/nrf52840_xxaa.out: \
  LINKER_SCRIPT  := ota_app.ld
  
# Available Cloud connection configurations.
CLOUD_TARGET_AWS_GPRS_SSL 		= 0
CLOUD_TARGET_AWS_MBEDTLS_GPRS_TCP 	= 1
CLOUD_TARGET_GCP_MBEDTLS_GPRS_SSL 	= 2
CLOUD_TARGET_GCP_MBEDTLS_GPRS_TCP	= 3

# Select Cloud connection configuration
CLOUD_TARGET = $(CLOUD_TARGET_AWS_GPRS_SSL)

  
SRC_AWS_IOT_SDK_COMMON += \
	$(PROJ_DIR)/aws-iot-device-sdk-embedded-C-3.0.1/external_libs/jsmn/jsmn.c \
	$(PROJ_DIR)/aws-iot-device-sdk-embedded-C-3.0.1/platform/nRF52840/common/timer.c \
	$(PROJ_DIR)/aws-iot-device-sdk-embedded-C-3.0.1/src/aws_iot_jobs_interface.c \
	$(PROJ_DIR)/aws-iot-device-sdk-embedded-C-3.0.1/src/aws_iot_mqtt_client_publish.c \
	$(PROJ_DIR)/aws-iot-device-sdk-embedded-C-3.0.1/src/aws_iot_jobs_json.c \
	$(PROJ_DIR)/aws-iot-device-sdk-embedded-C-3.0.1/src/aws_iot_mqtt_client_subscribe.c \
	$(PROJ_DIR)/aws-iot-device-sdk-embedded-C-3.0.1/src/aws_iot_jobs_topics.c \
	$(PROJ_DIR)/aws-iot-device-sdk-embedded-C-3.0.1/src/aws_iot_mqtt_client_unsubscribe.c \
	$(PROJ_DIR)/aws-iot-device-sdk-embedded-C-3.0.1/src/aws_iot_jobs_types.c \
	$(PROJ_DIR)/aws-iot-device-sdk-embedded-C-3.0.1/src/aws_iot_mqtt_client_yield.c \
	$(PROJ_DIR)/aws-iot-device-sdk-embedded-C-3.0.1/src/aws_iot_json_utils.c \
	$(PROJ_DIR)/aws-iot-device-sdk-embedded-C-3.0.1/src/aws_iot_mqtt_client.c \
	$(PROJ_DIR)/aws-iot-device-sdk-embedded-C-3.0.1/src/aws_iot_mqtt_client_common_internal.c \
	$(PROJ_DIR)/aws-iot-device-sdk-embedded-C-3.0.1/src/aws_iot_mqtt_client_connect.c
	
SRC_AWS_IOT_SDK_SHADOW += \
	$(PROJ_DIR)/aws-iot-device-sdk-embedded-C-3.0.1/src/aws_iot_shadow_records.c \
	$(PROJ_DIR)/aws-iot-device-sdk-embedded-C-3.0.1/src/aws_iot_shadow_actions.c \
	$(PROJ_DIR)/aws-iot-device-sdk-embedded-C-3.0.1/src/aws_iot_shadow.c \
	$(PROJ_DIR)/aws-iot-device-sdk-embedded-C-3.0.1/src/aws_iot_shadow_json.c



SRC_AWS_IOT_APP += \
	$(SRC_AWS_IOT_SDK_SHADOW) \
	$(PROJ_DIR)/src/aws_iot.c \
	$(PROJ_DIR)/aws-iot-device-sdk-embedded-C-3.0.1/platform/nRF52840/sim7600e/network_wrapper.c

INC_AWS_IOT_APP += \
	$(PROJ_DIR)/aws-iot-device-sdk-embedded-C-3.0.1/platform/nRF52840/sim7600e
	
SRC_AWS_IOT_APP_MBEDTLS += \
	$(SRC_AWS_IOT_SDK_SHADOW) \
	$(PROJ_DIR)/src/aws_iot.c \
	$(PROJ_DIR)/aws-iot-device-sdk-embedded-C-3.0.1/platform/nRF52840/mbedtls/network_mbedtls_wrapper.c \
	$(PROJ_DIR)/aws-iot-device-sdk-embedded-C-3.0.1/platform/nRF52840/mbedtls/mbedtls_gprs_sockets.c
	
INC_AWS_IOT_APP_MBEDTLS += \
	$(PROJ_DIR)/aws-iot-device-sdk-embedded-C-3.0.1/external_libs/mbedTLS/include \
	$(PROJ_DIR)/aws-iot-device-sdk-embedded-C-3.0.1/platform/nRF52840/mbedtls
	
SRC_MBEDTLS += \
	$(PROJ_DIR)/aws-iot-device-sdk-embedded-C-3.0.1/external_libs/mbedTLS/library/threading.c \
	$(PROJ_DIR)/aws-iot-device-sdk-embedded-C-3.0.1/external_libs/mbedTLS/library/entropy.c \
	$(PROJ_DIR)/aws-iot-device-sdk-embedded-C-3.0.1/external_libs/mbedTLS/library/ssl_tls.c \
	$(PROJ_DIR)/aws-iot-device-sdk-embedded-C-3.0.1/external_libs/mbedTLS/library/arc4.c \
	$(PROJ_DIR)/aws-iot-device-sdk-embedded-C-3.0.1/external_libs/mbedTLS/library/aesni.c \
	$(PROJ_DIR)/aws-iot-device-sdk-embedded-C-3.0.1/external_libs/mbedTLS/library/x509_crt.c \
	$(PROJ_DIR)/aws-iot-device-sdk-embedded-C-3.0.1/external_libs/mbedTLS/library/chachapoly.c \
	$(PROJ_DIR)/aws-iot-device-sdk-embedded-C-3.0.1/external_libs/mbedTLS/library/platform.c \
	$(PROJ_DIR)/aws-iot-device-sdk-embedded-C-3.0.1/external_libs/mbedTLS/library/x509_crl.c \
	$(PROJ_DIR)/aws-iot-device-sdk-embedded-C-3.0.1/external_libs/mbedTLS/library/ssl_srv.c \
	$(PROJ_DIR)/aws-iot-device-sdk-embedded-C-3.0.1/external_libs/mbedTLS/library/asn1write.c \
	$(PROJ_DIR)/aws-iot-device-sdk-embedded-C-3.0.1/external_libs/mbedTLS/library/aria.c \
	$(PROJ_DIR)/aws-iot-device-sdk-embedded-C-3.0.1/external_libs/mbedTLS/library/ecp_curves.c \
	$(PROJ_DIR)/aws-iot-device-sdk-embedded-C-3.0.1/external_libs/mbedTLS/library/asn1parse.c \
	$(PROJ_DIR)/aws-iot-device-sdk-embedded-C-3.0.1/external_libs/mbedTLS/library/x509write_crt.c \
	$(PROJ_DIR)/aws-iot-device-sdk-embedded-C-3.0.1/external_libs/mbedTLS/library/hkdf.c \
	$(PROJ_DIR)/aws-iot-device-sdk-embedded-C-3.0.1/external_libs/mbedTLS/library/x509_csr.c \
	$(PROJ_DIR)/aws-iot-device-sdk-embedded-C-3.0.1/external_libs/mbedTLS/library/oid.c \
	$(PROJ_DIR)/aws-iot-device-sdk-embedded-C-3.0.1/external_libs/mbedTLS/library/ssl_cookie.c \
	$(PROJ_DIR)/aws-iot-device-sdk-embedded-C-3.0.1/external_libs/mbedTLS/library/pkcs11.c \
	$(PROJ_DIR)/aws-iot-device-sdk-embedded-C-3.0.1/external_libs/mbedTLS/library/gcm.c \
	$(PROJ_DIR)/aws-iot-device-sdk-embedded-C-3.0.1/external_libs/mbedTLS/library/md2.c \
	$(PROJ_DIR)/aws-iot-device-sdk-embedded-C-3.0.1/external_libs/mbedTLS/library/xtea.c \
	$(PROJ_DIR)/aws-iot-device-sdk-embedded-C-3.0.1/external_libs/mbedTLS/library/cipher.c \
	$(PROJ_DIR)/aws-iot-device-sdk-embedded-C-3.0.1/external_libs/mbedTLS/library/aes.c \
	$(PROJ_DIR)/aws-iot-device-sdk-embedded-C-3.0.1/external_libs/mbedTLS/library/x509write_csr.c \
	$(PROJ_DIR)/aws-iot-device-sdk-embedded-C-3.0.1/external_libs/mbedTLS/library/pk_wrap.c \
	$(PROJ_DIR)/aws-iot-device-sdk-embedded-C-3.0.1/external_libs/mbedTLS/library/ecdsa.c \
	$(PROJ_DIR)/aws-iot-device-sdk-embedded-C-3.0.1/external_libs/mbedTLS/library/ctr_drbg.c \
	$(PROJ_DIR)/aws-iot-device-sdk-embedded-C-3.0.1/external_libs/mbedTLS/library/pk.c \
	$(PROJ_DIR)/aws-iot-device-sdk-embedded-C-3.0.1/external_libs/mbedTLS/library/version.c \
	$(PROJ_DIR)/aws-iot-device-sdk-embedded-C-3.0.1/external_libs/mbedTLS/library/hmac_drbg.c \
	$(PROJ_DIR)/aws-iot-device-sdk-embedded-C-3.0.1/external_libs/mbedTLS/library/poly1305.c \
	$(PROJ_DIR)/aws-iot-device-sdk-embedded-C-3.0.1/external_libs/mbedTLS/library/dhm.c \
	$(PROJ_DIR)/aws-iot-device-sdk-embedded-C-3.0.1/external_libs/mbedTLS/library/camellia.c \
	$(PROJ_DIR)/aws-iot-device-sdk-embedded-C-3.0.1/external_libs/mbedTLS/library/pem.c \
	$(PROJ_DIR)/aws-iot-device-sdk-embedded-C-3.0.1/external_libs/mbedTLS/library/ccm.c \
	$(PROJ_DIR)/aws-iot-device-sdk-embedded-C-3.0.1/external_libs/mbedTLS/library/version_features.c \
	$(PROJ_DIR)/aws-iot-device-sdk-embedded-C-3.0.1/external_libs/mbedTLS/library/nist_kw.c \
	$(PROJ_DIR)/aws-iot-device-sdk-embedded-C-3.0.1/external_libs/mbedTLS/library/timing.c \
	$(PROJ_DIR)/aws-iot-device-sdk-embedded-C-3.0.1/external_libs/mbedTLS/library/ripemd160.c \
	$(PROJ_DIR)/aws-iot-device-sdk-embedded-C-3.0.1/external_libs/mbedTLS/library/ecp.c \
	$(PROJ_DIR)/aws-iot-device-sdk-embedded-C-3.0.1/external_libs/mbedTLS/library/ecdh.c \
	$(PROJ_DIR)/aws-iot-device-sdk-embedded-C-3.0.1/external_libs/mbedTLS/library/ssl_cli.c \
	$(PROJ_DIR)/aws-iot-device-sdk-embedded-C-3.0.1/external_libs/mbedTLS/library/pkparse.c \
	$(PROJ_DIR)/aws-iot-device-sdk-embedded-C-3.0.1/external_libs/mbedTLS/library/md5.c \
	$(PROJ_DIR)/aws-iot-device-sdk-embedded-C-3.0.1/external_libs/mbedTLS/library/rsa.c \
	$(PROJ_DIR)/aws-iot-device-sdk-embedded-C-3.0.1/external_libs/mbedTLS/library/pkcs12.c \
	$(PROJ_DIR)/aws-iot-device-sdk-embedded-C-3.0.1/external_libs/mbedTLS/library/sha1.c \
	$(PROJ_DIR)/aws-iot-device-sdk-embedded-C-3.0.1/external_libs/mbedTLS/library/platform_util.c \
	$(PROJ_DIR)/aws-iot-device-sdk-embedded-C-3.0.1/external_libs/mbedTLS/library/ssl_ticket.c \
	$(PROJ_DIR)/aws-iot-device-sdk-embedded-C-3.0.1/external_libs/mbedTLS/library/memory_buffer_alloc.c \
	$(PROJ_DIR)/aws-iot-device-sdk-embedded-C-3.0.1/external_libs/mbedTLS/library/cipher_wrap.c \
	$(PROJ_DIR)/aws-iot-device-sdk-embedded-C-3.0.1/external_libs/mbedTLS/library/certs.c \
	$(PROJ_DIR)/aws-iot-device-sdk-embedded-C-3.0.1/external_libs/mbedTLS/library/error.c \
	$(PROJ_DIR)/aws-iot-device-sdk-embedded-C-3.0.1/external_libs/mbedTLS/library/base64.c \
	$(PROJ_DIR)/aws-iot-device-sdk-embedded-C-3.0.1/external_libs/mbedTLS/library/debug.c \
	$(PROJ_DIR)/aws-iot-device-sdk-embedded-C-3.0.1/external_libs/mbedTLS/library/blowfish.c \
	$(PROJ_DIR)/aws-iot-device-sdk-embedded-C-3.0.1/external_libs/mbedTLS/library/pkwrite.c \
	$(PROJ_DIR)/aws-iot-device-sdk-embedded-C-3.0.1/external_libs/mbedTLS/library/ecjpake.c \
	$(PROJ_DIR)/aws-iot-device-sdk-embedded-C-3.0.1/external_libs/mbedTLS/library/x509_create.c \
	$(PROJ_DIR)/aws-iot-device-sdk-embedded-C-3.0.1/external_libs/mbedTLS/library/chacha20.c \
	$(PROJ_DIR)/aws-iot-device-sdk-embedded-C-3.0.1/external_libs/mbedTLS/library/md4.c \
	$(PROJ_DIR)/aws-iot-device-sdk-embedded-C-3.0.1/external_libs/mbedTLS/library/ssl_cache.c \
	$(PROJ_DIR)/aws-iot-device-sdk-embedded-C-3.0.1/external_libs/mbedTLS/library/cmac.c \
	$(PROJ_DIR)/aws-iot-device-sdk-embedded-C-3.0.1/external_libs/mbedTLS/library/pkcs5.c \
	$(PROJ_DIR)/aws-iot-device-sdk-embedded-C-3.0.1/external_libs/mbedTLS/library/havege.c \
	$(PROJ_DIR)/aws-iot-device-sdk-embedded-C-3.0.1/external_libs/mbedTLS/library/padlock.c \
	$(PROJ_DIR)/aws-iot-device-sdk-embedded-C-3.0.1/external_libs/mbedTLS/library/md_wrap.c \
	$(PROJ_DIR)/aws-iot-device-sdk-embedded-C-3.0.1/external_libs/mbedTLS/library/entropy_poll.c \
	$(PROJ_DIR)/aws-iot-device-sdk-embedded-C-3.0.1/external_libs/mbedTLS/library/sha256.c \
	$(PROJ_DIR)/aws-iot-device-sdk-embedded-C-3.0.1/external_libs/mbedTLS/library/md.c \
	$(PROJ_DIR)/aws-iot-device-sdk-embedded-C-3.0.1/external_libs/mbedTLS/library/ssl_ciphersuites.c \
	$(PROJ_DIR)/aws-iot-device-sdk-embedded-C-3.0.1/external_libs/mbedTLS/library/bignum.c \
	$(PROJ_DIR)/aws-iot-device-sdk-embedded-C-3.0.1/external_libs/mbedTLS/library/rsa_internal.c \
	$(PROJ_DIR)/aws-iot-device-sdk-embedded-C-3.0.1/external_libs/mbedTLS/library/des.c \
	$(PROJ_DIR)/aws-iot-device-sdk-embedded-C-3.0.1/external_libs/mbedTLS/library/x509.c \
	$(PROJ_DIR)/aws-iot-device-sdk-embedded-C-3.0.1/external_libs/mbedTLS/library/sha512.c

SRC_GCP_IOT_APP_MBEDTLS += \
	$(PROJ_DIR)/src/gcp_iot.c \
	$(PROJ_DIR)/src/jwt.c \
	$(PROJ_DIR)/aws-iot-device-sdk-embedded-C-3.0.1/platform/nRF52840/mbedtls/network_mbedtls_wrapper.c \
	$(PROJ_DIR)/aws-iot-device-sdk-embedded-C-3.0.1/platform/nRF52840/mbedtls/mbedtls_gprs_sockets.c
	
INC_GCP_IOT_APP_MBEDTLS += \
	$(PROJ_DIR)/aws-iot-device-sdk-embedded-C-3.0.1/external_libs/mbedTLS/include \
	$(PROJ_DIR)/aws-iot-device-sdk-embedded-C-3.0.1/platform/nRF52840/mbedtls

	
SRC_GCP_IOT_APP += \
	$(PROJ_DIR)/src/gcp_iot.c \
	$(PROJ_DIR)/src/jwt.c \
	$(PROJ_DIR)/aws-iot-device-sdk-embedded-C-3.0.1/platform/nRF52840/sim7600e/network_wrapper.c
	
INC_GCP_IOT_APP += \
	$(PROJ_DIR)/aws-iot-device-sdk-embedded-C-3.0.1/platform/nRF52840/sim7600e \
	$(PROJ_DIR)/aws-iot-device-sdk-embedded-C-3.0.1/external_libs/mbedTLS/include

SRC_NRF_CRYPTO += \
	$(SDK_ROOT)/components/libraries/crypto/backend/nrf_hw/nrf_hw_backend_init.c \
	$(SDK_ROOT)/components/libraries/crypto/backend/cc310/cc310_backend_aes.c \
	$(SDK_ROOT)/components/libraries/crypto/backend/cc310/cc310_backend_hash.c \
	$(SDK_ROOT)/components/libraries/crypto/backend/cc310/cc310_backend_init.c \
	$(SDK_ROOT)/components/libraries/crypto/backend/cc310/cc310_backend_mutex.c \
	$(SDK_ROOT)/components/libraries/crypto/backend/cc310/cc310_backend_rng.c \
	$(SDK_ROOT)/components/libraries/crypto/backend/cc310/cc310_backend_shared.c \
	$(SDK_ROOT)/components/libraries/crypto/nrf_crypto_aes.c \
	$(SDK_ROOT)/components/libraries/crypto/nrf_crypto_aes_shared.c \
	$(SDK_ROOT)/components/libraries/crypto/nrf_crypto_error.c \
	$(SDK_ROOT)/components/libraries/crypto/nrf_crypto_hash.c \
	$(SDK_ROOT)/components/libraries/crypto/nrf_crypto_init.c \
	$(SDK_ROOT)/components/libraries/crypto/nrf_crypto_rng.c \
	$(SDK_ROOT)/components/libraries/crypto/nrf_crypto_shared.c
	
INC_NRF_CRYPTO += \
	$(SDK_ROOT)/components/libraries/stack_info \
	$(SDK_ROOT)/components/libraries/crypto/backend/cc310 \
	$(SDK_ROOT)/components/libraries/crypto/backend/cc310_bl \
	$(SDK_ROOT)/external/nrf_cc310/include \
	$(SDK_ROOT)/components/libraries/crypto \
	$(SDK_ROOT)/components/libraries/crypto/backend/nrf_hw \
	$(SDK_ROOT)/components/libraries/crypto/backend/nrf_sw \
	$(SDK_ROOT)/components/libraries/crypto/backend/optiga \
	$(SDK_ROOT)/components/libraries/crypto/backend/mbedtls \
	$(SDK_ROOT)/components/libraries/crypto/backend/oberon \
	$(SDK_ROOT)/components/libraries/crypto/backend/micro_ecc \
	$(SDK_ROOT)/components/libraries/crypto/backend/cifra \
	$(SDK_ROOT)/components/libraries/mutex


# Select optional source codes are per cloud target.
ifeq ($(CLOUD_TARGET), $(CLOUD_TARGET_AWS_GPRS_SSL))
	SRC_CLOUD_TARGET =\
		$(SRC_AWS_IOT_APP)
		
	INC_CLOUD_TARGET =\
		$(INC_AWS_IOT_APP)
		
	CFLAGS_IOT_CORE = -DUSE_AWS_IOT_CORE
endif

ifeq ($(CLOUD_TARGET), $(CLOUD_TARGET_AWS_MBEDTLS_GPRS_TCP))
	SRC_CLOUD_TARGET =\
		$(SRC_AWS_IOT_APP_MBEDTLS) \
		$(SRC_MBEDTLS)
		
	INC_CLOUD_TARGET =\
		$(INC_AWS_IOT_APP_MBEDTLS)
		
	CFLAGS_IOT_CORE = -DUSE_AWS_IOT_CORE
endif 

ifeq ($(CLOUD_TARGET), $(CLOUD_TARGET_GCP_MBEDTLS_GPRS_SSL))
	SRC_CLOUD_TARGET =\
		$(SRC_GCP_IOT_APP) \
		$(SRC_MBEDTLS)
		
	INC_CLOUD_TARGET =\
		$(INC_GCP_IOT_APP)
		
	CFLAGS_IOT_CORE = -DUSE_GCP_IOT_CORE
endif

ifeq ($(CLOUD_TARGET), $(CLOUD_TARGET_GCP_MBEDTLS_GPRS_TCP))
	SRC_CLOUD_TARGET =\
		$(SRC_GCP_IOT_APP_MBEDTLS) \
		$(SRC_MBEDTLS)
		
	INC_CLOUD_TARGET =\
		$(INC_GCP_IOT_APP_MBEDTLS)
		
	CFLAGS_IOT_CORE = -DUSE_GCP_IOT_CORE
endif

# Source files common to all targets
SRC_FILES += \
	$(SRC_NRF_CRYPTO) \
  $(SDK_ROOT)/modules/nrfx/mdk/gcc_startup_nrf52840.S \
  $(SDK_ROOT)/components/libraries/log/src/nrf_log_frontend.c \
  $(SDK_ROOT)/components/libraries/log/src/nrf_log_str_formatter.c \
  $(SDK_ROOT)/components/boards/boards.c \
  $(SDK_ROOT)/components/libraries/util/app_error.c \
  $(SDK_ROOT)/components/libraries/util/app_error_handler_gcc.c \
  $(SDK_ROOT)/components/libraries/util/app_error_weak.c \
  $(SDK_ROOT)/components/libraries/fifo/app_fifo.c \
  $(SDK_ROOT)/components/libraries/uart/app_uart_fifo.c \
  $(SDK_ROOT)/components/libraries/util/app_util_platform.c \
  $(SDK_ROOT)/components/libraries/util/nrf_assert.c \
  $(SDK_ROOT)/components/libraries/atomic/nrf_atomic.c \
  $(SDK_ROOT)/components/libraries/balloc/nrf_balloc.c \
  $(SDK_ROOT)/components/libraries/queue/nrf_queue.c \
  $(SDK_ROOT)/external/fprintf/nrf_fprintf.c \
  $(SDK_ROOT)/external/fprintf/nrf_fprintf_format.c \
  $(SDK_ROOT)/components/libraries/memobj/nrf_memobj.c \
  $(SDK_ROOT)/components/libraries/ringbuf/nrf_ringbuf.c \
  $(SDK_ROOT)/components/libraries/strerror/nrf_strerror.c \
  $(SDK_ROOT)/components/libraries/uart/retarget.c \
  $(SDK_ROOT)/integration/nrfx/legacy/nrf_drv_uart.c \
  $(SDK_ROOT)/integration/nrfx/legacy/nrf_drv_rng.c \
  $(SDK_ROOT)/integration/nrfx/legacy/nrf_drv_clock.c\
  $(SDK_ROOT)/modules/nrfx/soc/nrfx_atomic.c \
  $(SDK_ROOT)/modules/nrfx/drivers/src/prs/nrfx_prs.c \
  $(SDK_ROOT)/modules/nrfx/drivers/src/nrfx_uart.c \
  $(SDK_ROOT)/modules/nrfx/drivers/src/nrfx_uarte.c \
  $(SDK_ROOT)/modules/nrfx/drivers/src/nrfx_clock.c \
  $(SDK_ROOT)/modules/nrfx/drivers/src/nrfx_rtc.c \
  $(SDK_ROOT)/modules/nrfx/drivers/src/nrfx_rng.c \
  $(SDK_ROOT)/modules/nrfx/drivers/src/prs/nrfx_prs.c \
  $(SDK_ROOT)/modules/nrfx/mdk/system_nrf52840.c \
  $(PROJ_DIR)/src/main.c \
  $(PROJ_DIR)/src/at_modem.c \
  $(PROJ_DIR)/src/uarte.c \
  $(PROJ_DIR)/src/temp_sensor.c \
  $(PROJ_DIR)/src/uart_print.c \
  $(PROJ_DIR)/src/sim7600_gprs.c \
  $(PROJ_DIR)/src/sim7600_parser.c \
  $(PROJ_DIR)/src/rofs_generated.c \
  $(PROJ_DIR)/src/rofs.c \
  $(PROJ_DIR)/src/cal_time.c \
  $(PROJ_DIR)/src/ota_update.c \
  $(SRC_AWS_IOT_SDK_COMMON) \
  $(SRC_CLOUD_TARGET) \
	


# Include folders common to all targets
INC_FOLDERS += \
  $(SDK_ROOT)/components \
  $(SDK_ROOT)/modules/nrfx/mdk \
  $(PROJ_DIR)/include \
  $(PROJ_DIR)/../bootloader/include \
  $(PROJ_DIR)/aws-iot-device-sdk-embedded-C-3.0.1/external_libs/jsmn \
  $(PROJ_DIR)/aws-iot-device-sdk-embedded-C-3.0.1/platform/nRF52840/common \
  $(PROJ_DIR)/aws-iot-device-sdk-embedded-C-3.0.1/include \
  $(INC_CLOUD_TARGET) \
  $(SDK_ROOT)/components/libraries/fifo \
  $(SDK_ROOT)/components/libraries/queue \
  $(SDK_ROOT)/components/libraries/strerror \
  $(SDK_ROOT)/components/toolchain/cmsis/include \
  $(SDK_ROOT)/components/libraries/util \
  ../config \
  $(SDK_ROOT)/components/libraries/balloc \
  $(SDK_ROOT)/components/libraries/ringbuf \
  $(SDK_ROOT)/modules/nrfx/hal \
  $(SDK_ROOT)/components/libraries/bsp \
  $(SDK_ROOT)/components/libraries/uart \
  $(SDK_ROOT)/components/libraries/log \
  $(SDK_ROOT)/modules/nrfx \
  $(SDK_ROOT)/components/libraries/experimental_section_vars \
  $(SDK_ROOT)/integration/nrfx/legacy \
  $(SDK_ROOT)/components/libraries/delay \
  $(SDK_ROOT)/integration/nrfx \
  $(SDK_ROOT)/components/drivers_nrf/nrf_soc_nosd \
  $(SDK_ROOT)/components/libraries/atomic \
  $(SDK_ROOT)/components/boards \
  $(SDK_ROOT)/components/libraries/memobj \
  $(SDK_ROOT)/modules/nrfx/drivers/include \
  $(SDK_ROOT)/modules/nrfx/drivers/src/prs \
  $(SDK_ROOT)/external/fprintf \
  $(SDK_ROOT)/components/libraries/log/src \
	$(INC_NRF_CRYPTO)
	
# Libraries common to all targets
LIB_FILES += \
	$(SDK_ROOT)/external/nrf_cc310/lib/cortex-m4/hard-float/libnrf_cc310_0.9.12.a

# Optimization flags
OPT = -O2 -g
# Uncomment the line below to enable link time optimization
#OPT += -flto

# C flags common to all targets
CFLAGS += $(OPT)
CFLAGS += -DDEBUG
CFLAGS += $(CFLAGS_IOT_CORE)
CFLAGS += -DBOARD_B840_BLOCK_V1
CFLAGS += -DBSP_DEFINES_ONLY
CFLAGS += -DCONFIG_GPIO_AS_PINRESET
CFLAGS += -DFLOAT_ABI_HARD
CFLAGS += -DNRF52840_XXAA
CFLAGS += -mcpu=cortex-m4
CFLAGS += -mthumb -mabi=aapcs
CFLAGS += -Wall -Werror -Wno-unused-function -Wno-format
CFLAGS += -mfloat-abi=hard -mfpu=fpv4-sp-d16
# keep every function in a separate section, this allows linker to discard unused ones
CFLAGS += -ffunction-sections -fdata-sections -fno-strict-aliasing
CFLAGS += -fno-builtin -fshort-enums

# C++ flags common to all targets
CXXFLAGS += $(OPT)

# Assembler flags common to all targets
ASMFLAGS += -g3
ASMFLAGS += -mcpu=cortex-m4
ASMFLAGS += -mthumb -mabi=aapcs
ASMFLAGS += -mfloat-abi=hard -mfpu=fpv4-sp-d16
ASMFLAGS += -DBOARD_B840_BLOCK_V1
ASMFLAGS += -DBSP_DEFINES_ONLY
ASMFLAGS += -DCONFIG_GPIO_AS_PINRESET
ASMFLAGS += -DFLOAT_ABI_HARD
ASMFLAGS += -DNRF52840_XXAA

# Linker flags
LDFLAGS += $(OPT)
LDFLAGS += -mthumb -mabi=aapcs -L$(SDK_ROOT)/modules/nrfx/mdk -T$(LINKER_SCRIPT)
LDFLAGS += -mcpu=cortex-m4
LDFLAGS += -mfloat-abi=hard -mfpu=fpv4-sp-d16
# let linker dump unused sections
LDFLAGS += -Wl,--gc-sections
# use newlib in nano version
LDFLAGS += --specs=nano.specs

nrf52840_xxaa: CFLAGS += -D__HEAP_SIZE=131072
nrf52840_xxaa: CFLAGS += -D__STACK_SIZE=16384
nrf52840_xxaa: ASMFLAGS += -D__HEAP_SIZE=131072
nrf52840_xxaa: ASMFLAGS += -D__STACK_SIZE=16384

# Add standard libraries at the very end of the linker input, after all objects
# that may need symbols provided by these libraries.
LIB_FILES += -lc -lnosys -lm


.PHONY: default help

# Default target - first one defined
default: nrf52840_xxaa

# Print all targets that can be built
help:
	@echo following targets are available:
	@echo		nrf52840_xxaa
	@echo		sdk_config - starting external tool for editing sdk_config.h
	@echo		flash      - flashing binary

TEMPLATE_PATH := $(SDK_ROOT)/components/toolchain/gcc


include $(TEMPLATE_PATH)/Makefile.common

$(foreach target, $(TARGETS), $(call define_target, $(target)))

.PHONY: flash erase

# Flash the program
flash: default
	@echo Flashing: $(OUTPUT_DIRECTORY)/nrf52840_xxaa.hex
	pyocd flash -t nrf52840 -e sector $(OUTPUT_DIRECTORY)/nrf52840_xxaa.hex
	#pyocd cmd -t nrf52840 -c reset
    
debug:
	pyocd gdb -t nrf52840

flash_softdevice:
	@echo Flashing: $(SDK_ROOT)/components/softdevice/s140/hex/s140_nrf52_6.1.1_softdevice.hex
	pyocd flash -t nrf52840 -e sector $(SDK_ROOT)/components/softdevice/s140/hex/s140_nrf52_6.1.1_softdevice.hex

#erase: # don't use it for EBYTE module
#	nrfjprog -f nrf52 --eraseall

SDK_CONFIG_FILE := ../config/sdk_config.h
CMSIS_CONFIG_TOOL := $(SDK_ROOT)/external_tools/cmsisconfig/CMSIS_Configuration_Wizard.jar
sdk_config:
	java -jar $(CMSIS_CONFIG_TOOL) $(SDK_CONFIG_FILE)
