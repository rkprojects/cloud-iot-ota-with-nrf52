/*

Copyright 2019-2020 Ravikiran Bukkasagara <contact@ravikiranb.com>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

*/

/*
	Modified from Original Subscribe/Publish Sample application.
*/

#include <ctype.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "aws_iot_config.h"
#include "aws_iot_log.h"
#include "aws_iot_mqtt_client_interface.h"
#include "aws_iot_version.h"

#include "jwt.h"
#include "ota_update.h"
#include "rofs.h"
#include "sim7600_gprs.h"
#include "temp_sensor.h"
#include "timer_interface.h"
#include "version.h"

#define MQTT_EVENT_TOPIC_NAME "/devices/my-device/events"
#define MQTT_STATE_TOPIC_NAME "/devices/my-device/state"
#define MQTT_CONFIG_TOPIC_NAME "/devices/my-device/config"
#define MQTT_COMMANDS_TOPIC_NAME "/devices/my-device/commands/#"

#define GCP_IOT_MQTT_CLIENT_ID "projects/" GCP_PROJECT_ID "/locations/" GCP_IOT_LOCATION "/registries/" GCP_IOT_REGISTRY_NAME "/devices/" GCP_IOT_DEVICE_ID

#define TEMPERATURE_PUBLISH_INTERVAL_SECONDS (2 * 60)

static char msg_payload[100];

static int fw_update_pending = 0;

void iot_subscribe_cmd_callback_handler(AWS_IoT_Client* pClient, char* topicName, uint16_t topicNameLen,
    IoT_Publish_Message_Params* params, void* pData)
{

    IOT_UNUSED(pData);
    IOT_UNUSED(pClient);
    IOT_INFO("Subscribe callback");
    IOT_INFO("%.*s\r\n%.*s", topicNameLen, topicName, (int)params->payloadLen, (char*)params->payload);
}

void iot_subscribe_config_callback_handler(AWS_IoT_Client* pClient, char* topicName, uint16_t topicNameLen,
    IoT_Publish_Message_Params* params, void* pData)
{

    int ret;
    IOT_UNUSED(pData);
    IOT_UNUSED(pClient);
    IOT_INFO("FW update message received");
    IOT_DEBUG("%.*s\r\n%.*s", topicNameLen, topicName, (int)params->payloadLen, (char*)params->payload);

    ret = ota_update_prepare((const char*)params->payload, (int)params->payloadLen);
    if (ret < 0) {
        IOT_ERROR("ota_update_prepare failed: %d", ret);
        return;
    }

    if (ret > 0) {
        fw_update_pending = 1;
    }
}

void disconnectCallbackHandler(AWS_IoT_Client* pClient, void* data)
{
    IOT_WARN("MQTT Disconnect");
    IoT_Error_t rc = FAILURE;

    if (NULL == pClient) {
        return;
    }

    IOT_UNUSED(data);

    if (aws_iot_is_autoreconnect_enabled(pClient)) {
        IOT_INFO("Auto Reconnect is enabled, Reconnecting attempt will start now");
    } else {
        IOT_WARN("Auto Reconnect not enabled. Starting manual reconnect...");
        rc = aws_iot_mqtt_attempt_reconnect(pClient);
        if (NETWORK_RECONNECTED == rc) {
            IOT_WARN("Manual Reconnect Successful");
        } else {
            IOT_WARN("Manual Reconnect Failed - %d", rc);
        }
    }
}

static const char* prepare_jwt_claims(void)
{
    static char claims[128];
    int ret;
    unsigned long now_seconds;
    ret = gsm_get_time(&now_seconds);
    if (ret < 0) {
        IOT_ERROR("gsm_get_time returned error : %d ", ret);
        return NULL;
    }

    sprintf(claims, "{ \"aud\": \"%s\", \"iat\": %lu, \"exp\": %lu }",
        GCP_PROJECT_ID, now_seconds, now_seconds + 86400);

    return &claims[0];
}

int gcp_iot_app(void)
{
    IoT_Error_t rc = FAILURE;

    AWS_IoT_Client client;
    IoT_Client_Init_Params mqttInitParams = iotClientInitParamsDefault;
    IoT_Client_Connect_Params connectParams = iotClientConnectParamsDefault;
    IoT_Publish_Message_Params paramsQOS;

    Timer temp_measure_timer;

    const unsigned char* device_key;
    const rofs_file_info_t* device_keyinfo;
    string_t jwt;
    size_t jwt_len;
    cstring_t jwt_claims;
    unsigned long jwt_calc_duration_start;
    unsigned long jwt_calc_duration_end;

    IOT_INFO("\r\nApplication Version: %lu\r\n", APP_VERSION);
    IOT_INFO("Google Cloud IoT Core with");
    IOT_INFO("AWS IoT SDK Version %d.%d.%d-%s\r\n", VERSION_MAJOR, VERSION_MINOR, VERSION_PATCH, VERSION_TAG);

    IOT_DEBUG("rootCA %s", GCP_IOT_ROOT_CA_FILENAME);

    mqttInitParams.enableAutoReconnect = false; // We enable this later below
    mqttInitParams.pHostURL = GCP_IOT_MQTT_HOST;
    mqttInitParams.port = GCP_IOT_MQTT_PORT;

    //Setting RootCA to NULL will skip server verification.
    //For ECC keys + Google mqtt LTS server, both mbedTLS and SIM7600 SSL APIs
    //fail in handshake stage when server verification is enabled. - TODO
    //To try out GCP set RootCA to NULL.
    mqttInitParams.pRootCALocation = NULL; //GCP_IOT_ROOT_CA_FILENAME;
    mqttInitParams.pDeviceCertLocation = NULL;
    mqttInitParams.pDevicePrivateKeyLocation = NULL;
    mqttInitParams.mqttCommandTimeout_ms = 30000;
    mqttInitParams.tlsHandshakeTimeout_ms = 60000;
    mqttInitParams.mqttPacketTimeout_ms = 30000;
    mqttInitParams.isSSLHostnameVerify = true;
    mqttInitParams.disconnectHandler = disconnectCallbackHandler;
    mqttInitParams.disconnectHandlerData = NULL;

    rc = aws_iot_mqtt_init(&client, &mqttInitParams);
    if (SUCCESS != rc) {
        IOT_ERROR("aws_iot_mqtt_init returned error : %d ", rc);
        return rc;
    }

    //Init JWT
    rc = jwt_init();
    if (SUCCESS != rc) {
        IOT_ERROR("jwt_init returned error : %d\r\n", rc);
        return rc;
    }

    rc = rofs_readfile(GCP_IOT_DEVICE_PRIVATE_KEY_FILENAME, &device_key, &device_keyinfo);
    if (rc < 0) {
        IOT_ERROR("rofs_readfile returned error : %d\r\n", rc);
        return rc;
    }

    rc = jwt_pk_init(device_key, device_keyinfo->length + device_keyinfo->null_added);
    if (SUCCESS != rc) {
        IOT_ERROR("jwt_pk_init returned error : %d\r\n", rc);
        return rc;
    }

    gsm_get_time(&jwt_calc_duration_start);

    jwt_claims = prepare_jwt_claims();
    if (jwt_claims == NULL) {
        IOT_ERROR("prepare_jwt_claims failed\r\n");
        return -1;
    }

    IOT_INFO("Generating JWT for claims: %s\r\n", jwt_claims);

    rc = jwt_create_RS256_token(jwt_claims, &jwt, &jwt_len);
    if (SUCCESS != rc) {
        IOT_ERROR("jwt_create_RS256_token returned error : %d\r\n", rc);
        return rc;
    }

    gsm_get_time(&jwt_calc_duration_end);

    IOT_DEBUG("JWT Generated: %lu\n%s\n", jwt_len, jwt);
    IOT_INFO("JWT computation time : %lu seconds\r\n", jwt_calc_duration_end - jwt_calc_duration_start);

    connectParams.keepAliveIntervalInSec = 300;
    connectParams.isCleanSession = true;
    connectParams.MQTTVersion = MQTT_3_1_1;
    connectParams.pClientID = GCP_IOT_MQTT_CLIENT_ID;
    connectParams.clientIDLen = (uint16_t)strlen(GCP_IOT_MQTT_CLIENT_ID);
    connectParams.isWillMsgPresent = false;
    connectParams.pUsername = "ignore";
    connectParams.usernameLen = strlen(connectParams.pUsername);
    connectParams.pPassword = jwt;
    connectParams.passwordLen = jwt_len;

    IOT_INFO("Connecting...");
    rc = aws_iot_mqtt_connect(&client, &connectParams);
    if (SUCCESS != rc) {
        IOT_ERROR("Error(%d) connecting to %s:%d", rc, mqttInitParams.pHostURL, mqttInitParams.port);
        return rc;
    }
    /*
	 * Enable Auto Reconnect functionality. Minimum and Maximum time of Exponential backoff are set in aws_iot_config.h
	 *  #AWS_IOT_MQTT_MIN_RECONNECT_WAIT_INTERVAL
	 *  #AWS_IOT_MQTT_MAX_RECONNECT_WAIT_INTERVAL
	 */
    // JWT needs to be re-generated when reconnecting.
    rc = aws_iot_mqtt_autoreconnect_set_status(&client, true);
    if (SUCCESS != rc) {
        IOT_ERROR("Unable to set Auto Reconnect to true - %d", rc);
        return rc;
    }

    IOT_INFO("Subscribing to topic: %s\n", MQTT_CONFIG_TOPIC_NAME);
    rc = aws_iot_mqtt_subscribe(&client, MQTT_CONFIG_TOPIC_NAME, strlen(MQTT_CONFIG_TOPIC_NAME), QOS1, iot_subscribe_config_callback_handler, NULL);
    if (SUCCESS != rc) {
        IOT_ERROR("Error subscribing : %d ", rc);
        return rc;
    }

    IOT_INFO("Subscribing to topic: %s\n", MQTT_COMMANDS_TOPIC_NAME);
    rc = aws_iot_mqtt_subscribe(&client, MQTT_COMMANDS_TOPIC_NAME, strlen(MQTT_COMMANDS_TOPIC_NAME), QOS1, iot_subscribe_cmd_callback_handler, NULL);
    if (SUCCESS != rc) {
        IOT_ERROR("Error subscribing : %d ", rc);
        return rc;
    }

    paramsQOS.qos = QOS0;
    paramsQOS.payload = (void*)msg_payload;
    paramsQOS.isRetained = 0;

    //NOTE device state can be updated at the rate of only 1 per second. Exceeding
    //this will cause connection to be dropped. Publish to events topic instead.
    IOT_INFO("Publishing  to topic: %s", MQTT_STATE_TOPIC_NAME);

    init_timer(&temp_measure_timer);

    do {
        if (has_timer_expired(&temp_measure_timer)) {
            unsigned long timestamp;

            gsm_get_time(&timestamp);
            sprintf(msg_payload, "Temperature: %d C\r\nTimestamp: %lu", temps_read(), timestamp);
            paramsQOS.payloadLen = strlen(msg_payload);
            IOT_INFO("Publishing: %s", msg_payload);
            rc = aws_iot_mqtt_publish(&client, MQTT_STATE_TOPIC_NAME, strlen(MQTT_STATE_TOPIC_NAME), &paramsQOS);
            countdown_sec(&temp_measure_timer, TEMPERATURE_PUBLISH_INTERVAL_SECONDS);
        } else {
            // Wait for all the messages to be received
            rc = aws_iot_mqtt_yield(&client, 1000);
        }

        if (fw_update_pending) {
            break;
        }

    } while ((NETWORK_ATTEMPTING_RECONNECT == rc || NETWORK_RECONNECTED == rc || SUCCESS == rc));

    IOT_ERROR("Closing connection. Last error = %d\r\n", rc);

    aws_iot_mqtt_disconnect(&client);

    if (fw_update_pending) {
        int ret = ota_update_run();
        if (ret < 0) {
            IOT_ERROR("ota_update_run failed= %d\r\n", ret);
            //restart aws app.
            rc = NETWORK_MANUALLY_DISCONNECTED;
        }
    }

    return rc;
}
