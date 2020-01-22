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

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <limits.h>
#include <string.h>

#include "aws_iot_config.h"
#include "aws_iot_log.h"
#include "aws_iot_version.h"
#include "aws_iot_mqtt_client_interface.h"
#include "temp_sensor.h"

#include "sim7600_gprs.h"

#include "ota_update.h"
#include "version.h"

#define MQTT_TOPIC_EVENTS		"test/events"
#define MQTT_TOPIC_OTA_UPDATE   "test/ota_update"

#define TEMPERATURE_PUBLISH_INTERVAL_SECONDS	(2*60)

static char msg_payload[100];

static int fw_update_pending = 0;

void iot_subscribe_ota_update_handler(AWS_IoT_Client *pClient, char *topicName, uint16_t topicNameLen,
									IoT_Publish_Message_Params *params, void *pData) {

	int ret;
    IOT_UNUSED(pData);
	IOT_UNUSED(pClient);
	IOT_INFO("FW update message received");
	IOT_DEBUG("%.*s\r\n%.*s", topicNameLen, topicName, (int) params->payloadLen, (char *) params->payload);


    ret = ota_update_prepare((const char *) params->payload, (int) params->payloadLen);
    if (ret < 0)
    {
        IOT_ERROR("ota_update_prepare failed: %d", ret);
        return;
    }

    if (ret > 0)
    {
        fw_update_pending = 1;
    }

}

void disconnectCallbackHandler(AWS_IoT_Client *pClient, void *data) {
	IOT_WARN("MQTT Disconnect");
	IoT_Error_t rc = FAILURE;

	if(NULL == pClient) {
		return;
	}

	IOT_UNUSED(data);

	if(aws_iot_is_autoreconnect_enabled(pClient)) {
		IOT_INFO("Auto Reconnect is enabled, Reconnecting attempt will start now");
	} else {
		IOT_WARN("Auto Reconnect not enabled. Starting manual reconnect...");
		rc = aws_iot_mqtt_attempt_reconnect(pClient);
		if(NETWORK_RECONNECTED == rc) {
			IOT_WARN("Manual Reconnect Successful");
		} else {
			IOT_WARN("Manual Reconnect Failed - %d", rc);
		}
	}
}

int aws_iot_app(void) {
	IoT_Error_t rc = FAILURE;

	AWS_IoT_Client client;
	IoT_Client_Init_Params mqttInitParams = iotClientInitParamsDefault;
	IoT_Client_Connect_Params connectParams = iotClientConnectParamsDefault;

	IoT_Publish_Message_Params paramsQOS;
	
	Timer temp_measure_timer;
	
	IOT_INFO("\r\nApplication Version: %lu\r\n", APP_VERSION);
    IOT_INFO("Amazon Web Services IoT Core with");
	IOT_INFO("\nAWS IoT SDK Version %d.%d.%d-%s\n", VERSION_MAJOR, VERSION_MINOR, VERSION_PATCH, VERSION_TAG);

	IOT_DEBUG("rootCA %s", AWS_IOT_ROOT_CA_FILENAME);
	IOT_DEBUG("clientCRT %s", AWS_IOT_DEVICE_CERTIFICATE_FILENAME);
	IOT_DEBUG("clientKey %s", AWS_IOT_DEVICE_PRIVATE_KEY_FILENAME);
	
	mqttInitParams.enableAutoReconnect = false; // We enable this later below
	mqttInitParams.pHostURL = AWS_IOT_MQTT_HOST;
	mqttInitParams.port = AWS_IOT_MQTT_PORT;
	mqttInitParams.pRootCALocation = AWS_IOT_ROOT_CA_FILENAME;
	mqttInitParams.pDeviceCertLocation = AWS_IOT_DEVICE_CERTIFICATE_FILENAME;
	mqttInitParams.pDevicePrivateKeyLocation = AWS_IOT_DEVICE_PRIVATE_KEY_FILENAME;
	mqttInitParams.mqttCommandTimeout_ms = 30000;
	mqttInitParams.tlsHandshakeTimeout_ms = 60000;
	mqttInitParams.mqttPacketTimeout_ms = 30000;
	mqttInitParams.isSSLHostnameVerify = true;
	mqttInitParams.disconnectHandler = disconnectCallbackHandler;
	mqttInitParams.disconnectHandlerData = NULL;

	rc = aws_iot_mqtt_init(&client, &mqttInitParams);
	if(SUCCESS != rc) {
		IOT_ERROR("aws_iot_mqtt_init returned error : %d ", rc);
		return rc;
	}

	connectParams.keepAliveIntervalInSec = 300;
	connectParams.isCleanSession = true;
	connectParams.MQTTVersion = MQTT_3_1_1;
	connectParams.pClientID = AWS_IOT_MQTT_CLIENT_ID;
	connectParams.clientIDLen = (uint16_t) strlen(AWS_IOT_MQTT_CLIENT_ID);
	connectParams.isWillMsgPresent = false;

	IOT_INFO("Connecting...");
	rc = aws_iot_mqtt_connect(&client, &connectParams);
	if(SUCCESS != rc) {
		IOT_ERROR("Error(%d) connecting to %s:%d", rc, mqttInitParams.pHostURL, mqttInitParams.port);
		return rc;
	}
	/*
	 * Enable Auto Reconnect functionality. Minimum and Maximum time of Exponential backoff are set in aws_iot_config.h
	 *  #AWS_IOT_MQTT_MIN_RECONNECT_WAIT_INTERVAL
	 *  #AWS_IOT_MQTT_MAX_RECONNECT_WAIT_INTERVAL
	 */
	rc = aws_iot_mqtt_autoreconnect_set_status(&client, true);
	if(SUCCESS != rc) {
		IOT_ERROR("Unable to set Auto Reconnect to true - %d", rc);
		return rc;
	}

	IOT_INFO("Subscribing...");
	rc = aws_iot_mqtt_subscribe(&client, MQTT_TOPIC_OTA_UPDATE, 
                strlen(MQTT_TOPIC_OTA_UPDATE), 
                QOS1, 
                iot_subscribe_ota_update_handler, NULL);
                
	if(SUCCESS != rc) {
		IOT_ERROR("Error subscribing : %d ", rc);
		return rc;
	}

	paramsQOS.qos = QOS0;
	paramsQOS.payload = (void *) msg_payload;
	paramsQOS.isRetained = 0;
	
	IOT_INFO("Publishing...");
	
	init_timer(&temp_measure_timer);

	do
	{
		if (has_timer_expired(&temp_measure_timer))
		{
			unsigned long timestamp;
			
			gsm_get_time(&timestamp);
			sprintf(msg_payload, "Temperature: %d C\r\nTimestamp: %lu", temps_read(), timestamp);
			paramsQOS.payloadLen = strlen(msg_payload);
			IOT_INFO("Publishing: %s", msg_payload);
			rc = aws_iot_mqtt_publish(&client, MQTT_TOPIC_EVENTS, strlen(MQTT_TOPIC_EVENTS), &paramsQOS);
			countdown_sec(&temp_measure_timer, TEMPERATURE_PUBLISH_INTERVAL_SECONDS);
		}
		else
		{
			// Wait for all the messages to be received
			rc = aws_iot_mqtt_yield(&client, 1000);
		}

        if (fw_update_pending)
        {
            break;
        }

	} while((NETWORK_ATTEMPTING_RECONNECT == rc || NETWORK_RECONNECTED == rc || SUCCESS == rc));
	
	IOT_ERROR("Closing connection. Last error= %d\r\n", rc);

	aws_iot_mqtt_disconnect(&client);

    if (fw_update_pending)
    {
        int ret = ota_update_run();
        if (ret < 0)
        {
            IOT_ERROR("ota_update_run failed= %d\r\n", ret);
            //restart aws app.
            rc = NETWORK_MANUALLY_DISCONNECTED;
        }
    }
	
	return rc;
}
