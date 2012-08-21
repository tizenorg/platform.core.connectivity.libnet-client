/*
 *  Network Client Library
 *
* Copyright 2012  Samsung Electronics Co., Ltd

* Licensed under the Flora License, Version 1.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at

* http://www.tizenopensource.org/license

* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
 *
 */


#ifdef __cplusplus
extern "C"
{
#endif /* __cplusplus */

/*****************************************************************************
 * 	Standard headers
 *****************************************************************************/
#include <stdio.h> 
#include <errno.h> 
#include <stdlib.h> 
#include <string.h> 
#include <glib.h>

#include <dbus/dbus.h> 

#include <sys/types.h>
#include <sys/wait.h>

#include <fcntl.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <linux/if_ether.h>

/*****************************************************************************
 * 	Platform headers
 *****************************************************************************/

#include "network-internal.h"
#include "network-dbus-request.h"

/*****************************************************************************
 * 	Macros and Typedefs
 *****************************************************************************/

/*****************************************************************************
 * 	Local Functions Declaration
 *****************************************************************************/

/*****************************************************************************
 * 	Global Functions
 *****************************************************************************/

/*****************************************************************************
 * 	Extern Global Variables
 *****************************************************************************/
extern network_info_t NetworkInfo;

/*****************************************************************************
 * 	Global Variables
 *****************************************************************************/

/** set all request to FALSE (0) */
network_request_table_t request_table[NETWORK_REQUEST_TYPE_MAX] = {{0, }, };

struct {
	pthread_mutex_t callback_mutex;
	pthread_mutex_t wifi_state_mutex;
} networkinfo_mutex;

/*****************************************************************************
 * 	Local Functions Definition
 *****************************************************************************/

char *__convert_eap_type_to_string(gchar eap_type)
{
	switch (eap_type) {
	case WLAN_SEC_EAP_TYPE_PEAP:
		return "peap";

	case WLAN_SEC_EAP_TYPE_TLS:
		return "tls";

	case WLAN_SEC_EAP_TYPE_TTLS:
		return "ttls";

	case WLAN_SEC_EAP_TYPE_SIM:
		return "sim";

	case WLAN_SEC_EAP_TYPE_AKA:
		return "aka";

	default:
		return NULL;
	}
}

char *__convert_eap_auth_to_string(gchar eap_auth)
{
	switch (eap_auth) {
	case WLAN_SEC_EAP_AUTH_NONE:
		return "NONE";

	case WLAN_SEC_EAP_AUTH_PAP:
		return "PAP";

	case WLAN_SEC_EAP_AUTH_MSCHAP:
		return "MSCHAP";

	case WLAN_SEC_EAP_AUTH_MSCHAPV2:
		return "MSCHAPV2";

	case WLAN_SEC_EAP_AUTH_GTC:
		return "GTC";

	case WLAN_SEC_EAP_AUTH_MD5:
		return "MD5";

	default:
		return NULL;
	}
}

/*****************************************************************************
 * 	Global Functions Definition
 *****************************************************************************/

char* _net_print_error(net_err_t error)
{
	switch (error) {
		/** No error */
	case NET_ERR_NONE:
		return "NET_ERR_NONE";

		/* Common Error value */

		/** Error unknown */
	case NET_ERR_UNKNOWN:
		return "NET_ERR_UNKNOWN";

		/* Client Register related Errors used in API return */

		/** Application is already registered */
	case NET_ERR_APP_ALREADY_REGISTERED:
		return "NET_ERR_APP_ALREADY_REGISTERED";
		/** Application is not registered */
	case NET_ERR_APP_NOT_REGISTERED:
		return "NET_ERR_APP_NOT_REGISTERED";

		/* Connection Related Error */

		/** No active connection exists for the given profile name */
	case NET_ERR_NO_ACTIVE_CONNECTIONS:
		return "NET_ERR_NO_ACTIVE_CONNECTIONS";
		/** Active connection already exists for the given profile name  */
	case NET_ERR_ACTIVE_CONNECTION_EXISTS:
		return "NET_ERR_ACTIVE_CONNECTION_EXISTS";

		/** Connection failure : out of range */
	case NET_ERR_CONNECTION_OUT_OF_RANGE:
		return "NET_ERR_CONNECTION_OUT_OF_RANGE";
		/** Connection failure : pin missing */
	case NET_ERR_CONNECTION_PIN_MISSING:
		return "NET_ERR_CONNECTION_PIN_MISSING";
		/** Connection failure : dhcp failed */
	case NET_ERR_CONNECTION_DHCP_FAILED:
		return "NET_ERR_CONNECTION_DHCP_FAILED";
		/** Connection failure */
	case NET_ERR_CONNECTION_CONNECT_FAILED:
		return "NET_ERR_CONNECTION_CONNECT_FAILED";
		/** Connection failure : login failed */
	case NET_ERR_CONNECTION_LOGIN_FAILED:
		return "NET_ERR_CONNECTION_LOGIN_FAILED";
		/** Connection failure : authentication failed */
	case NET_ERR_CONNECTION_AUTH_FAILED:
		return "NET_ERR_CONNECTION_AUTH_FAILED";
		/** Connection failure : invalid key */
	case NET_ERR_CONNECTION_INVALID_KEY:
		return "NET_ERR_CONNECTION_INVALID_KEY";

		/* Other Error */

		/** Access is denied */
	case NET_ERR_ACCESS_DENIED:
		return "NET_ERR_ACCESS_DENIED";
		/** Operation is in progress */
	case NET_ERR_IN_PROGRESS:
		return "NET_ERR_IN_PROGRESS";
		/** Operation was aborted by client or network*/
	case NET_ERR_OPERATION_ABORTED:
		return "NET_ERR_OPERATION_ABORTED";
		/** Invalid value of API parameter */
	case NET_ERR_INVALID_PARAM:
		return "NET_ERR_INVALID_PARAM";
		/** invalid operation depending on current state */
	case NET_ERR_INVALID_OPERATION:
		return "NET_ERR_INVALID_OPERATION";

		/** Feature not supported */
	case NET_ERR_NOT_SUPPORTED:
		return "NET_ERR_NOT_SUPPORTED";
		/** TimeOut Error */
	case NET_ERR_TIME_OUT:
		return "NET_ERR_TIME_OUT";
		/** Network service is not available*/
	case NET_ERR_NO_SERVICE:
		return "NET_ERR_NO_SERVICE";
		/** DBus can't find appropriate method */
	case NET_ERR_UNKNOWN_METHOD:
		return "NET_ERR_UNKNOWN_METHOD";
	default:
		return "INVALID";
	}
}

net_device_t _net_get_tech_type_from_path(const char *profile_name)
{
	__NETWORK_FUNC_ENTER__;

	net_device_t device_type = NET_DEVICE_UNKNOWN;

	if (g_str_has_prefix(profile_name, CONNMAN_WIFI_SERVICE_PROFILE_PREFIX) == TRUE)
		device_type = NET_DEVICE_WIFI;
	else if (g_str_has_prefix(profile_name, CONNMAN_CELLULAR_SERVICE_PROFILE_PREFIX) == TRUE)
		device_type = NET_DEVICE_CELLULAR;
	else if (g_str_has_prefix(profile_name, CONNMAN_ETHERNET_SERVICE_PROFILE_PREFIX) == TRUE)
		device_type = NET_DEVICE_ETHERNET;

	__NETWORK_FUNC_EXIT__;
	return device_type;
}

char* _net_get_string(DBusMessage* msg)
{
	__NETWORK_FUNC_ENTER__;

	DBusMessageIter args;
	char* sigvalue = NULL;

	if (!dbus_message_iter_init(msg, &args)) {
		NETWORK_LOG(NETWORK_LOW, "Message does not have parameters\n");
	} else if (dbus_message_iter_get_arg_type(&args) != DBUS_TYPE_STRING) {
		NETWORK_LOG(NETWORK_LOW, "Argument is not string\n");
	} else {
		dbus_message_iter_get_basic(&args, &sigvalue);
	}

	__NETWORK_FUNC_EXIT__;
	return sigvalue;
}

unsigned long long _net_get_uint64(DBusMessage* msg)
{
	DBusMessageIter args;
	unsigned long long sigvalue = 0;

	if (!dbus_message_iter_init(msg, &args)) {
		NETWORK_LOG(NETWORK_LOW, "Message does not have parameters\n");
	} else if (dbus_message_iter_get_arg_type(&args) != DBUS_TYPE_UINT64) {
		NETWORK_LOG(NETWORK_LOW, "Argument is not uint64\n");
	} else {
		dbus_message_iter_get_basic(&args, &sigvalue);
	}

	return sigvalue;
}

char* _net_get_object(DBusMessage* msg)
{
	__NETWORK_FUNC_ENTER__;

	DBusMessageIter args;
	char* sigvalue = NULL;

	if (!dbus_message_iter_init(msg, &args)) {
		NETWORK_LOG(NETWORK_LOW, "Message does not have parameters\n");
	} else if (dbus_message_iter_get_arg_type(&args) != DBUS_TYPE_OBJECT_PATH) {
		NETWORK_LOG(NETWORK_LOW, "Argument is not string\n");
	} else {
		dbus_message_iter_get_basic(&args, &sigvalue);
	}

	__NETWORK_FUNC_EXIT__;
	return sigvalue;
}

int _net_get_boolean(DBusMessage* msg)
{
	__NETWORK_FUNC_ENTER__;

	DBusMessageIter args;
	dbus_bool_t val = FALSE;
	int retvalue = FALSE;

	if (!dbus_message_iter_init(msg, &args)) {
		NETWORK_LOG(NETWORK_LOW, "Message does not have parameters\n");
	} else if (dbus_message_iter_get_arg_type(&args) != DBUS_TYPE_BOOLEAN) {
		NETWORK_LOG(NETWORK_LOW, "Argument is not boolean\n");
	} else {
		dbus_message_iter_get_basic(&args, &val);

		if (val)
			retvalue = TRUE;
		else
			retvalue = FALSE;
	}

	__NETWORK_FUNC_EXIT__;
	return retvalue;
}

int _net_get_path(DBusMessage *msg, char *profile_name)
{
	__NETWORK_FUNC_ENTER__;

	char* ProfileName = NULL;

	ProfileName = (char*)dbus_message_get_path(msg);
	snprintf(profile_name, strlen(ProfileName) + 1, "%s", ProfileName);

	__NETWORK_FUNC_EXIT__;

	return NET_ERR_NONE;
}

int _net_get_tech_state(DBusMessage* msg, network_get_tech_state_info_t* tech_state)
{
	__NETWORK_FUNC_ENTER__;

	net_err_t Error = NET_ERR_NONE;
	DBusMessageIter args, dict;

	if (!dbus_message_iter_init(msg, &args)) {
		NETWORK_LOG(NETWORK_LOW, "Message does not have parameters\n");
		Error = NET_ERR_UNKNOWN;
		goto done;
	}

	dbus_message_iter_recurse(&args, &dict);

	while (dbus_message_iter_get_arg_type(&dict) == DBUS_TYPE_DICT_ENTRY) {
		DBusMessageIter key_iter, sub_iter1, sub_iter2;
		const char *key = NULL;
		const char *tech_name = NULL;

		dbus_message_iter_recurse(&dict, &key_iter);
		dbus_message_iter_get_basic(&key_iter, &key);

		if (strcmp(key, "AvailableTechnologies") == 0 ||
		    strcmp(key, "EnabledTechnologies") == 0 ||
		    strcmp(key, "ConnectedTechnologies") == 0) {
			dbus_message_iter_next(&key_iter);
			dbus_message_iter_recurse(&key_iter, &sub_iter1);

			if (dbus_message_iter_get_arg_type(&sub_iter1) == DBUS_TYPE_ARRAY)
				dbus_message_iter_recurse(&sub_iter1, &sub_iter2);
			else
				goto next_dict;

			while (dbus_message_iter_get_arg_type(&sub_iter2) == DBUS_TYPE_STRING) {
				dbus_message_iter_get_basic(&sub_iter2, &tech_name);
				if (tech_name != NULL &&
				    strcmp(tech_name, tech_state->technology) == 0) {
					if (strcmp(key, "AvailableTechnologies") == 0)
						tech_state->AvailableTechnology = TRUE;
					else if (strcmp(key, "EnabledTechnologies") == 0)
						tech_state->EnabledTechnology = TRUE;
					else
						tech_state->ConnectedTechnology = TRUE;
				}

				dbus_message_iter_next(&sub_iter2);
			}
		} else if (strcmp(key, "DefaultTechnology") == 0) {
			dbus_message_iter_next(&key_iter);
			dbus_message_iter_recurse(&key_iter, &sub_iter1);

			if (dbus_message_iter_get_arg_type(&sub_iter1) == DBUS_TYPE_STRING) {
				dbus_message_iter_get_basic(&sub_iter1, &tech_name);
				if (tech_name != NULL && strcmp(tech_name, tech_state->technology) == 0)
					tech_state->DefaultTechnology = TRUE;
			}
		}
next_dict:
		dbus_message_iter_next(&dict);
	}

done:
	__NETWORK_FUNC_EXIT__;
	return Error;
}

/** This function is used only to open Wi-Fi connection with hidden APs */
int _net_open_connection_with_wifi_info(const net_wifi_connection_info_t* wifi_info)
{
	__NETWORK_FUNC_ENTER__;

	net_err_t Error = NET_ERR_NONE;

	net_wifi_connect_service_info_t wifi_connection_info;
	memset(&wifi_connection_info, 0, sizeof(net_wifi_connect_service_info_t));

	wifi_connection_info.type = g_strdup("wifi");

	if (wifi_info->wlan_mode == NETPM_WLAN_CONNMODE_ADHOC)
		wifi_connection_info.mode = g_strdup("adhoc");
	else
		wifi_connection_info.mode = g_strdup("managed");

	wifi_connection_info.ssid = g_strdup(wifi_info->essid);

	switch (wifi_info->security_info.sec_mode) {
	case WLAN_SEC_MODE_NONE:
		wifi_connection_info.security = g_strdup("none");
		break;

	case WLAN_SEC_MODE_WEP:
		wifi_connection_info.security = g_strdup("wep");
		wifi_connection_info.passphrase = g_strdup(wifi_info->security_info.authentication.wep.wepKey);
		break;

	/** WPA-PSK(equivalent to WPA-NONE in case of Ad-Hoc) */
	case WLAN_SEC_MODE_WPA_PSK:
		wifi_connection_info.security = g_strdup("psk");
		wifi_connection_info.passphrase = g_strdup(wifi_info->security_info.authentication.psk.pskKey);
		break;

	/** WPA2-PSK */
	/** WPA-PSK / WPA2-PSK supported */
	case WLAN_SEC_MODE_WPA2_PSK:
		wifi_connection_info.security = g_strdup("rsn");
		wifi_connection_info.passphrase = g_strdup(wifi_info->security_info.authentication.psk.pskKey);
		break;

	case WLAN_SEC_MODE_IEEE8021X:
		wifi_connection_info.security = g_strdup("ieee8021x");

		wifi_connection_info.eap_type = g_strdup(
				__convert_eap_type_to_string(wifi_info->security_info.authentication.eap.eap_type));
		wifi_connection_info.eap_auth = g_strdup(
				__convert_eap_auth_to_string(wifi_info->security_info.authentication.eap.eap_auth));

		if (wifi_info->security_info.authentication.eap.username != NULL)
			if (strlen(wifi_info->security_info.authentication.eap.username) > 0)
				wifi_connection_info.identity = g_strdup(wifi_info->security_info.authentication.eap.username);

		if (wifi_info->security_info.authentication.eap.password != NULL)
			if (strlen(wifi_info->security_info.authentication.eap.password) > 0)
				wifi_connection_info.password = g_strdup(wifi_info->security_info.authentication.eap.password);

		if (wifi_info->security_info.authentication.eap.ca_cert_filename != NULL)
			if (strlen(wifi_info->security_info.authentication.eap.ca_cert_filename) > 0)
				wifi_connection_info.ca_cert_file = g_strdup(wifi_info->security_info.authentication.eap.ca_cert_filename);

		if (wifi_info->security_info.authentication.eap.client_cert_filename != NULL)
			if (strlen(wifi_info->security_info.authentication.eap.client_cert_filename) > 0)
				wifi_connection_info.client_cert_file = g_strdup(wifi_info->security_info.authentication.eap.client_cert_filename);

		if (wifi_info->security_info.authentication.eap.private_key_filename != NULL)
			if (strlen(wifi_info->security_info.authentication.eap.private_key_filename) > 0)
				wifi_connection_info.private_key_file = g_strdup(wifi_info->security_info.authentication.eap.private_key_filename);

		if (wifi_info->security_info.authentication.eap.private_key_passwd != NULL)
			if (strlen(wifi_info->security_info.authentication.eap.private_key_passwd) > 0)
				wifi_connection_info.private_key_password = g_strdup(wifi_info->security_info.authentication.eap.private_key_passwd);

		break;

	default:
		NETWORK_LOG(NETWORK_ERROR, "Error!!! Invalid security type\n");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_INVALID_PARAM;
	}

	NETWORK_LOG(NETWORK_HIGH,
			"Parameters: type:\t%s\nmode:\t%s\nssid:\t%s\nsecurity:\t%s\npassphrase:\t%s\n",
			wifi_connection_info.type, wifi_connection_info.mode,
			wifi_connection_info.ssid, wifi_connection_info.security,
			wifi_connection_info.passphrase);

	if (wifi_info->security_info.sec_mode == WLAN_SEC_MODE_IEEE8021X) {
		NETWORK_LOG(NETWORK_HIGH,
				"Wi-Fi Enterprise type:\t%s\nauth:\t%s\nidentity:\t%s\npassword:\t%s\n",
				wifi_connection_info.eap_type, wifi_connection_info.eap_auth,
				wifi_connection_info.identity, wifi_connection_info.password);
		NETWORK_LOG(NETWORK_HIGH,
				"CA cert:\t%s\nClient cert:\t%s\nPrivate key:\t%s\nPrivate key password:\t%s\n",
				wifi_connection_info.ca_cert_file, wifi_connection_info.client_cert_file,
				wifi_connection_info.private_key_file, wifi_connection_info.private_key_password);
	}

	if ((Error = _net_dbus_connect_service(&wifi_connection_info)) != NET_ERR_NONE)
		NETWORK_LOG(NETWORK_EXCEPTION, "Failed to request connect service. Error [%s]\n",
				_net_print_error(Error));
	else
		NETWORK_LOG(NETWORK_HIGH, "Successfully requested to connect service\n");

	g_free(wifi_connection_info.type);
	g_free(wifi_connection_info.mode);
	g_free(wifi_connection_info.ssid);
	g_free(wifi_connection_info.security);
	g_free(wifi_connection_info.passphrase);
	g_free(wifi_connection_info.eap_type);
	g_free(wifi_connection_info.eap_auth);
	g_free(wifi_connection_info.identity);
	g_free(wifi_connection_info.password);
	g_free(wifi_connection_info.ca_cert_file);
	g_free(wifi_connection_info.client_cert_file);
	g_free(wifi_connection_info.private_key_file);
	g_free(wifi_connection_info.private_key_password);

	__NETWORK_FUNC_EXIT__;
	return Error;
}

int _net_mutex_init(void)
{
	__NETWORK_FUNC_ENTER__;

	if (pthread_mutex_init(&networkinfo_mutex.callback_mutex, NULL) != 0) {
		NETWORK_LOG(NETWORK_ERROR, "Mutex for callback initialization failed!\n");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_UNKNOWN;
	}

	if (pthread_mutex_init(&networkinfo_mutex.wifi_state_mutex, NULL) != 0) {
		NETWORK_LOG(NETWORK_ERROR, "Mutex for wifi state initialization failed!\n");
		pthread_mutex_destroy(&networkinfo_mutex.callback_mutex);
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_UNKNOWN;
	}

	__NETWORK_FUNC_EXIT__;
	return NET_ERR_NONE;
}

void _net_mutex_destroy(void)
{
	__NETWORK_FUNC_ENTER__;

	pthread_mutex_destroy(&networkinfo_mutex.callback_mutex);
	pthread_mutex_destroy(&networkinfo_mutex.wifi_state_mutex);

	__NETWORK_FUNC_EXIT__;
}

void _net_client_callback(net_event_info_t *event_data)
{
	pthread_mutex_lock(&networkinfo_mutex.callback_mutex);
	__NETWORK_FUNC_ENTER__;

	if (NetworkInfo.ClientEventCb != NULL)
		NetworkInfo.ClientEventCb(event_data, NetworkInfo.user_data);

	if (NetworkInfo.ClientEventCb_conn != NULL)
		NetworkInfo.ClientEventCb_conn(event_data, NetworkInfo.user_data_conn);

	if (NetworkInfo.ClientEventCb_wifi != NULL)
		NetworkInfo.ClientEventCb_wifi(event_data, NetworkInfo.user_data_wifi);

	__NETWORK_FUNC_EXIT__;
	pthread_mutex_unlock(&networkinfo_mutex.callback_mutex);
}

net_wifi_state_t _net_get_wifi_state(void)
{
	pthread_mutex_lock(&networkinfo_mutex.wifi_state_mutex);
	__NETWORK_FUNC_ENTER__;

	net_err_t Error = NET_ERR_NONE;
	network_get_tech_state_info_t tech_state = {{0,},};
	net_wifi_state_t wifi_state = WIFI_UNKNOWN;

	snprintf(tech_state.technology, NET_TECH_LENGTH_MAX, "%s", "wifi");
	Error = _net_dbus_get_technology_state(&tech_state);
	if (Error != NET_ERR_NONE) {
		NETWORK_LOG(NETWORK_ERROR,
			"Error!!! _net_dbus_get_technology_state() failed. Error [%s]\n",
			_net_print_error(Error));
		goto state_done;
	}

	if (tech_state.EnabledTechnology == TRUE &&
	    tech_state.AvailableTechnology == TRUE)
		wifi_state = WIFI_ON;
	else
		wifi_state = WIFI_OFF;

state_done:
	__NETWORK_FUNC_EXIT__;
	pthread_mutex_unlock(&networkinfo_mutex.wifi_state_mutex);
	return wifi_state;
}

void _net_clear_request_table(void)
{
	__NETWORK_FUNC_ENTER__;

	int i = 0;

	for (i = 0;i < NETWORK_REQUEST_TYPE_MAX;i++)
		memset(&request_table[i], 0, sizeof(network_request_table_t));

	__NETWORK_FUNC_EXIT__;
}

#ifdef __cplusplus
}
#endif /* __cplusplus */
