/*
 *  Network Client Library
 *
 * Copyright 2011-2013 Samsung Electronics Co., Ltd

 * Licensed under the Flora License, Version 1.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at

 * http://floralicense.org/license/

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

#include <vconf.h>
#include <dbus/dbus.h>
#include <dbus/dbus-glib-lowlevel.h>

/*****************************************************************************
 * 	Platform headers
 *****************************************************************************/

#include "network-internal.h"
#include "network-signal-handler.h"
#include "network-dbus-request.h"

/*****************************************************************************
 * 	Macros and Typedefs
 *****************************************************************************/


/*****************************************************************************
 * 	Local Functions Declaration
 *****************************************************************************/
static DBusHandlerResult __net_signal_filter
      (DBusConnection *conn, DBusMessage *msg, void *user_data);

static int __net_get_state(DBusMessage *msg, char *state, char *error);
static char* __net_get_property(DBusMessage* msg, char** prop_value, int *value);
static int __net_handle_scan_rsp(DBusMessage* msg);
static int __net_handle_wifi_power_rsp(int value);
static int __net_svc_error_string_to_enum(const char *error);
static void __net_handle_svc_failure_ind(const char *profile_name, const char *svc_error);
static void __net_handle_state_ind(const char* profile_name, net_state_type_t profile_state);
static void __net_init_dbus_thread();

/*****************************************************************************
 * 	Global Functions
 *****************************************************************************/


/*****************************************************************************
 * 	Extern Global Variables
 *****************************************************************************/
extern network_info_t NetworkInfo;
extern network_request_table_t request_table[NETWORK_REQUEST_TYPE_MAX];

/*****************************************************************************
 * 	Extern Functions Declarations 
 *****************************************************************************/

/*****************************************************************************
 * 	Global Variables
 *****************************************************************************/
DBusConnection* signal_conn = NULL;
static net_state_type_t service_state_table[NET_DEVICE_MAX] = {NET_STATE_TYPE_UNKNOWN,};

/*****************************************************************************
 * 	Local Functions Definition
 *****************************************************************************/

static int __net_get_state(DBusMessage *msg, char *state, char *error)
{
	__NETWORK_FUNC_ENTER__;

	char *key_name = NULL;
	char *svc_state = NULL;
	char *svc_error = NULL;
	DBusMessageIter iter, sub_iter;
	int Error = NET_ERR_UNKNOWN;

	/* Get state */
	dbus_message_iter_init(msg, &iter);
	int ArgType = dbus_message_iter_get_arg_type(&iter);

	if (ArgType != DBUS_TYPE_STRING)
		goto done;

	dbus_message_iter_get_basic(&iter, &key_name);
	if (strcmp(key_name, "State") != 0)
		goto done;

	dbus_message_iter_next(&iter);
	ArgType = dbus_message_iter_get_arg_type(&iter);
	if (ArgType != DBUS_TYPE_VARIANT)
		goto done;

	dbus_message_iter_recurse(&iter, &sub_iter);
	ArgType = dbus_message_iter_get_arg_type(&sub_iter);
	if (ArgType != DBUS_TYPE_STRING)
		goto done;

	dbus_message_iter_get_basic(&sub_iter, &svc_state);
	snprintf(state, strlen(svc_state) + 1, "%s", svc_state);
	Error = NET_ERR_NONE;

	/* Get error */
	dbus_message_iter_next(&iter);
	ArgType = dbus_message_iter_get_arg_type(&iter);
	if (ArgType != DBUS_TYPE_STRING)
		goto done;

	dbus_message_iter_get_basic(&iter, &key_name);
	if (strcmp(key_name, "Error") != 0)
		goto done;

	dbus_message_iter_next(&iter);
	ArgType = dbus_message_iter_get_arg_type(&iter);
	if (ArgType != DBUS_TYPE_VARIANT)
		goto done;

	dbus_message_iter_recurse(&iter, &sub_iter);
	ArgType = dbus_message_iter_get_arg_type(&sub_iter);
	if (ArgType != DBUS_TYPE_STRING)
		goto done;

	dbus_message_iter_get_basic(&sub_iter, &svc_error);
	snprintf(error, strlen(svc_error) + 1, "%s", svc_error);

done:
	__NETWORK_FUNC_EXIT__;
	return Error;
}

static char* __net_get_property(DBusMessage* msg, char** prop_value, int *value)
{
	DBusMessageIter args, variant;
	char* property = NULL;
	dbus_bool_t data;

	__NETWORK_FUNC_ENTER__;

	if (!dbus_message_iter_init(msg, &args)) {
		NETWORK_LOG( NETWORK_LOW, "Message does not have parameters\n");
	} else if (dbus_message_iter_get_arg_type(&args) != DBUS_TYPE_STRING) {
		NETWORK_LOG( NETWORK_LOW, "Argument is not string\n");
	} else {
		dbus_message_iter_get_basic(&args, &property);
		dbus_message_iter_next(&args);
		dbus_message_iter_recurse(&args, &variant);
		if (dbus_message_iter_get_arg_type(&variant) == DBUS_TYPE_STRING) {
			NETWORK_LOG( NETWORK_LOW, "DBUS_TYPE_STRING\n");
			dbus_message_iter_get_basic(&variant, prop_value);
		} else if (dbus_message_iter_get_arg_type(&variant) == DBUS_TYPE_BOOLEAN) {
			NETWORK_LOG( NETWORK_LOW, "DBUS_TYPE_BOOLEAN\n");
			dbus_message_iter_get_basic(&variant, &data);
			NETWORK_LOG( NETWORK_LOW, "value - [%s]\n", data ? "True" : "False");
			if (data)
				*value = TRUE;
			else
				*value = FALSE;
		} else {
			NETWORK_LOG( NETWORK_LOW, "Type NULL\n");
			*prop_value = NULL;
		}
	}

	__NETWORK_FUNC_EXIT__;
	return property;
}

/* ScanCompleted signal is no more used */
#if 0
static int __net_handle_scan_rsp(DBusMessage* msg)
{
	__NETWORK_FUNC_ENTER__;

	int boolvalue = FALSE;
	net_event_info_t event_data = {0,};

	boolvalue = _net_get_boolean(msg);
	if(boolvalue == TRUE)
		event_data.Error = NET_ERR_NONE;
	else
		event_data.Error = NET_ERR_UNKNOWN;

	NETWORK_LOG( NETWORK_LOW, "[Manager : ScanCompleted] Got Signal with value [%d]\n", boolvalue);

	if(request_table[NETWORK_REQUEST_TYPE_SCAN].flag == TRUE)
	{
		memset(&request_table[NETWORK_REQUEST_TYPE_SCAN], 0, sizeof(network_request_table_t));

		event_data.Event = NET_EVENT_WIFI_SCAN_RSP;
		event_data.Datalength = 0;
		event_data.Data = NULL;
		NETWORK_LOG(NETWORK_LOW, "Sending NET_EVENT_WIFI_SCAN_RSP\n");
		_net_client_callback(&event_data);
	}
	else
	{
		event_data.Event = NET_EVENT_WIFI_SCAN_IND;
		event_data.Datalength = 0;
		event_data.Data = NULL;
		NETWORK_LOG(NETWORK_LOW, "Sending NET_EVENT_WIFI_SCAN_IND\n");
		_net_client_callback(&event_data);
	}

	__NETWORK_FUNC_EXIT__;
	return NET_ERR_NONE;
}
#endif

static int __net_handle_services_changed_signal(DBusMessage* msg)
{
	__NETWORK_FUNC_ENTER__;

	net_event_info_t event_data = {0,};

	/* TODO: Need to analyze further the handling for this signal.
	 * And also check the contents associated w.r.t the msg received.
	 * Temporarily sending below events to the UI.
	 */
	event_data.Error = NET_ERR_NONE;
	event_data.Event = NET_EVENT_WIFI_SCAN_IND;
	event_data.Datalength = 0;
	event_data.Data = NULL;
	NETWORK_LOG(NETWORK_LOW, "Sending NET_EVENT_WIFI_SCAN_IND\n");
	_net_client_callback(&event_data);

	__NETWORK_FUNC_EXIT__;
	return NET_ERR_NONE;
}

static int __net_handle_wifi_power_rsp(int value)
{
	__NETWORK_FUNC_ENTER__;

	int wifi_state_flag = 0;
	net_event_info_t event_data = {0,};
	int hotspot_state = 0;

	vconf_get_int(VCONFKEY_MOBILE_HOTSPOT_MODE, &hotspot_state);
	if (hotspot_state & VCONFKEY_MOBILE_HOTSPOT_MODE_WIFI) {
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_NONE;
	}

	if (value == FALSE && NetworkInfo.wifi_state != WIFI_OFF) {
		NetworkInfo.wifi_state = WIFI_OFF;
		wifi_state_flag = 1;
		event_data.Error = NET_ERR_NONE;

		if(request_table[NETWORK_REQUEST_TYPE_SCAN].flag == TRUE)
			memset(&request_table[NETWORK_REQUEST_TYPE_SCAN],
					0, sizeof(network_request_table_t));

	} else if (value == TRUE && NetworkInfo.wifi_state != WIFI_ON) {
		NetworkInfo.wifi_state = WIFI_ON;
		wifi_state_flag = 1;
		event_data.Error = NET_ERR_NONE;
	}

	if (wifi_state_flag != 0) {
		if (request_table[NETWORK_REQUEST_TYPE_WIFI_POWER].flag == TRUE) {
			memset(&request_table[NETWORK_REQUEST_TYPE_WIFI_POWER],
					0, sizeof(network_request_table_t));

			event_data.Event = NET_EVENT_WIFI_POWER_RSP;
			NETWORK_LOG(NETWORK_LOW,
					"Sending NET_EVENT_WIFI_POWER_RSP  wifi state : %d\n",
					NetworkInfo.wifi_state);
			_net_dbus_clear_pending_call();
		} else {
			event_data.Event = NET_EVENT_WIFI_POWER_IND;
			NETWORK_LOG(NETWORK_LOW,
					"Sending NET_EVENT_WIFI_POWER_IND  wifi state : %d\n",
					NetworkInfo.wifi_state);
		}

		event_data.Datalength = sizeof(net_wifi_state_t);
		event_data.Data = &(NetworkInfo.wifi_state);
		_net_client_callback(&event_data);
	}

	__NETWORK_FUNC_EXIT__;
	return NET_ERR_NONE;
}

static int __net_handle_specific_scan_resp(GSList *bss_info_list)
{
	__NETWORK_FUNC_ENTER__;

	net_event_info_t event_data = {0,};

	if (request_table[NETWORK_REQUEST_TYPE_SPECIFIC_SCAN].flag == TRUE) {
		memset(&request_table[NETWORK_REQUEST_TYPE_SPECIFIC_SCAN],
				0, sizeof(network_request_table_t));

		_net_dbus_clear_pending_call();

		event_data.Event = NET_EVENT_SPECIFIC_SCAN_IND;
		NETWORK_LOG(NETWORK_LOW,
				"Sending NET_EVENT_SPECIFIC_SCAN_IND  wifi state : %d\n",
				NetworkInfo.wifi_state);

		NETWORK_LOG(NETWORK_LOW, "bss_info_list : 0x%x\n", bss_info_list);
		event_data.Data = bss_info_list;
		_net_client_callback(&event_data);
	}

	__NETWORK_FUNC_EXIT__;
	return NET_ERR_NONE;
}

static int __net_svc_error_string_to_enum(const char *error)
{
	if (strcmp(error, "out-of-range") == 0)
		return NET_ERR_CONNECTION_OUT_OF_RANGE;
	else if (strcmp(error, "pin-missing") == 0)
		return NET_ERR_CONNECTION_PIN_MISSING;
	else if (strcmp(error, "dhcp-failed") == 0)
		return NET_ERR_CONNECTION_DHCP_FAILED;
	else if (strcmp(error, "connect-failed") == 0)
		return NET_ERR_CONNECTION_CONNECT_FAILED;
	else if (strcmp(error, "login-failed") == 0)
		return NET_ERR_CONNECTION_LOGIN_FAILED;
	else if (strcmp(error, "auth-failed") == 0)
		return NET_ERR_CONNECTION_AUTH_FAILED;
	else if (strcmp(error, "invalid-key") == 0)
		return NET_ERR_CONNECTION_INVALID_KEY;

	return NET_ERR_UNKNOWN;
}

static void __net_handle_svc_failure_ind(const char *profile_name, const char *svc_error)
{
	__NETWORK_FUNC_ENTER__;

	net_event_info_t event_data = {0,};
	char event_string[64] = {0,};

	char *svc_name1 = request_table[NETWORK_REQUEST_TYPE_OPEN_CONNECTION].ProfileName;
	char *svc_name2 = request_table[NETWORK_REQUEST_TYPE_ENROLL_WPS].ProfileName;

	if (request_table[NETWORK_REQUEST_TYPE_OPEN_CONNECTION].flag == TRUE &&
	    strstr(profile_name, svc_name1) != NULL) {

		memset(&request_table[NETWORK_REQUEST_TYPE_OPEN_CONNECTION], 0,
				sizeof(network_request_table_t));

		event_data.Event = NET_EVENT_OPEN_RSP;
		g_strlcpy(event_string, "Sending NET_EVENT_OPEN_RSP", 64);
		_net_dbus_clear_pending_call();
	} else if (request_table[NETWORK_REQUEST_TYPE_ENROLL_WPS].flag == TRUE &&
	           strcmp(profile_name, svc_name2) == 0) {

		memset(&request_table[NETWORK_REQUEST_TYPE_ENROLL_WPS], 0,
				sizeof(network_request_table_t));

		event_data.Event = NET_EVENT_WIFI_WPS_RSP;
		g_strlcpy(event_string, "Sending NET_EVENT_WIFI_WPS_RSP", 64);
		_net_dbus_clear_pending_call();
	} else {
		__net_handle_state_ind(profile_name, NET_STATE_TYPE_FAILURE);
		__NETWORK_FUNC_EXIT__;
		return;
	}

	snprintf(event_data.ProfileName,
			NET_PROFILE_NAME_LEN_MAX+1, "%s", profile_name);

	event_data.Error = __net_svc_error_string_to_enum(svc_error);
	event_data.Datalength = 0;
	event_data.Data = NULL;

	NETWORK_LOG(NETWORK_LOW, "%s, Error : %d\n", event_string, event_data.Error);
	_net_client_callback(&event_data);

	__NETWORK_FUNC_EXIT__;
}

static void __net_handle_state_ind(const char* profile_name, net_state_type_t profile_state)
{
	__NETWORK_FUNC_ENTER__;
	
	net_event_info_t event_data = {0,};
	
	event_data.Error = NET_ERR_NONE;
	event_data.Event = NET_EVENT_NET_STATE_IND;

	g_strlcpy(event_data.ProfileName, profile_name,
			sizeof(event_data.ProfileName));
	
	event_data.Datalength = sizeof(net_state_type_t);
	event_data.Data = &profile_state;
	
	NETWORK_LOG(NETWORK_LOW, "Sending NET_EVENT_NET_STATE_IND, state : %d, profile name : %s\n",
			profile_state, event_data.ProfileName);

	_net_client_callback(&event_data);
	
	__NETWORK_FUNC_EXIT__;
}

static wlan_security_mode_type_t __net_get_wlan_sec_mode(int security)
{
	switch (security) {
	default:
		return WLAN_SEC_MODE_NONE;
	case 2:
		return WLAN_SEC_MODE_WEP;
	case 3:
		return WLAN_SEC_MODE_WPA_PSK;
	case 4:
		return WLAN_SEC_MODE_IEEE8021X;
	}
}

static DBusHandlerResult
__net_signal_filter (DBusConnection* conn, DBusMessage* msg, void* user_data)
{
	__NETWORK_FUNC_ENTER__;

	static char svc_state[CONNMAN_MAX_BUFLEN] = "";
	static char svc_error[CONNMAN_MAX_BUFLEN] = "";
	static char ProfileName[NET_PROFILE_NAME_LEN_MAX + 1] = "";

	static int open_connection_rsp_sent = FALSE;

	const char* sig_path = NULL;
	const char* svc_name1 = NULL;
	const char* svc_name2 = NULL;
	const char* svc_name3 = NULL;

	char* property = NULL;
	net_event_info_t event_data = {0,};
	net_err_t Error = NET_ERR_NONE;
	net_device_t device_type = NET_DEVICE_UNKNOWN;

	if (msg == NULL) {
		NETWORK_LOG(NETWORK_LOW, "Invalid Message. Ignore\n");
		/* We have handled this message, don't pass it on */
		__NETWORK_FUNC_EXIT__;
		return DBUS_HANDLER_RESULT_HANDLED;
	}

	if (dbus_message_is_signal(msg, CONNMAN_MANAGER_INTERFACE,
			CONNMAN_SIGNAL_PROPERTY_CHANGED)) {
		property = _net_get_string(msg);
		if(property == NULL) {
			/* We have handled this message, don't pass it on */
			__NETWORK_FUNC_EXIT__;
			return DBUS_HANDLER_RESULT_HANDLED;
		}
		NETWORK_LOG(NETWORK_LOW, "[Manager : PropertyChanged] Property - [%s]\n", property);

		/* We have handled this message, don't pass it on */
		__NETWORK_FUNC_EXIT__;
		return DBUS_HANDLER_RESULT_HANDLED;
	} else if (dbus_message_is_signal(msg, CONNMAN_MANAGER_INTERFACE,
			CONNMAN_SIGNAL_TECHNOLOGY_ADDED)) {
		NETWORK_LOG(NETWORK_LOW, "[Manager : TechnologyAdded]\n");
	} else if (dbus_message_is_signal(msg, CONNMAN_MANAGER_INTERFACE,
			CONNMAN_SIGNAL_TECHNOLOGY_REMOVED)) {
		NETWORK_LOG(NETWORK_LOW, "[Manager : TechnologyRemoved]\n");
	} else if (dbus_message_is_signal(msg, CONNMAN_MANAGER_INTERFACE,
			CONNMAN_SIGNAL_SERVICES_CHANGED)) {
		NETWORK_LOG(NETWORK_LOW, "[Manager : ServicesChanged]\n");

		__net_handle_services_changed_signal(msg);

		/* We have handled this message, don't pass it on */
		__NETWORK_FUNC_EXIT__;
		return DBUS_HANDLER_RESULT_HANDLED;
	} else if (dbus_message_is_signal(msg, NETCONFIG_WIFI_INTERFACE, NETCONFIG_SIGNAL_POWERON_COMPLETED)) {
		__net_handle_wifi_power_rsp(TRUE);

		/* We have handled this message, don't pass it on */
		__NETWORK_FUNC_EXIT__;
		return DBUS_HANDLER_RESULT_HANDLED;
	} else if (dbus_message_is_signal(msg, NETCONFIG_WIFI_INTERFACE, NETCONFIG_SIGNAL_POWEROFF_COMPLETED)) {
		__net_handle_wifi_power_rsp(FALSE);

		/* We have handled this message, don't pass it on */
		__NETWORK_FUNC_EXIT__;
		return DBUS_HANDLER_RESULT_HANDLED;
	} else if (dbus_message_is_signal(msg, NETCONFIG_WIFI_INTERFACE, NETCONFIG_SIGNAL_SPECIFIC_SCAN_DONE)) {
		DBusMessageIter iter, array;
		dbus_message_iter_init(msg, &iter);
		dbus_message_iter_recurse(&iter, &array);

		GSList *bss_info_list = NULL;

		/* The dbus message will be packed in this format: {{"ssid", <ssid name>}{"security", <security mode>}....}*/
		while (dbus_message_iter_get_arg_type(&array) == DBUS_TYPE_DICT_ENTRY) {
			DBusMessageIter entry, dict;
			const char *key = NULL;
			const char *ssid = NULL;
			const int security = 0;

			dbus_message_iter_recurse(&array, &entry);
			dbus_message_iter_get_basic(&entry, &key);

			if (g_strcmp0(key, "ssid")) {
				Error = NET_ERR_UNKNOWN;
				break;
			}
			dbus_message_iter_next(&entry);
			dbus_message_iter_recurse(&entry, &dict);
			dbus_message_iter_get_basic(&dict, &ssid);
			NETWORK_LOG(NETWORK_LOW, "Got an ssid: %s", ssid);

			dbus_message_iter_next(&array);
			if (dbus_message_iter_get_arg_type(&array) != DBUS_TYPE_DICT_ENTRY) {
				Error = NET_ERR_UNKNOWN;
				break;
			}
			dbus_message_iter_recurse(&array, &entry);
			dbus_message_iter_get_basic(&entry, &key);
			if (g_strcmp0(key, "security")) {
				Error = NET_ERR_UNKNOWN;
				break;
			}
			dbus_message_iter_next(&entry);
			dbus_message_iter_recurse(&entry, &dict);
			dbus_message_iter_get_basic(&dict, (void *)&security);
			NETWORK_LOG(NETWORK_LOW, "with security: %d", security);

			net_wifi_connection_info_t *resp_data = g_try_new0(net_wifi_connection_info_t, 1);
			g_strlcpy(resp_data->essid, ssid, NET_WLAN_ESSID_LEN);
			resp_data->security_info.sec_mode = __net_get_wlan_sec_mode(security);
			bss_info_list = g_slist_append(bss_info_list, resp_data);

			dbus_message_iter_next(&array);
		}

		NETWORK_LOG(NETWORK_LOW, "Received the signal: %s with total bss count = %d(Error = %d)", NETCONFIG_SIGNAL_SPECIFIC_SCAN_DONE, g_slist_length(bss_info_list), Error);

		__net_handle_specific_scan_resp(bss_info_list);

		/* Specific Scan response handled. Release/Destroy the list */
		g_slist_free_full(bss_info_list, g_free);

		/* We have handled this message, don't pass it on */
		__NETWORK_FUNC_EXIT__;
		return DBUS_HANDLER_RESULT_HANDLED;
	} else if (dbus_message_is_signal(msg, CONNMAN_TECHNOLOGY_INTERFACE,
			CONNMAN_SIGNAL_PROPERTY_CHANGED)) {
#if 0
		char* prop_value = NULL;
		int value = FALSE;

		property = __net_get_property(msg, &prop_value, &value);
		if (property == NULL) {
			/* We have handled this message, don't pass it on */
			__NETWORK_FUNC_EXIT__;
			return DBUS_HANDLER_RESULT_HANDLED;
		}

		memset(ProfileName, 0, sizeof(ProfileName));
		_net_get_path(msg, ProfileName);

		NETWORK_LOG(NETWORK_LOW,
				"[Technology : PropertyChanged]"
				"Property-[%s] path [%s] state [%s]\n",
				property, ProfileName, prop_value);
#endif
		/* We have handled this message, don't pass it on */
		__NETWORK_FUNC_EXIT__;
		return DBUS_HANDLER_RESULT_HANDLED;
	} else if (dbus_message_is_signal(msg, CONNMAN_SERVICE_INTERFACE, CONNMAN_SIGNAL_PROPERTY_CHANGED)) {
		property = _net_get_string(msg);
		if (property == NULL) {
			/* We have handled this message, don't pass it on */
			__NETWORK_FUNC_EXIT__;
			return DBUS_HANDLER_RESULT_HANDLED;
		}

		if(strcmp(property, "Strength") != 0) /** Ignore Strength signal */
			NETWORK_LOG(NETWORK_LOW, "[Service : PropertyChanged]"
					"Got Signal with value [%s]\n", property);

		if (strcmp(property, "State") == 0) {
			memset(ProfileName, 0, sizeof(ProfileName));
			_net_get_path(msg, ProfileName);

			device_type = _net_get_tech_type_from_path(ProfileName);

			if (device_type == NET_DEVICE_UNKNOWN) {
				/* We have handled this message, don't pass it on */
				__NETWORK_FUNC_EXIT__;
				return DBUS_HANDLER_RESULT_HANDLED;
			}

			sig_path = ProfileName;

			memset(svc_state, 0, sizeof(svc_state));
			memset(svc_error, 0, sizeof(svc_error));
			__net_get_state(msg, svc_state, svc_error);
			NETWORK_LOG(NETWORK_LOW, "Current ConnMan svc_state [%s] and svc_error [%s] for ProfileName [%s]\n",
					svc_state, svc_error, ProfileName);

			if (device_type == NET_DEVICE_WIFI &&
					NetworkInfo.wifi_state == WIFI_OFF) {
				NETWORK_LOG(NETWORK_LOW, "Warning!! Wi-Fi is already off!!\n");
				/* We have handled this message, don't pass it on */
				__NETWORK_FUNC_EXIT__;
				return DBUS_HANDLER_RESULT_HANDLED;;
			}

			if (strcmp(svc_state, "idle") == 0) {
				service_state_table[device_type] = NET_STATE_TYPE_IDLE;
				__net_handle_state_ind(ProfileName, NET_STATE_TYPE_IDLE);
			} else if (strcmp(svc_state, "association") == 0) {
				service_state_table[device_type] = NET_STATE_TYPE_ASSOCIATION;
				__net_handle_state_ind(ProfileName, NET_STATE_TYPE_ASSOCIATION);
			} else if (strcmp(svc_state, "configuration") == 0) {
				service_state_table[device_type] = NET_STATE_TYPE_CONFIGURATION;
				__net_handle_state_ind(ProfileName, NET_STATE_TYPE_CONFIGURATION);
			} else if (strcmp(svc_state, "ready") == 0 ||
					strcmp(svc_state, "online") == 0) {
				if (service_state_table[device_type] != NET_STATE_TYPE_READY &&
						service_state_table[device_type] != NET_STATE_TYPE_ONLINE) {
					svc_name1 = request_table[NETWORK_REQUEST_TYPE_OPEN_CONNECTION].ProfileName;
					svc_name2 = request_table[NETWORK_REQUEST_TYPE_ENROLL_WPS].ProfileName;

					if (request_table[NETWORK_REQUEST_TYPE_OPEN_CONNECTION].flag == TRUE &&
					    strstr(sig_path, svc_name1) != NULL) {
						memset(&request_table[NETWORK_REQUEST_TYPE_OPEN_CONNECTION], 0,
								sizeof(network_request_table_t));

						event_data.Event =  NET_EVENT_OPEN_RSP;
						NETWORK_LOG(NETWORK_LOW, "Sending NET_EVENT_OPEN_RSP\n");
						_net_dbus_clear_pending_call();
					} else if (request_table[NETWORK_REQUEST_TYPE_ENROLL_WPS].flag == TRUE &&
							strcmp(sig_path, svc_name2) == 0) {
						memset(&request_table[NETWORK_REQUEST_TYPE_ENROLL_WPS], 0,
								sizeof(network_request_table_t));

						event_data.Event =  NET_EVENT_WIFI_WPS_RSP;
						NETWORK_LOG(NETWORK_LOW, "Sending NET_EVENT_WIFI_WPS_RSP\n");
						_net_dbus_clear_pending_call();
					} else {
						event_data.Event =  NET_EVENT_OPEN_IND;
						NETWORK_LOG(NETWORK_LOW, "Sending NET_EVENT_OPEN_IND\n");
					}

					net_profile_info_t prof_info;
					if ((Error = net_get_profile_info(ProfileName, &prof_info)) != NET_ERR_NONE) {
						NETWORK_LOG(NETWORK_ERROR, "Error!!! net_get_profile_info() failed [%s]\n",
								_net_print_error(Error));
						event_data.Datalength = 0;
						event_data.Data = NULL;
					} else {
						event_data.Datalength = sizeof(net_profile_info_t);
						event_data.Data = &prof_info;
					}

					event_data.Error = Error;
					snprintf(event_data.ProfileName, NET_PROFILE_NAME_LEN_MAX + 1, "%s", ProfileName);
					open_connection_rsp_sent = TRUE;
					_net_client_callback(&event_data);
				} else {
					if (strcmp(svc_state, "ready") == 0)
						__net_handle_state_ind(ProfileName, NET_STATE_TYPE_READY);
					else
						__net_handle_state_ind(ProfileName, NET_STATE_TYPE_ONLINE);
				}

				if (strcmp(svc_state, "ready") == 0)
					service_state_table[device_type] = NET_STATE_TYPE_READY;
				else
					service_state_table[device_type] = NET_STATE_TYPE_ONLINE;
			} else if (strcmp(svc_state, "disconnect") == 0) {
				svc_name1 = request_table[NETWORK_REQUEST_TYPE_CLOSE_CONNECTION].ProfileName;
				svc_name2 = request_table[NETWORK_REQUEST_TYPE_OPEN_CONNECTION].ProfileName;
				svc_name3 = request_table[NETWORK_REQUEST_TYPE_ENROLL_WPS].ProfileName;

				if (request_table[NETWORK_REQUEST_TYPE_OPEN_CONNECTION].flag == TRUE &&
				    strstr(sig_path, svc_name2) != NULL) {
					memset(&request_table[NETWORK_REQUEST_TYPE_OPEN_CONNECTION], 0,
							sizeof(network_request_table_t));

					/** Send Open Resp */
					event_data.Error = NET_ERR_OPERATION_ABORTED;
					event_data.Event =  NET_EVENT_OPEN_RSP;
					snprintf(event_data.ProfileName,
							NET_PROFILE_NAME_LEN_MAX+1, "%s", ProfileName);

					event_data.Datalength = 0;
					event_data.Data = NULL;
					NETWORK_LOG(NETWORK_LOW, "Sending NET_EVENT_OPEN_RSP\n");
					_net_dbus_clear_pending_call();
					_net_client_callback(&event_data);
				} else if (request_table[NETWORK_REQUEST_TYPE_ENROLL_WPS].flag == TRUE &&
						strcmp(sig_path, svc_name3) == 0) {
					memset(&request_table[NETWORK_REQUEST_TYPE_ENROLL_WPS], 0,
							sizeof(network_request_table_t));

					/** Send WPS Resp */
					event_data.Error = NET_ERR_OPERATION_ABORTED;
					event_data.Event =  NET_EVENT_WIFI_WPS_RSP;
					snprintf(event_data.ProfileName,
							NET_PROFILE_NAME_LEN_MAX+1, "%s", ProfileName);

					event_data.Datalength = 0;
					event_data.Data = NULL;
					NETWORK_LOG(NETWORK_LOW, "Sending NET_EVENT_WIFI_WPS_RSP\n");
					_net_dbus_clear_pending_call();
					_net_client_callback(&event_data);
				} else if (request_table[NETWORK_REQUEST_TYPE_CLOSE_CONNECTION].flag == TRUE &&
						strcmp(sig_path, svc_name1) == 0) {
					memset(&request_table[NETWORK_REQUEST_TYPE_CLOSE_CONNECTION], 0,
							sizeof(network_request_table_t));

					/** Send Close Resp */
					event_data.Error = Error;
					event_data.Event =  NET_EVENT_CLOSE_RSP;
					snprintf(event_data.ProfileName,
							NET_PROFILE_NAME_LEN_MAX+1, "%s", ProfileName);

					event_data.Datalength = 0;
					event_data.Data = NULL;
					NETWORK_LOG(NETWORK_LOW, "Sending NET_EVENT_CLOSE_RSP\n");
					_net_dbus_clear_pending_call();
					_net_client_callback(&event_data);
				} else {
					/** Send Close Ind */
					event_data.Error = Error;
					event_data.Event =  NET_EVENT_CLOSE_IND;
					snprintf(event_data.ProfileName,
							NET_PROFILE_NAME_LEN_MAX+1, "%s", ProfileName);

					event_data.Datalength = 0;
					event_data.Data = NULL;
					NETWORK_LOG(NETWORK_LOW, "Sending NET_EVENT_CLOSE_IND\n");
					_net_client_callback(&event_data);
				}

				service_state_table[device_type] = NET_STATE_TYPE_DISCONNECT;
			} else if (strcmp(svc_state, "failure") == 0) {
				__net_handle_svc_failure_ind(sig_path, (char*)svc_error);
				service_state_table[device_type] = NET_STATE_TYPE_FAILURE;
				__NETWORK_FUNC_EXIT__;
				return DBUS_HANDLER_RESULT_HANDLED;
			}
		} else if (strcmp(property, "Nameservers") == 0) {
			/* We have handled this message, don't pass it on */
			__NETWORK_FUNC_EXIT__;
			return DBUS_HANDLER_RESULT_HANDLED;
		} else if (strcmp(property, "IPv4") == 0) {
			/** Ignore - compared for future use */
		} else if (strcmp(property, "Ethernet") == 0) {
			/** Ignore - compared for future use */
		} else if (strcmp(property, "Domains") == 0) {
			/** Ignore - compared for future use */
		} else if (strcmp(property, "IPv4.Configuration") == 0) {
			/** Ignore - compared for future use */
		} else {
			/** Ignore - compared for future use */
		}

		/* We have handled this message, don't pass it on */
		__NETWORK_FUNC_EXIT__;
		return DBUS_HANDLER_RESULT_HANDLED;
	}

	if (dbus_message_is_signal(msg, CONNMAN_COUNTER_INTERFACE, "Usage")) {
		NETWORK_LOG(NETWORK_LOW, "Received [COUNTER_USAGE_SIGNAL] signal\n");
	} else if (dbus_message_is_signal(msg, CONNMAN_COUNTER_INTERFACE, "Release")) {
		NETWORK_LOG(NETWORK_LOW, "Received [COUNTER_RELEASE_SIGNAL] signal\n");
	}

	NETWORK_LOG(NETWORK_LOW, "Useless signal. Ignored !!!\n");
	__NETWORK_FUNC_EXIT__;
	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

static void __net_init_dbus_thread()
{
	static dbus_bool_t init_required = TRUE;
	if (init_required) {
		dbus_g_thread_init();
		init_required = FALSE;
	}
}

/*****************************************************************************
 * 	Global Functions
 *****************************************************************************/

int _net_deregister_signal(void)
{
	__NETWORK_FUNC_ENTER__;

	DBusError err;
	dbus_error_init(&err);

	if (signal_conn == NULL) {
		NETWORK_LOG(NETWORK_HIGH, "Already de-registered. Nothing to be done\n");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_NONE;
	}

	dbus_bus_remove_match(signal_conn, CONNMAN_MANAGER_SIGNAL_FILTER, &err);
	dbus_connection_flush(signal_conn);
	if (dbus_error_is_set(&err)) {
		NETWORK_LOG(NETWORK_ERROR, "Error!!! Remove Match Error (%s)\n", err.message);
		dbus_error_free(&err);
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_UNKNOWN;
	}

	dbus_bus_remove_match(signal_conn, CONNMAN_TECHNOLOGY_SIGNAL_FILTER, &err);
	dbus_connection_flush(signal_conn);
	if (dbus_error_is_set(&err)) {
		NETWORK_LOG(NETWORK_ERROR, "Error!!! Remove Match Error (%s)\n", err.message);
		dbus_error_free(&err);
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_UNKNOWN;
	}

	dbus_bus_remove_match(signal_conn, CONNMAN_SERVICE_SIGNAL_FILTER, &err);
	dbus_connection_flush(signal_conn);
	if (dbus_error_is_set(&err)) {
		NETWORK_LOG(NETWORK_ERROR, "Error!!! Remove Match Error (%s)\n", err.message);
		dbus_error_free(&err);
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_UNKNOWN;
	}

	dbus_bus_remove_match(signal_conn, CONNMAN_NETWORK_COUNTER_FILTER, &err);
	dbus_connection_flush(signal_conn);
	if (dbus_error_is_set(&err)) {
		NETWORK_LOG(NETWORK_ERROR, "Error!!! Remove Match Error (%s)\n", err.message);
		dbus_error_free(&err);
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_UNKNOWN;
	}

	dbus_bus_remove_match(signal_conn, NETCONFIG_WIFI_FILTER, &err);
	dbus_connection_flush(signal_conn);
	if (dbus_error_is_set(&err)) {
		NETWORK_LOG(NETWORK_ERROR, "Error!!! Remove Match Error (%s)\n", err.message);
		dbus_error_free(&err);
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_UNKNOWN;
	}

	dbus_connection_remove_filter(signal_conn, __net_signal_filter, NULL);
	NETWORK_LOG(NETWORK_HIGH, "dbus_connection_remove_filter() successful\n");
	NETWORK_LOG(NETWORK_LOW, "Successfully removed signal filter rules\n");

	/* If DBusPendingCall remains, it should be released */
	if (_net_dbus_is_pending_call_used() == TRUE) {
		_net_dbus_clear_pending_call();
		NETWORK_LOG(NETWORK_HIGH, "DBus pending call successfully removed\n");
	}

	dbus_connection_unref(signal_conn);
	signal_conn = NULL;

	__NETWORK_FUNC_EXIT__;
	return NET_ERR_NONE;
}

int _net_register_signal(void)
{
	__NETWORK_FUNC_ENTER__;

	DBusConnection* conn = NULL;
	DBusError err;

	__net_init_dbus_thread();

	dbus_error_init(&err);
	conn = dbus_bus_get(DBUS_BUS_SYSTEM, NULL); 
	if (conn == NULL) {
		NETWORK_LOG(NETWORK_ERROR, "Error!!! Failed to connect to the D-BUS daemon: [%s]\n", err.message);
		dbus_error_free(&err);
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_UNKNOWN;
	}

	signal_conn = conn;

	dbus_connection_setup_with_g_main(conn, NULL);

	/** listening to messages from all objects as no path is specified */
	/** see signals from the given interface */
	dbus_bus_add_match(conn, CONNMAN_MANAGER_SIGNAL_FILTER, &err); 
	dbus_connection_flush(conn);
	if (dbus_error_is_set(&err)) {
		NETWORK_LOG(NETWORK_ERROR, "Error!!! Add Match Error (%s)\n", err.message);
		dbus_error_free(&err);
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_UNKNOWN;
	}

	dbus_bus_add_match(conn, CONNMAN_TECHNOLOGY_SIGNAL_FILTER, &err); 
	dbus_connection_flush(conn);
	if (dbus_error_is_set(&err)) {
		NETWORK_LOG(NETWORK_ERROR, "Error!!! Add Match Error (%s)\n", err.message);
		dbus_error_free(&err);
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_UNKNOWN;
	}

	dbus_bus_add_match(conn, CONNMAN_SERVICE_SIGNAL_FILTER, &err);
	dbus_connection_flush(conn);
	if (dbus_error_is_set(&err)) {
		NETWORK_LOG(NETWORK_ERROR, "Error!!! Add Match Error (%s)\n", err.message);
		dbus_error_free(&err);
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_UNKNOWN;
	}

	dbus_bus_add_match(conn, CONNMAN_NETWORK_COUNTER_FILTER, &err);
	dbus_connection_flush(conn);
	if (dbus_error_is_set(&err)) {
		NETWORK_LOG(NETWORK_ERROR, "Error!!! Add Match Error (%s)\n", err.message);
		dbus_error_free(&err);
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_UNKNOWN;
	}

	dbus_bus_add_match(conn, NETCONFIG_WIFI_FILTER, &err);
	dbus_connection_flush(conn);
	if (dbus_error_is_set(&err)) {
		NETWORK_LOG(NETWORK_ERROR, "Error!!! Add Match Error (%s)\n", err.message);
		dbus_error_free(&err);
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_UNKNOWN;
	}

	if (dbus_connection_add_filter(conn, __net_signal_filter, NULL, NULL) == FALSE) {
		NETWORK_LOG(NETWORK_ERROR, "Error!!! dbus_connection_add_filter() failed\n");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_UNKNOWN;
	}
	
	NETWORK_LOG(NETWORK_LOW, "Successfully set signal filter rules\n");

	__NETWORK_FUNC_EXIT__;
	return NET_ERR_NONE;
}

int _net_init_service_state_table(void)
{
	__NETWORK_FUNC_ENTER__;

	net_err_t Error = NET_ERR_NONE;
	net_cm_network_status_t network_status;

	Error = _net_dbus_get_network_status(NET_DEVICE_WIFI, &network_status);
	if (Error != NET_ERR_NONE) {
		__NETWORK_FUNC_EXIT__;
		return Error;
	}

	if (network_status == NET_STATUS_AVAILABLE)
		service_state_table[NET_DEVICE_WIFI] = NET_STATE_TYPE_READY;

	Error = _net_dbus_get_network_status(NET_DEVICE_CELLULAR, &network_status);
	if (Error != NET_ERR_NONE) {
		__NETWORK_FUNC_EXIT__;
		return Error;
	}

	if (network_status == NET_STATUS_AVAILABLE)
		service_state_table[NET_DEVICE_CELLULAR] = NET_STATE_TYPE_READY;

	Error = _net_dbus_get_network_status(NET_DEVICE_ETHERNET, &network_status);
	if (Error != NET_ERR_NONE) {
		__NETWORK_FUNC_EXIT__;
		return Error;
	}

	if (network_status == NET_STATUS_AVAILABLE)
		service_state_table[NET_DEVICE_ETHERNET] = NET_STATE_TYPE_READY;

	Error = _net_dbus_get_network_status(NET_DEVICE_BLUETOOTH, &network_status);
	if (Error != NET_ERR_NONE) {
		__NETWORK_FUNC_EXIT__;
		return Error;
	}

	if (network_status == NET_STATUS_AVAILABLE)
		service_state_table[NET_DEVICE_BLUETOOTH] = NET_STATE_TYPE_READY;

	NETWORK_LOG(NETWORK_HIGH, "init service state table. "
				"wifi:%d, cellular:%d, ethernet:%d, bluetooth:%d\n",
				service_state_table[NET_DEVICE_WIFI],
				service_state_table[NET_DEVICE_CELLULAR],
				service_state_table[NET_DEVICE_ETHERNET],
				service_state_table[NET_DEVICE_BLUETOOTH]);

	__NETWORK_FUNC_EXIT__;
	return NET_ERR_NONE;
}

#ifdef __cplusplus
}
#endif /* __cplusplus */
