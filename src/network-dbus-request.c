/*
 * Network Client Library
 *
 * Copyright 2011-2013 Samsung Electronics Co., Ltd
 *
 * Licensed under the Flora License, Version 1.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://floralicense.org/license/
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#include <vconf.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include "network-internal.h"
#include "network-dbus-request.h"

/*****************************************************************************
 * 	Macros and Typedefs
 *****************************************************************************/
#define DBUS_REPLY_TIMEOUT (120 * 1000)

/*****************************************************************************
 * 	Global Functions
 *****************************************************************************/

/*****************************************************************************
 * 	Global Variables
 *****************************************************************************/
struct dbus_pending_call_data {
	DBusPendingCall *pcall;
	dbus_bool_t is_used;
};

static struct dbus_pending_call_data network_dbus_pending_call_data = {
	NULL,
	FALSE
};

/*****************************************************************************
 * 	Extern Variables
 *****************************************************************************/
extern network_info_t NetworkInfo;
extern network_request_table_t request_table[NETWORK_REQUEST_TYPE_MAX];

/*****************************************************************************
 * 	Extern Functions 
 *****************************************************************************/

/*****************************************************************************
 * 	Local Functions Definition
 *****************************************************************************/
static int __net_error_string_to_enum(const char* error)
{
	NETWORK_LOG(NETWORK_HIGH, "Passed error value [%s]\n", error);

	if (NULL != strstr(error, CONNMAN_ERROR_INTERFACE ".NoReply"))
		return NET_ERR_TIME_OUT;
	else if (NULL != strstr(error, CONNMAN_ERROR_INTERFACE ".Failed"))
		return NET_ERR_UNKNOWN;
	else if (NULL != strstr(error, CONNMAN_ERROR_INTERFACE ".UnknownMethod"))
		return NET_ERR_UNKNOWN_METHOD;
	else if (NULL != strstr(error, CONNMAN_ERROR_INTERFACE ".InvalidArguments"))
		return NET_ERR_INVALID_PARAM;
	else if (NULL != strstr(error, CONNMAN_ERROR_INTERFACE ".PermissionDenied"))
		return NET_ERR_ACCESS_DENIED;
	else if (NULL != strstr(error, CONNMAN_ERROR_INTERFACE ".PassphraseRequired"))
		return NET_ERR_INVALID_OPERATION;
	else if (NULL != strstr(error, CONNMAN_ERROR_INTERFACE ".NotRegistered"))
		return NET_ERR_INVALID_OPERATION;
	else if (NULL != strstr(error, CONNMAN_ERROR_INTERFACE ".NotUnique"))
		return NET_ERR_INVALID_OPERATION;
	else if (NULL != strstr(error, CONNMAN_ERROR_INTERFACE ".NotSupported"))
		return NET_ERR_NOT_SUPPORTED;
	else if (NULL != strstr(error, CONNMAN_ERROR_INTERFACE ".NotImplemented"))
		return NET_ERR_NOT_SUPPORTED;
	else if (NULL != strstr(error, CONNMAN_ERROR_INTERFACE ".NotFound"))
		return NET_ERR_NOT_SUPPORTED;
	else if (NULL != strstr(error, CONNMAN_ERROR_INTERFACE ".NoCarrier"))
		return NET_ERR_NOT_SUPPORTED;
	else if (NULL != strstr(error, CONNMAN_ERROR_INTERFACE ".InProgress"))
		return NET_ERR_IN_PROGRESS;
	else if (NULL != strstr(error, CONNMAN_ERROR_INTERFACE ".AlreadyExists"))
		return NET_ERR_INVALID_OPERATION;
	else if (NULL != strstr(error, CONNMAN_ERROR_INTERFACE ".AlreadyEnabled"))
		return NET_ERR_INVALID_OPERATION;
	else if (NULL != strstr(error, CONNMAN_ERROR_INTERFACE ".AlreadyDisabled"))
		return NET_ERR_INVALID_OPERATION;
	else if (NULL != strstr(error, CONNMAN_ERROR_INTERFACE ".AlreadyConnected"))
		return NET_ERR_ACTIVE_CONNECTION_EXISTS;
	else if (NULL != strstr(error, CONNMAN_ERROR_INTERFACE ".NotConnected"))
		return NET_ERR_NO_ACTIVE_CONNECTIONS;
	else if (NULL != strstr(error, CONNMAN_ERROR_INTERFACE ".OperationAborted"))
		return NET_ERR_OPERATION_ABORTED;
	else if (NULL != strstr(error, CONNMAN_ERROR_INTERFACE ".OperationTimeout"))
		return NET_ERR_TIME_OUT;
	else if (NULL != strstr(error, CONNMAN_ERROR_INTERFACE ".InvalidService"))
		return NET_ERR_NO_SERVICE;
	else if (NULL != strstr(error, CONNMAN_ERROR_INTERFACE ".InvalidProperty"))
		return NET_ERR_INVALID_OPERATION;
	return NET_ERR_UNKNOWN;
}

static int __net_netconfig_error_string_to_enum(const char* error)
{
	NETWORK_LOG(NETWORK_HIGH, "Passed error value [%s]\n", error);

	if (error == NULL)
		return NET_ERR_UNKNOWN;

	if (NULL != strstr(error, ".WifiDriverFailed"))
		return NET_ERR_WIFI_DRIVER_FAILURE;
	else if (NULL != strstr(error, ".SecurityRestricted"))
		return NET_ERR_SECURITY_RESTRICTED;
	else if (NULL != strstr(error, ".WifiLoadInprogress"))
		return NET_ERR_WIFI_DRIVER_LOAD_INPROGRESS;
	return NET_ERR_UNKNOWN;
}

static int _net_get_error_from_message(DBusMessage *message)
{
	__NETWORK_FUNC_ENTER__;

	int MessageType = 0;

	MessageType = dbus_message_get_type(message);

	if (MessageType == DBUS_MESSAGE_TYPE_ERROR) {
		const char* str = dbus_message_get_error_name(message);

		NETWORK_LOG(NETWORK_ERROR, "message %s\n", str);
		__NETWORK_FUNC_EXIT__;
		return __net_error_string_to_enum(str);
	}

	__NETWORK_FUNC_EXIT__;
	return NET_ERR_NONE;
}

static int _net_get_error_from_netconfig_message(DBusMessage *message)
{
	__NETWORK_FUNC_ENTER__;

	int MessageType = 0;

	MessageType = dbus_message_get_type(message);

	if (MessageType == DBUS_MESSAGE_TYPE_ERROR) {
		const char* str = dbus_message_get_error_name(message);
		const char* err_msg = _net_get_string(message);

		NETWORK_LOG(NETWORK_ERROR, "message %s %s\n", str, err_msg);
		__NETWORK_FUNC_EXIT__;
		return __net_netconfig_error_string_to_enum(err_msg);
	}

	__NETWORK_FUNC_EXIT__;
	return NET_ERR_NONE;
}

static void __net_open_connection_reply(DBusPendingCall *call, void *user_data)
{
	__NETWORK_FUNC_ENTER__;

	NETWORK_LOG(NETWORK_LOW, "__net_open_connection_reply() called\n");

	int callback_flag = FALSE;
	net_event_info_t event_data = {0,};
	net_profile_info_t prof_info;
	network_request_table_t *open_info =
			&request_table[NETWORK_REQUEST_TYPE_OPEN_CONNECTION];
	network_request_table_t *wps_info =
			&request_table[NETWORK_REQUEST_TYPE_ENROLL_WPS];

	DBusMessage *reply = dbus_pending_call_steal_reply(call);
	net_err_t Error = _net_get_error_from_message(reply);

	if (Error == NET_ERR_NONE)
		goto done;

	NETWORK_LOG(NETWORK_ERROR, "Connection open failed. Error [%d]\n", Error);

	if (open_info->flag == TRUE) {
		net_device_t device_type =
				_net_get_tech_type_from_path(open_info->ProfileName);

		if (Error == NET_ERR_IN_PROGRESS && device_type == NET_DEVICE_CELLULAR)
			goto done;

		g_strlcpy(event_data.ProfileName, open_info->ProfileName,
				NET_PROFILE_NAME_LEN_MAX + 1);
		memset(open_info, 0, sizeof(network_request_table_t));

		event_data.Error = Error;

		if (Error == NET_ERR_ACTIVE_CONNECTION_EXISTS) {
			Error = net_get_profile_info(event_data.ProfileName, &prof_info);

			if (device_type == NET_DEVICE_CELLULAR)
				event_data.Error = NET_ERR_NONE;

			if (Error != NET_ERR_NONE) {
				NETWORK_LOG(NETWORK_ERROR, "Fail to get profile info [%s]\n",
						_net_print_error(Error));

				event_data.Datalength = 0;
				event_data.Data = NULL;
			} else {
				event_data.Datalength = sizeof(net_profile_info_t);
				event_data.Data = &prof_info;
			}
		}

		event_data.Event = NET_EVENT_OPEN_RSP;
		NETWORK_LOG(NETWORK_LOW, "Sending NET_EVENT_OPEN_RSP Error = %s\n",
				_net_print_error(event_data.Error));

		callback_flag = TRUE;
	} else if (wps_info->flag == TRUE) {
		g_strlcpy(event_data.ProfileName, wps_info->ProfileName,
				NET_PROFILE_NAME_LEN_MAX + 1);
		memset(wps_info, 0, sizeof(network_request_table_t));

		event_data.Error = Error;

		if (Error == NET_ERR_ACTIVE_CONNECTION_EXISTS) {
			Error = net_get_profile_info(event_data.ProfileName, &prof_info);
			if (Error != NET_ERR_NONE) {
				NETWORK_LOG(NETWORK_ERROR, "Fail to get profile info [%s]\n",
						_net_print_error(Error));

				event_data.Datalength = 0;
				event_data.Data = NULL;
			} else {
				event_data.Datalength = sizeof(net_profile_info_t);
				event_data.Data = &prof_info;
			}
		}

		event_data.Event = NET_EVENT_WIFI_WPS_RSP;

		NETWORK_LOG(NETWORK_LOW, "Sending NET_EVENT_WIFI_WPS_RSP Error = %s\n",
				_net_print_error(event_data.Error));

		callback_flag = TRUE;
	}

done:
	dbus_message_unref(reply);
	dbus_pending_call_unref(call);

	network_dbus_pending_call_data.is_used = FALSE;
	network_dbus_pending_call_data.pcall = NULL;

	if (callback_flag)
		_net_client_callback(&event_data);

	__NETWORK_FUNC_EXIT__;
}

static void __net_close_connection_reply(DBusPendingCall *call, void *user_data)
{
	__NETWORK_FUNC_ENTER__;

	NETWORK_LOG(NETWORK_LOW, "__net_close_connection_reply() called\n");

	int callback_flag = FALSE;
	net_event_info_t event_data = {0,};
	network_request_table_t *close_info =
			&request_table[NETWORK_REQUEST_TYPE_CLOSE_CONNECTION];

	DBusMessage *reply = dbus_pending_call_steal_reply(call);
	net_err_t Error = _net_get_error_from_message(reply);

	if (Error == NET_ERR_NONE)
		goto done;

	NETWORK_LOG(NETWORK_ERROR, "Connection close failed. Error [%d]\n", Error);

	if (close_info->flag == TRUE) {
		net_device_t device_type =
				_net_get_tech_type_from_path(close_info->ProfileName);

		if (Error == NET_ERR_ACTIVE_CONNECTION_EXISTS &&
		    device_type == NET_DEVICE_CELLULAR)
			Error = NET_ERR_NONE;

		g_strlcpy(event_data.ProfileName, close_info->ProfileName,
				NET_PROFILE_NAME_LEN_MAX + 1);
		memset(close_info, 0, sizeof(network_request_table_t));

		event_data.Error = Error;
		event_data.Datalength = 0;
		event_data.Data = NULL;
		event_data.Event = NET_EVENT_CLOSE_RSP;

		NETWORK_LOG(NETWORK_LOW, "Sending NET_EVENT_CLOSE_RSP Error = %s\n",
				_net_print_error(event_data.Error));

		callback_flag = TRUE;
	}

done:
	dbus_message_unref(reply);
	dbus_pending_call_unref(call);

	network_dbus_pending_call_data.is_used = FALSE;
	network_dbus_pending_call_data.pcall = NULL;

	if (callback_flag)
		_net_client_callback(&event_data);

	__NETWORK_FUNC_EXIT__;
}

static void __net_wifi_power_reply(DBusPendingCall *call, void *user_data)
{
	__NETWORK_FUNC_ENTER__;

	NETWORK_LOG(NETWORK_LOW, "__net_wifi_power_reply() called\n");

	int callback_flag = FALSE;
	DBusMessage *reply = dbus_pending_call_steal_reply(call);
	net_err_t Error = _net_get_error_from_netconfig_message(reply);
	net_event_info_t event_data = {0,};

	if (Error != NET_ERR_NONE) {
		NETWORK_LOG(NETWORK_ERROR,
				"Wi-Fi power operation failed. Error [%d]\n", Error);

		if (Error != NET_ERR_WIFI_DRIVER_LOAD_INPROGRESS) {
			if (request_table[NETWORK_REQUEST_TYPE_WIFI_POWER].flag == TRUE) {
				memset(&request_table[NETWORK_REQUEST_TYPE_WIFI_POWER],
						0, sizeof(network_request_table_t));

				event_data.Event = NET_EVENT_WIFI_POWER_RSP;

				NETWORK_LOG(NETWORK_LOW,
						"Sending NET_EVENT_WIFI_POWER_RSP Wi-Fi: %d Error = %d\n",
						NetworkInfo.wifi_state, Error);

				event_data.Datalength = sizeof(net_wifi_state_t);
				event_data.Data = &(NetworkInfo.wifi_state);
				event_data.Error = Error;

				callback_flag = TRUE;
			}
		}
	}

	dbus_message_unref(reply);
	dbus_pending_call_unref(call);

	network_dbus_pending_call_data.is_used = FALSE;
	network_dbus_pending_call_data.pcall = NULL;

	if (callback_flag)
		_net_client_callback(&event_data);

	__NETWORK_FUNC_EXIT__;
}

static void __net_specific_scan_wifi_reply(DBusPendingCall *call, void *user_data)
{
	__NETWORK_FUNC_ENTER__;

	int callback_flag = FALSE;
	DBusMessage *reply = dbus_pending_call_steal_reply(call);
	net_err_t Error = _net_get_error_from_netconfig_message(reply);
	net_event_info_t event_data = {0,};

	if (Error != NET_ERR_NONE)
		NETWORK_LOG(NETWORK_ERROR, "Find hidden AP failed. Error [%d]\n", Error);
	else
		NETWORK_LOG(NETWORK_LOW, "Hidden AP found\n");

	if (request_table[NETWORK_REQUEST_TYPE_SPECIFIC_SCAN].flag == TRUE) {
		if (NET_ERR_NONE != Error) {
			/* An error occurred.
			 * So lets reset specific scan request entry in the request table */
			memset(&request_table[NETWORK_REQUEST_TYPE_SPECIFIC_SCAN],
					0, sizeof(network_request_table_t));
		}

		event_data.Event = NET_EVENT_SPECIFIC_SCAN_RSP;

		NETWORK_LOG(NETWORK_LOW,
				"Sending NET_EVENT_SPECIFIC_SCAN_RSP Wi-Fi: %d Error = %d\n",
				NetworkInfo.wifi_state, Error);

		event_data.Datalength = sizeof(net_wifi_state_t);
		event_data.Data = &(NetworkInfo.wifi_state);
		event_data.Error = Error;

		callback_flag = TRUE;
	}

	dbus_message_unref(reply);
	dbus_pending_call_unref(call);

	network_dbus_pending_call_data.is_used = FALSE;
	network_dbus_pending_call_data.pcall = NULL;

	if (callback_flag)
		_net_client_callback(&event_data);

	__NETWORK_FUNC_EXIT__;
}

static void __net_scan_wifi_reply(DBusPendingCall *call, void *user_data)
{
	__NETWORK_FUNC_ENTER__;

	NETWORK_LOG(NETWORK_LOW, "__net_scan_wifi_reply() called\n");

	int callback_flag = FALSE;
	net_event_info_t event_data = {0,};

	DBusMessage *reply = dbus_pending_call_steal_reply(call);
	net_err_t Error = _net_get_error_from_message(reply);

	if (Error == NET_ERR_IN_PROGRESS || Error == NET_ERR_NONE)
		goto done;

	NETWORK_LOG(NETWORK_ERROR,
		"Error!!! WiFi Scan reply received. Error code : [%d]\n", Error);

	if (request_table[NETWORK_REQUEST_TYPE_SCAN].flag == TRUE) {
		memset(&request_table[NETWORK_REQUEST_TYPE_SCAN],
				0, sizeof(network_request_table_t));
		event_data.Error = Error;
		event_data.Event = NET_EVENT_WIFI_SCAN_RSP;

		NETWORK_LOG(NETWORK_LOW, "Sending NET_EVENT_WIFI_SCAN_RSP Error = %s\n",
				_net_print_error(event_data.Error));

		callback_flag = TRUE;
	}

done:
	dbus_message_unref(reply);
	dbus_pending_call_unref(call);

	network_dbus_pending_call_data.is_used = FALSE;
	network_dbus_pending_call_data.pcall = NULL;

	if (callback_flag)
		_net_client_callback(&event_data);

	__NETWORK_FUNC_EXIT__;
}

static void __net_set_default_reply(DBusPendingCall *call, void *user_data)
{
	__NETWORK_FUNC_ENTER__;

	NETWORK_LOG(NETWORK_LOW, "__net_set_default_reply() called\n");

	int callback_flag = FALSE;
	net_event_info_t event_data = {0,};
	int rv;

	DBusMessage *reply = dbus_pending_call_steal_reply(call);
	net_err_t Error = _net_get_error_from_message(reply);

	NETWORK_LOG(NETWORK_ERROR, "Error code : [%d]\n", Error);

	if (request_table[NETWORK_REQUEST_TYPE_SET_DEFAULT].flag == TRUE) {
		memset(&request_table[NETWORK_REQUEST_TYPE_SET_DEFAULT],
						0, sizeof(network_request_table_t));
		event_data.Event = NET_EVENT_CELLULAR_SET_DEFAULT_RSP;

		if (Error == NET_ERR_NONE) {
			rv = _net_get_boolean(reply);

			NETWORK_LOG(NETWORK_LOW, "Reply : [%s]\n", rv ? "TRUE" : "FALSE");

			if (rv)
				event_data.Error = NET_ERR_NONE;
			else
				event_data.Error = NET_ERR_UNKNOWN;
		} else
			event_data.Error = Error;

		NETWORK_LOG(NETWORK_LOW, "Sending NET_EVENT_CELLULAR_SET_DEFAULT_RSP Error = %s\n",
				_net_print_error(event_data.Error));

		callback_flag = TRUE;
	}

	dbus_message_unref(reply);
	dbus_pending_call_unref(call);

	network_dbus_pending_call_data.is_used = FALSE;
	network_dbus_pending_call_data.pcall = NULL;

	if (callback_flag)
		_net_client_callback(&event_data);

	__NETWORK_FUNC_EXIT__;
}

static char *__net_make_group_name(const char *ssid, const char *net_mode, const char *sec)
{
	char *buf = NULL;
	char *pbuf = NULL;
	const char *hidden_str = "hidden";
	const char *g_sec;
	char buf_tmp[32] = {0,};
	int i;
	int ssid_len = 0;
	int actual_len = 0;

	if (net_mode == NULL || sec == NULL)
		return NULL;

	if (NULL != ssid) {
		ssid_len = strlen(ssid);
		actual_len = ssid_len * 2;
	} else {
		ssid_len = strlen(hidden_str);
		actual_len = ssid_len;
	}

	if (g_strcmp0(net_mode, "managed") != 0)
		return NULL;

	if (!g_strcmp0(sec, "wpa") || !g_strcmp0(sec, "rsn"))
		g_sec = "psk";
	else
		g_sec = sec;

	buf = g_try_malloc0(actual_len + strlen(net_mode) + strlen(sec) + 3);
	if (buf == NULL)
		return NULL;

	if (NULL != ssid) {
		pbuf = buf;
		for (i = 0; i < ssid_len; i++) {
			g_snprintf(pbuf, 3, "%02x", ssid[i]);
			pbuf += 2;
		}
	} else
		g_strlcat(buf, hidden_str,
				actual_len + strlen(net_mode) + strlen(sec) + 3);

	g_snprintf(buf_tmp, 32, "_%s_%s", net_mode, g_sec);
	g_strlcat(buf, buf_tmp,
			actual_len + strlen(net_mode) + strlen(sec) + 3);

	NETWORK_LOG(NETWORK_HIGH, "Group name : %s\n", buf);

	return buf;
}

static int __net_append_param(DBusMessage *message, char *param_array[])
{
	int count = 0;
	dbus_uint32_t uint32 = 0;
	DBusMessageIter iter;
	DBusMessageIter container_iter;
	char *args = NULL;
	char *ch = NULL;

	if (param_array == NULL)
		return NET_ERR_NONE;

	dbus_message_iter_init_append(message, &iter);

	while (param_array[count] != NULL) {
		args = param_array[count];
		NETWORK_LOG(NETWORK_HIGH, "parameter %d - [%s]", count, param_array[count]);

		ch = strchr(args, ':');
		if (ch == NULL) {
			NETWORK_LOG(NETWORK_ERROR, "Invalid parameter[\"%s\"]\n", args);
			return NET_ERR_INVALID_PARAM;
		}
		*ch = 0; ch++;

		if (strcmp(args, CONNMAN_CLIENT_DBUS_TYPE_STRING) == 0)
			dbus_message_iter_append_basic(&iter, DBUS_TYPE_STRING, &ch);
		else if (strcmp(args, CONNMAN_CLIENT_DBUS_TYPE_UINT32) == 0) {
			uint32 = strtoul(ch, NULL, 0);
			dbus_message_iter_append_basic(&iter, DBUS_TYPE_UINT32, &uint32);
		} else if (strcmp(args, CONNMAN_CLIENT_DBUS_TYPE_VARIANT) == 0) {
			args = ch;
			ch = strchr(args, ':');
			if (ch == NULL) {
				NETWORK_LOG(NETWORK_ERROR, "Invalid data format[\"%s\"]\n", args);
				return NET_ERR_INVALID_PARAM;
			}
			*ch = 0; ch++;

			if (strcmp(args, CONNMAN_CLIENT_DBUS_TYPE_STRING) == 0) {
				dbus_message_iter_open_container(&iter, DBUS_TYPE_VARIANT,
						DBUS_TYPE_STRING_AS_STRING, &container_iter);
				dbus_message_iter_append_basic(&container_iter, DBUS_TYPE_STRING, &ch);
				dbus_message_iter_close_container(&iter, &container_iter);
			} else {
				NETWORK_LOG(NETWORK_ERROR, "Not supported data format[\"%s\"]\n", args);
				return NET_ERR_INVALID_PARAM;
			}
		} else {
			NETWORK_LOG(NETWORK_ERROR, "Not supported data format[\"%s\"]\n", args);
			return NET_ERR_INVALID_PARAM;
		}

		count++;
	}

	return NET_ERR_NONE;
}

static inline void __net_dict_append_strings(DBusMessageIter *dict,
		const char *field, const char *value)
{
	DBusMessageIter entry;

	dbus_message_iter_open_container(dict, DBUS_TYPE_DICT_ENTRY,
								NULL, &entry);
	dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &field);
	dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &value);
	dbus_message_iter_close_container(dict, &entry);
}

static int __net_dbus_set_agent_field(char *field_name, char *field_value)
{
	DBusConnection* conn = NULL;
	net_err_t Error = NET_ERR_NONE;
	DBusError error;
	DBusMessage *message = NULL;
	DBusMessage *reply = NULL;
	DBusMessageIter itr, dict;

	__NETWORK_FUNC_ENTER__;

	conn = dbus_bus_get(DBUS_BUS_SYSTEM, NULL);
	if (NULL == conn) {
		NETWORK_LOG(NETWORK_ERROR, "Failed to get a system bus\n");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_UNKNOWN;
	}

	message = dbus_message_new_method_call(NETCONFIG_SERVICE,
			NETCONFIG_WIFI_PATH, CONNMAN_AGENT_INTERFACE,
			"SetField");
	if (NULL == message) {
		NETWORK_LOG(NETWORK_ERROR, "dbus_message_new_method_call() "
				"failed\n");
		dbus_connection_unref(conn);
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_UNKNOWN;
	}

	dbus_message_iter_init_append(message, &itr);

	dbus_message_iter_open_container(&itr, DBUS_TYPE_ARRAY,
			(DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
			 DBUS_TYPE_STRING_AS_STRING
			 DBUS_TYPE_STRING_AS_STRING
			 DBUS_DICT_ENTRY_END_CHAR_AS_STRING), &dict);

	__net_dict_append_strings(&dict, field_name, field_value);
	NETWORK_LOG(NETWORK_HIGH, "Adding - %s %s\n", field_name, field_value);

	dbus_message_iter_close_container(&itr, &dict);

	dbus_error_init(&error);

	reply = dbus_connection_send_with_reply_and_block(conn, message,
			DBUS_REPLY_TIMEOUT, &error);
	if (NULL == reply) {
		Error = NET_ERR_UNKNOWN;
		if (dbus_error_is_set (&error) == TRUE) {
			NETWORK_LOG(NETWORK_ERROR,
				"dbus_connection_send_with_reply_and_block() "
				"failed, Error[%s: %s]\n", error.name,
				error.message);
			Error = __net_error_string_to_enum(error.name);
			dbus_error_free(&error);
		}

		dbus_message_unref(message);
		dbus_connection_unref(conn);
		__NETWORK_FUNC_EXIT__;
		return Error;
	}

	dbus_message_unref(reply);
	dbus_message_unref(message);
	dbus_connection_unref(conn);

	__NETWORK_FUNC_EXIT__;
	return NET_ERR_NONE;
}

/*****************************************************************************
 * 	Global Functions Definition
 *****************************************************************************/
DBusMessage *_net_invoke_dbus_method(const char* dest, const char* path,
		char* interface_name, char* method,
		char* param_array[], int* dbus_error)
{
	__NETWORK_FUNC_ENTER__;

	DBusError error;
	DBusConnection* conn = NULL;
	DBusMessage *reply = NULL;
	DBusMessage *message = NULL;

	*dbus_error = NET_ERR_NONE;

	NETWORK_LOG(NETWORK_HIGH, "[DBUS Sync] %s.%s, %s\n",
			interface_name, method, path);

	conn = dbus_bus_get(DBUS_BUS_SYSTEM, NULL);
	if (conn == NULL) {
		NETWORK_LOG(NETWORK_ERROR, "Failed to get a system bus\n");

		*dbus_error = NET_ERR_UNKNOWN;

		__NETWORK_FUNC_EXIT__;
		return NULL;
	}

	message = dbus_message_new_method_call(dest, path, interface_name, method);
	if (message == NULL) {
		NETWORK_LOG(NETWORK_ERROR, "dbus_message_new_method_call() failed\n");

		dbus_connection_unref(conn);
		*dbus_error = NET_ERR_UNKNOWN;

		__NETWORK_FUNC_EXIT__;
		return NULL;
	}

	if (__net_append_param(message, param_array) != NET_ERR_NONE) {
		NETWORK_LOG(NETWORK_ERROR, "__net_append_param() failed\n");

		dbus_message_unref(message);
		dbus_connection_unref(conn);

		*dbus_error = NET_ERR_INVALID_PARAM;

		__NETWORK_FUNC_EXIT__;
		return NULL;
	}

	dbus_error_init(&error);

	reply = dbus_connection_send_with_reply_and_block(conn, message,
								DBUS_REPLY_TIMEOUT, &error);
	if (reply == NULL) {
		if (dbus_error_is_set(&error) == TRUE) {
			NETWORK_LOG(NETWORK_ERROR,
					"dbus_connection_send_with_reply_and_block() failed."
					"error [%s: %s]\n", error.name, error.message);

			*dbus_error = __net_error_string_to_enum(error.name);
			dbus_error_free(&error);
		} else {
			NETWORK_LOG(NETWORK_ERROR,
					"dbus_connection_send_with_reply_and_block() failed\n");

			*dbus_error = NET_ERR_UNKNOWN;
		}

		dbus_message_unref(message);
		dbus_connection_unref(conn);

		__NETWORK_FUNC_EXIT__;
		return NULL;
	}

	dbus_message_unref(message);
	dbus_connection_unref(conn);

	__NETWORK_FUNC_EXIT__;
	return reply;
}

int _net_invoke_dbus_method_nonblock(const char* dest, const char* path,
		char* interface_name, char* method,
		DBusPendingCallNotifyFunction notify_func)
{
	__NETWORK_FUNC_ENTER__;

	DBusConnection *conn = NULL;
	DBusMessage *message = NULL;
	DBusPendingCall *call;
	dbus_bool_t result;

	NETWORK_LOG(NETWORK_HIGH, "[DBUS Async] %s.%s, %s\n",
			interface_name, method, path);

	conn = dbus_bus_get(DBUS_BUS_SYSTEM, NULL);
	if (conn == NULL) {
		NETWORK_LOG(NETWORK_ERROR, "Failed to get a system bus\n");

		__NETWORK_FUNC_EXIT__;
		return NET_ERR_UNKNOWN;
	}

	message = dbus_message_new_method_call(dest, path, interface_name, method);
	if (message == NULL) {
		NETWORK_LOG(NETWORK_ERROR, "dbus_message_new_method_call() Failed\n");

		dbus_connection_unref(conn);

		__NETWORK_FUNC_EXIT__;
		return NET_ERR_UNKNOWN;
	}

	result = dbus_connection_send_with_reply(conn, message, &call,
			DBUS_REPLY_TIMEOUT);
	if (result == FALSE || call == NULL) {
		NETWORK_LOG(NETWORK_ERROR, "dbus_connection_send_with_reply() Failed\n");

		dbus_message_unref(message);
		dbus_connection_unref(conn);

		__NETWORK_FUNC_EXIT__;
		return NET_ERR_UNKNOWN;
	}

	if (notify_func == NULL)
		dbus_pending_call_cancel(call);
	else {
		dbus_pending_call_set_notify(call, notify_func, NULL, NULL);

		network_dbus_pending_call_data.pcall = call;
		network_dbus_pending_call_data.is_used = TRUE;
	}

	dbus_message_unref(message);
	dbus_connection_unref(conn);

	__NETWORK_FUNC_EXIT__;
	return NET_ERR_NONE;
}

int _net_dbus_open_connection(const char* profile_name)
{
	__NETWORK_FUNC_ENTER__;

	net_err_t Error = NET_ERR_NONE;

	Error = _net_invoke_dbus_method_nonblock(CONNMAN_SERVICE, profile_name,
			CONNMAN_SERVICE_INTERFACE, "Connect", __net_open_connection_reply);

	__NETWORK_FUNC_EXIT__;
	return Error;
}

int _net_dbus_close_connection(const char* profile_name)
{
	__NETWORK_FUNC_ENTER__;

	net_err_t Error = NET_ERR_NONE;

	Error = _net_invoke_dbus_method_nonblock(CONNMAN_SERVICE, profile_name,
			CONNMAN_SERVICE_INTERFACE, "Disconnect", __net_close_connection_reply);

	__NETWORK_FUNC_EXIT__;
	return Error;
}

int _net_dbus_scan_request(void)
{
	__NETWORK_FUNC_ENTER__;

	net_err_t Error = NET_ERR_NONE;

	Error = _net_invoke_dbus_method_nonblock(CONNMAN_SERVICE,
			CONNMAN_WIFI_TECHNOLOGY_PREFIX,
			CONNMAN_TECHNOLOGY_INTERFACE, "Scan", __net_scan_wifi_reply);

	if (Error == NET_ERR_IN_PROGRESS)
		Error = NET_ERR_NONE;

	__NETWORK_FUNC_EXIT__;
	return Error;
}

int _net_dbus_set_default(const char* profile_name)
{
	__NETWORK_FUNC_ENTER__;

	net_err_t Error = NET_ERR_NONE;

	Error = _net_invoke_dbus_method_nonblock(TELEPHONY_SERVICE,
			profile_name, TELEPHONY_PROFILE_INTERFACE,
			"SetDefaultConnection", __net_set_default_reply);

	__NETWORK_FUNC_EXIT__;
	return Error;
}

int _net_dbus_set_bgscan_mode(net_wifi_background_scan_mode_t mode)
{
	__NETWORK_FUNC_ENTER__;

	net_err_t Error = NET_ERR_NONE;
	DBusMessage *message = NULL;

	char param0[64] = "";
	char path[CONNMAN_MAX_BUFLEN] = NETCONFIG_WIFI_PATH;
	char* param_array[] = { NULL, NULL };

	g_snprintf(param0, 64, "uint32:%d", mode);
	param_array[0] = param0;

	message = _net_invoke_dbus_method(NETCONFIG_SERVICE, path,
			NETCONFIG_WIFI_INTERFACE, "SetBgscan", param_array, &Error);

	if (Error != NET_ERR_NONE)
		NETWORK_LOG(NETWORK_ERROR, "_net_invoke_dbus_method failed\n");

	if (message)
		dbus_message_unref(message);

	__NETWORK_FUNC_EXIT__;
	return Error;
}

int _net_dbus_get_technology_state(network_tech_state_info_t* tech_state)
{
	__NETWORK_FUNC_ENTER__;

	net_err_t Error = NET_ERR_NONE;
	DBusMessage *message = NULL;

	if ((tech_state == NULL) || (strlen(tech_state->technology) == 0)) {
		NETWORK_LOG(NETWORK_ERROR, "Invalid parameter\n");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_INVALID_PARAM;
	}

	message = _net_invoke_dbus_method(CONNMAN_SERVICE,
			CONNMAN_MANAGER_PATH, CONNMAN_MANAGER_INTERFACE,
			"GetTechnologies", NULL, &Error);

	if (message == NULL) {
		NETWORK_LOG(NETWORK_ERROR, "Failed to get technology info\n");
		goto done;
	}

	Error = _net_get_tech_state(message, tech_state);

	NETWORK_LOG(NETWORK_HIGH,
			"Technology-[%s] Powered-[%d] Connected-[%d]",
			tech_state->technology,
			tech_state->Powered,
			tech_state->Connected);

	dbus_message_unref(message);

done:
	__NETWORK_FUNC_EXIT__;
	return Error;
}

int _net_dbus_get_network_status(net_device_t device_type, net_cm_network_status_t* network_status)
{
	__NETWORK_FUNC_ENTER__;

	net_err_t Error = NET_ERR_NONE;
	network_tech_state_info_t tech_state = {{0,},};

	if (device_type == NET_DEVICE_WIFI)
		g_strlcpy(tech_state.technology, "wifi", NET_TECH_LENGTH_MAX);
	else if (device_type == NET_DEVICE_CELLULAR)
		g_strlcpy(tech_state.technology, "cellular", NET_TECH_LENGTH_MAX);
	else if (device_type == NET_DEVICE_ETHERNET)
		g_strlcpy(tech_state.technology, "ethernet", NET_TECH_LENGTH_MAX);
	else if (device_type == NET_DEVICE_BLUETOOTH)
		g_strlcpy(tech_state.technology, "bluetooth", NET_TECH_LENGTH_MAX);
	else {
		Error = NET_ERR_INVALID_PARAM;
		goto done;
	}

	Error = _net_dbus_get_technology_state(&tech_state);
	if (Error != NET_ERR_NONE) {
		NETWORK_LOG(NETWORK_ERROR,
			"_net_dbus_get_technology_state() failed. Error [%s]\n",
			_net_print_error(Error));
		goto done;
	}

	if (tech_state.Connected == TRUE)
		*network_status = NET_STATUS_AVAILABLE;
	else
		*network_status = NET_STATUS_UNAVAILABLE;

done:
	__NETWORK_FUNC_EXIT__;
	return Error;
}

int _net_dbus_get_tech_status(net_device_t device_type, net_tech_info_t* tech_status)
{
	__NETWORK_FUNC_ENTER__;

	net_err_t Error = NET_ERR_NONE;
	network_tech_state_info_t tech_state = {{0,},};

	if (device_type == NET_DEVICE_WIFI)
		g_strlcpy(tech_state.technology, "wifi", NET_TECH_LENGTH_MAX);
	else if (device_type == NET_DEVICE_CELLULAR)
		g_strlcpy(tech_state.technology, "cellular", NET_TECH_LENGTH_MAX);
	else if (device_type == NET_DEVICE_ETHERNET)
		g_strlcpy(tech_state.technology, "ethernet", NET_TECH_LENGTH_MAX);
	else if (device_type == NET_DEVICE_BLUETOOTH)
		g_strlcpy(tech_state.technology, "bluetooth", NET_TECH_LENGTH_MAX);
	else {
		Error = NET_ERR_INVALID_PARAM;
		goto done;
	}

	Error = _net_dbus_get_technology_state(&tech_state);
	if (Error != NET_ERR_NONE) {
		NETWORK_LOG(NETWORK_ERROR,
			"_net_dbus_get_technology_state() failed. Error [%s]\n",
			_net_print_error(Error));
		goto done;
	}

	if (tech_state.Powered == TRUE)
		tech_status->powered = TRUE;
	else
		tech_status->powered = FALSE;

	if (tech_state.Connected == TRUE)
		tech_status->connected = TRUE;
	else
		tech_status->connected = FALSE;

done:
	__NETWORK_FUNC_EXIT__;
	return Error;
}

int _net_dbus_get_statistics(net_device_t device_type, net_statistics_type_e statistics_type, unsigned long long *size)
{
	net_err_t Error = NET_ERR_NONE;
	DBusMessage *message = NULL;
	char *method = NULL;

	if (device_type == NET_DEVICE_WIFI) {
		switch (statistics_type) {
		case NET_STATISTICS_TYPE_LAST_RECEIVED_DATA:
			method = "GetWifiLastRxBytes";
			break;
		case NET_STATISTICS_TYPE_LAST_SENT_DATA:
			method = "GetWifiLastTxBytes";
			break;
		case NET_STATISTICS_TYPE_TOTAL_RECEIVED_DATA:
			method = "GetWifiTotalRxBytes";
			break;
		case NET_STATISTICS_TYPE_TOTAL_SENT_DATA:
			method = "GetWifiTotalTxBytes";
			break;
		default:
			NETWORK_LOG(NETWORK_ERROR, "Invalid profile name\n");
			return NET_ERR_INVALID_PARAM;
		}
	} else {
		NETWORK_LOG(NETWORK_ERROR, "Invalid profile name\n");
		return NET_ERR_INVALID_PARAM;
	}

	message = _net_invoke_dbus_method(
			NETCONFIG_SERVICE, NETCONFIG_STATISTICS_PATH,
			NETCONFIG_STATISTICS_INTERFACE, method, NULL, &Error);
	if (message == NULL) {
		NETWORK_LOG(NETWORK_ERROR, "Failed to get service properties\n");
		return Error;
	}

	*size = _net_get_uint64(message);

	NETWORK_LOG(NETWORK_HIGH, "success [%s] statistics size : [%llu]\n", method, *size);
	dbus_message_unref(message);

	return Error;
}

int _net_dbus_set_statistics(net_device_t device_type, net_statistics_type_e statistics_type)
{
	net_err_t Error = NET_ERR_NONE;
	DBusMessage *message = NULL;
	char *method = NULL;

	if (device_type == NET_DEVICE_CELLULAR) {
		switch (statistics_type) {
		case NET_STATISTICS_TYPE_LAST_RECEIVED_DATA:
			method = "ResetCellularLastRxBytes";
			break;
		case NET_STATISTICS_TYPE_LAST_SENT_DATA:
			method = "ResetCellularLastTxBytes";
			break;
		case NET_STATISTICS_TYPE_TOTAL_RECEIVED_DATA:
			method = "ResetCellularTotalRxBytes";
			break;
		case NET_STATISTICS_TYPE_TOTAL_SENT_DATA:
			method = "ResetCellularTotalTxBytes";
			break;
		default:
			NETWORK_LOG(NETWORK_ERROR, "Invalid profile name\n");
			return NET_ERR_INVALID_PARAM;
		}
	} else if (device_type == NET_DEVICE_WIFI) {
		switch (statistics_type) {
		case NET_STATISTICS_TYPE_LAST_RECEIVED_DATA:
			method = "ResetWifiLastRxBytes";
			break;
		case NET_STATISTICS_TYPE_LAST_SENT_DATA:
			method = "ResetWifiLastTxBytes";
			break;
		case NET_STATISTICS_TYPE_TOTAL_RECEIVED_DATA:
			method = "ResetWifiTotalRxBytes";
			break;
		case NET_STATISTICS_TYPE_TOTAL_SENT_DATA:
			method = "ResetWifiTotalTxBytes";
			break;
		default:
			NETWORK_LOG(NETWORK_ERROR, "Invalid profile name\n");
			return NET_ERR_INVALID_PARAM;
		}
	} else {
		NETWORK_LOG(NETWORK_ERROR, "Invalid profile name\n");
		return NET_ERR_INVALID_PARAM;
	}

	message = _net_invoke_dbus_method(
			NETCONFIG_SERVICE, NETCONFIG_STATISTICS_PATH,
			NETCONFIG_STATISTICS_INTERFACE, method, NULL, &Error);
	if (message == NULL) {
		NETWORK_LOG(NETWORK_ERROR, "Failed to get service properties\n");
		return Error;
	}

	NETWORK_LOG(NETWORK_HIGH, "reset [%s] statistics success\n", method);
	dbus_message_unref(message);

	return Error;
}

int _net_dbus_get_state(char* state)
{
	__NETWORK_FUNC_ENTER__;

	net_err_t Error = NET_ERR_NONE;
	DBusMessage *message = NULL;
	char *net_state = NULL;

	message = _net_invoke_dbus_method(
			CONNMAN_SERVICE, CONNMAN_MANAGER_PATH,
			CONNMAN_MANAGER_INTERFACE, "GetProperties", NULL, &Error);
	if (message == NULL) {
		NETWORK_LOG(NETWORK_ERROR, "Failed to get service properties\n");

		__NETWORK_FUNC_EXIT__;
		return Error;
	}

	net_state = _net_get_string(message);
	g_strlcpy(state, net_state, CONNMAN_STATE_STRLEN);

	NETWORK_LOG(NETWORK_HIGH, "State: %s\n", state);

	dbus_message_unref(message);

	__NETWORK_FUNC_EXIT__;
	return Error;
}

int _net_dbus_set_eap_config_fields(
		const net_wifi_connect_service_info_t *wifi_info)
{
	__NETWORK_FUNC_ENTER__;

	net_err_t Error = NET_ERR_NONE;
	DBusError error;
	DBusMessage *message = NULL;
	DBusMessageIter itr, dict;
	DBusConnection* conn = NULL;
	DBusMessage *reply = NULL;

	conn = dbus_bus_get(DBUS_BUS_SYSTEM, NULL);
	if (NULL == conn) {
		NETWORK_LOG(NETWORK_ERROR, "Failed to get a system bus\n");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_UNKNOWN;
	}

	message = dbus_message_new_method_call(NETCONFIG_SERVICE,
			NETCONFIG_WIFI_PATH, NETCONFIG_WIFI_INTERFACE,
			"CreateConfig");
	if (NULL == message) {
		NETWORK_LOG(NETWORK_ERROR, "dbus_message_new_method_call() "
				"failed\n");
		dbus_connection_unref(conn);
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_UNKNOWN;
	}

	dbus_message_iter_init_append(message, &itr);

	dbus_message_iter_open_container(&itr, DBUS_TYPE_ARRAY,
			(DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
			 DBUS_TYPE_STRING_AS_STRING
			 DBUS_TYPE_STRING_AS_STRING
			 DBUS_DICT_ENTRY_END_CHAR_AS_STRING), &dict);

	__net_dict_append_strings(&dict, CONNMAN_CONFIG_FIELD_TYPE, "wifi");
	NETWORK_LOG(NETWORK_HIGH, "Adding - %s wifi\n",
			CONNMAN_CONFIG_FIELD_TYPE);

	if (NULL != wifi_info->ssid) {
		__net_dict_append_strings(&dict, CONNMAN_CONFIG_FIELD_NAME,
				wifi_info->ssid);
		NETWORK_LOG(NETWORK_HIGH, "Adding - %s %s\n",
				CONNMAN_CONFIG_FIELD_NAME, wifi_info->ssid);
	}

	if (NULL != wifi_info->eap_type) {
		__net_dict_append_strings(&dict,
				CONNMAN_CONFIG_FIELD_EAP_METHOD,
				wifi_info->eap_type);
		NETWORK_LOG(NETWORK_HIGH, "Adding - %s %s\n",
				CONNMAN_CONFIG_FIELD_EAP_METHOD,
				wifi_info->eap_type);
	}

	if (NULL != wifi_info->identity) {
		__net_dict_append_strings(&dict, CONNMAN_CONFIG_FIELD_IDENTITY,
				wifi_info->identity);
		NETWORK_LOG(NETWORK_HIGH, "Adding - %s %s \n",
				CONNMAN_CONFIG_FIELD_IDENTITY,
				wifi_info->identity);
	}

	if (NULL != wifi_info->password) {
		__net_dict_append_strings(&dict,
				CONNMAN_CONFIG_FIELD_PASSPHRASE,
				wifi_info->password);
		NETWORK_LOG(NETWORK_HIGH, "Adding - %s %s \n",
				CONNMAN_CONFIG_FIELD_PASSPHRASE,
				wifi_info->password);
	}

	if (NULL != wifi_info->eap_auth && strcmp(wifi_info->eap_auth, "NONE")) {
		__net_dict_append_strings(&dict, CONNMAN_CONFIG_FIELD_PHASE2,
				wifi_info->eap_auth);
		NETWORK_LOG(NETWORK_HIGH, "Adding - %s %s \n",
				CONNMAN_CONFIG_FIELD_PHASE2,
				wifi_info->eap_auth);
	}

	if (NULL != wifi_info->ca_cert_file) {
		__net_dict_append_strings(&dict,
				CONNMAN_CONFIG_FIELD_CA_CERT_FILE,
				wifi_info->ca_cert_file);
		NETWORK_LOG(NETWORK_HIGH, "Adding - %s %s \n",
				CONNMAN_CONFIG_FIELD_CA_CERT_FILE,
				wifi_info->ca_cert_file);
	}

	if (NULL != wifi_info->client_cert_file) {
		__net_dict_append_strings(&dict,
				CONNMAN_CONFIG_FIELD_CLIENT_CERT_FILE,
				wifi_info->client_cert_file);
		NETWORK_LOG(NETWORK_HIGH, "Adding - %s %s \n",
				CONNMAN_CONFIG_FIELD_CLIENT_CERT_FILE,
				wifi_info->client_cert_file);
	}

	if (NULL != wifi_info->private_key_file) {
		__net_dict_append_strings(&dict,
				CONNMAN_CONFIG_FIELD_PVT_KEY_FILE,
				wifi_info->private_key_file);
		NETWORK_LOG(NETWORK_HIGH, "Adding - %s %s \n",
				CONNMAN_CONFIG_FIELD_PVT_KEY_FILE,
				wifi_info->private_key_file);
	}

	if (NULL != wifi_info->private_key_password) {
		__net_dict_append_strings(&dict,
				CONNMAN_CONFIG_FIELD_PVT_KEY_PASSPHRASE,
				wifi_info->private_key_password);
		NETWORK_LOG(NETWORK_HIGH, "Adding - %s %s \n",
				CONNMAN_CONFIG_FIELD_PVT_KEY_PASSPHRASE,
				wifi_info->private_key_password);
	}

	dbus_message_iter_close_container(&itr, &dict);

	dbus_error_init(&error);

	reply = dbus_connection_send_with_reply_and_block(conn, message,
			DBUS_REPLY_TIMEOUT, &error);
	if (NULL == reply) {
		if (dbus_error_is_set (&error) == TRUE) {
			NETWORK_LOG(NETWORK_ERROR,
				"dbus_connection_send_with_reply_and_block() "
				"failed, Error[%s: %s]\n", error.name,
				error.message);
			Error = __net_error_string_to_enum(error.name);
			dbus_error_free(&error);

			goto done;
		}

		Error = NET_ERR_UNKNOWN;
		goto done;
	}

	dbus_message_unref(reply);

	NETWORK_LOG(NETWORK_HIGH, "Successfully sent eap config fields\n");
done:
	dbus_message_unref(message);
	dbus_connection_unref(conn);

	__NETWORK_FUNC_EXIT__;
	return Error;
}

int _net_dbus_set_agent_passphrase(const char *passphrase)
{
	__NETWORK_FUNC_ENTER__;

	int ret_val;

	if (NULL == passphrase || strlen(passphrase) <= 0) {
		NETWORK_LOG(NETWORK_ERROR, "Invalid param \n");
		return NET_ERR_INVALID_PARAM;
	}

	ret_val = __net_dbus_set_agent_field(NETCONFIG_AGENT_FIELD_PASSPHRASE, passphrase);
	if (NET_ERR_NONE != ret_val) {
		NETWORK_LOG(NETWORK_ERROR, "__net_dbus_set_agent_field failed. Error = %d \n", ret_val);
		return ret_val;
	}

	NETWORK_LOG(NETWORK_HIGH, "Successfully sent passphrase\n");

	__NETWORK_FUNC_EXIT__;
	return NET_ERR_NONE;
}

int _net_dbus_set_agent_wps_pbc(void)
{
	__NETWORK_FUNC_ENTER__;

	int ret_val;

	ret_val = __net_dbus_set_agent_field(NETCONFIG_AGENT_FIELD_WPS_PBC, "enable");
	if (NET_ERR_NONE != ret_val) {
		NETWORK_LOG(NETWORK_ERROR, "__net_dbus_set_agent_field failed. Error = %d \n", ret_val);
		return ret_val;
	}

	NETWORK_LOG(NETWORK_HIGH, "Successfully sent wps pbc\n");

	__NETWORK_FUNC_EXIT__;
	return NET_ERR_NONE;
}

int _net_dbus_set_agent_wps_pin(char *wps_pin)
{
	__NETWORK_FUNC_ENTER__;

	int ret_val;

	if (NULL == wps_pin || strlen(wps_pin) <= 0) {
		NETWORK_LOG(NETWORK_ERROR, "Invalid param \n");
		return NET_ERR_INVALID_PARAM;
	}

	ret_val = __net_dbus_set_agent_field(NETCONFIG_AGENT_FIELD_WPS_PIN, wps_pin);
	if (NET_ERR_NONE != ret_val) {
		NETWORK_LOG(NETWORK_ERROR, "__net_dbus_set_agent_field failed. Error = %d \n", ret_val);
		return ret_val;
	}

	NETWORK_LOG(NETWORK_HIGH, "Successfully sent wps pin\n");

	__NETWORK_FUNC_EXIT__;
	return NET_ERR_NONE;
}

int _net_dbus_connect_service(const net_wifi_connect_service_info_t *wifi_connection_info)
{
	__NETWORK_FUNC_ENTER__;

	net_err_t Error = NET_ERR_NONE;
	char *grp_name = NULL;
	int profile_count = 0;
	net_profile_info_t* profile_info = NULL;
	int i = 0;

	/* Get group name with prefix 'ssid' in hex */
	grp_name = __net_make_group_name(wifi_connection_info->ssid,
			wifi_connection_info->mode,
			wifi_connection_info->security);
	if (NULL == grp_name) {
		NETWORK_LOG(NETWORK_ERROR, "Failed to make a group name\n");

		__NETWORK_FUNC_EXIT__;
		return NET_ERR_UNKNOWN;
	}

	Error = _net_get_profile_list(NET_DEVICE_WIFI, &profile_info, &profile_count);
	if (NET_ERR_NONE != Error) {
		NETWORK_LOG(NETWORK_ERROR,
				"_net_get_profile_list fail. Error [%s]\n",
				_net_print_error(Error));

		goto done;
	}

	for (i = 0; i < profile_count; i++) {
		if (g_strstr_len(profile_info[i].ProfileName,
				NET_PROFILE_NAME_LEN_MAX+1, grp_name) != NULL) {
			NETWORK_LOG(NETWORK_ERROR, "Found profile %s\n",
					profile_info[i].ProfileName);

			break;
		}
	}

	if (i >= profile_count) {
		NETWORK_LOG(NETWORK_ERROR, "No matching profile found\n");
		Error = NET_ERR_NO_SERVICE;

		goto done;
	}

	g_strlcpy(request_table[NETWORK_REQUEST_TYPE_OPEN_CONNECTION].ProfileName,
			profile_info[i].ProfileName, NET_PROFILE_NAME_LEN_MAX+1);

	if (g_strcmp0(wifi_connection_info->security, "ieee8021x") == 0) {
		/* Create the EAP config file */
		Error = _net_dbus_set_eap_config_fields(wifi_connection_info);
		if (NET_ERR_NONE != Error) {
			NETWORK_LOG(NETWORK_ERROR, "Fail to create eap_config\n");

			goto done;
		}
	} else {
		Error = _net_dbus_set_agent_passphrase(wifi_connection_info->passphrase);
		if (NET_ERR_NONE != Error) {
			NETWORK_LOG(NETWORK_ERROR, "Fail to set agent_passphrase\n");

			goto done;
		}
	}

	Error = _net_dbus_open_connection(profile_info[i].ProfileName);
	if (NET_ERR_NONE != Error) {
		NETWORK_LOG(NETWORK_ERROR,
				"Failed to request open connection, Error [%s]\n",
				_net_print_error(Error));

		memset(&request_table[NETWORK_REQUEST_TYPE_OPEN_CONNECTION],
				0, sizeof(network_request_table_t));
	} else
		NETWORK_LOG(NETWORK_HIGH, "Sent Connect request\n");

done:
	NET_MEMFREE(profile_info);
	g_free(grp_name);

	__NETWORK_FUNC_EXIT__;
	return Error;
}

int _net_dbus_set_profile_ipv4(net_profile_info_t* prof_info, char* profile_name)
{
	__NETWORK_FUNC_ENTER__;

	net_err_t Error = NET_ERR_NONE;
	DBusError error;

	const char *manual_method = "manual";
	const char *dhcp_method = "dhcp";
	const char *off_method = "off";

	const char *prop_ipv4_configuration = "IPv4.Configuration";
	const char *prop_method = "Method";
	const char *prop_address = "Address";
	const char *prop_gateway = "Gateway";
	const char *prop_netmask = "Netmask";	

	char ip_buffer[NETPM_IPV4_STR_LEN_MAX+1] = "";
	char netmask_buffer[NETPM_IPV4_STR_LEN_MAX+1] = "";
	char gateway_buffer[NETPM_IPV4_STR_LEN_MAX+1] = "";

	char *ipaddress = ip_buffer;
	char *netmask = netmask_buffer;
	char *gateway = gateway_buffer;

	DBusMessage *message = NULL;
	DBusMessage *reply = NULL;
	DBusMessageIter itr, variant, dict, entry, sub_variant;
	DBusConnection* conn = NULL;

	if ((prof_info == NULL) || (profile_name == NULL) || (strlen(profile_name) == 0)) {
		NETWORK_LOG(NETWORK_ERROR, "Invalid argument\n");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_INVALID_PARAM;
	}

	g_strlcpy(ip_buffer,
			inet_ntoa(prof_info->ProfileInfo.Wlan.net_info.IpAddr.Data.Ipv4),
			NETPM_IPV4_STR_LEN_MAX + 1);

	g_strlcpy(netmask_buffer,
			inet_ntoa(prof_info->ProfileInfo.Wlan.net_info.SubnetMask.Data.Ipv4),
			NETPM_IPV4_STR_LEN_MAX + 1);

	g_strlcpy(gateway_buffer,
			inet_ntoa(prof_info->ProfileInfo.Wlan.net_info.GatewayAddr.Data.Ipv4),
			NETPM_IPV4_STR_LEN_MAX + 1);

	NETWORK_LOG(NETWORK_HIGH, "ipaddress: %s, netmask: %s, gateway: %s\n",
			ipaddress, netmask, gateway);

	conn = dbus_bus_get(DBUS_BUS_SYSTEM, NULL);
	if (conn == NULL) {
		NETWORK_LOG(NETWORK_ERROR, "Failed to get a system bus\n");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_UNKNOWN;
	}

	/** Send ipaddress, netmask, gateway configuration */
	message = dbus_message_new_method_call(CONNMAN_SERVICE,
			profile_name, CONNMAN_SERVICE_INTERFACE, "SetProperty");
	if (message == NULL) {
		NETWORK_LOG(NETWORK_ERROR, "dbus_message_new_method_call() failed\n");
		dbus_connection_unref(conn);
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_UNKNOWN;
	}
	NETWORK_LOG(NETWORK_HIGH, "DBus Message 1/2: %s %s %s %s\n", CONNMAN_SERVICE,
			profile_name, CONNMAN_SERVICE_INTERFACE, "SetProperty");

	dbus_message_iter_init_append(message, &itr);
	dbus_message_iter_append_basic(&itr, DBUS_TYPE_STRING, &prop_ipv4_configuration);

	dbus_message_iter_open_container
		(&itr, DBUS_TYPE_VARIANT,
		 (DBUS_TYPE_ARRAY_AS_STRING
		  DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
		  DBUS_TYPE_STRING_AS_STRING
		  DBUS_TYPE_VARIANT_AS_STRING
		  DBUS_DICT_ENTRY_END_CHAR_AS_STRING),
		 &variant);
	dbus_message_iter_open_container
		(&variant, DBUS_TYPE_ARRAY,
		 (DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
		  DBUS_TYPE_STRING_AS_STRING
		  DBUS_TYPE_VARIANT_AS_STRING
		  DBUS_DICT_ENTRY_END_CHAR_AS_STRING),
		 &dict);

	if (prof_info->ProfileInfo.Wlan.net_info.IpConfigType == NET_IP_CONFIG_TYPE_DYNAMIC ||
	    prof_info->ProfileInfo.Wlan.net_info.IpConfigType == NET_IP_CONFIG_TYPE_AUTO_IP) {
		dbus_message_iter_open_container(&dict, DBUS_TYPE_DICT_ENTRY, NULL, &entry);

		dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &prop_method);
		dbus_message_iter_open_container(&entry, DBUS_TYPE_VARIANT,
						DBUS_TYPE_STRING_AS_STRING, &sub_variant);
		dbus_message_iter_append_basic(&sub_variant, DBUS_TYPE_STRING, &dhcp_method);
		dbus_message_iter_close_container(&entry, &sub_variant);

		dbus_message_iter_close_container(&dict, &entry);
		NETWORK_LOG(NETWORK_HIGH, "DBus Message 2/2: %s %s\n", prop_method, dhcp_method);
	} else if (prof_info->ProfileInfo.Wlan.net_info.IpConfigType == NET_IP_CONFIG_TYPE_OFF) {
		dbus_message_iter_open_container(&dict, DBUS_TYPE_DICT_ENTRY, NULL, &entry);

		dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &prop_method);
		dbus_message_iter_open_container(&entry, DBUS_TYPE_VARIANT,
						DBUS_TYPE_STRING_AS_STRING, &sub_variant);
		dbus_message_iter_append_basic(&sub_variant, DBUS_TYPE_STRING, &off_method);
		dbus_message_iter_close_container(&entry, &sub_variant);

		dbus_message_iter_close_container(&dict, &entry);
		NETWORK_LOG(NETWORK_HIGH, "DBus Message 2/2: %s %s\n", prop_method, off_method);
	} else if (prof_info->ProfileInfo.Wlan.net_info.IpConfigType == NET_IP_CONFIG_TYPE_STATIC) {
		dbus_message_iter_open_container(&dict, DBUS_TYPE_DICT_ENTRY, NULL, &entry);

		dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &prop_method);
		dbus_message_iter_open_container(&entry, DBUS_TYPE_VARIANT,
						DBUS_TYPE_STRING_AS_STRING, &sub_variant);
		dbus_message_iter_append_basic(&sub_variant, DBUS_TYPE_STRING, &manual_method);
		dbus_message_iter_close_container(&entry, &sub_variant);

		dbus_message_iter_close_container(&dict, &entry);

		if (strlen(ipaddress) >= NETPM_IPV4_STR_LEN_MIN) {
			dbus_message_iter_open_container(&dict, DBUS_TYPE_DICT_ENTRY, NULL, &entry);

			dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &prop_address);
			dbus_message_iter_open_container(&entry, DBUS_TYPE_VARIANT,
							DBUS_TYPE_STRING_AS_STRING, &sub_variant);
			dbus_message_iter_append_basic(&sub_variant, DBUS_TYPE_STRING, &ipaddress);
			dbus_message_iter_close_container(&entry, &sub_variant);

			dbus_message_iter_close_container(&dict, &entry);
		}

		if (strlen(netmask) >= NETPM_IPV4_STR_LEN_MIN) {
			dbus_message_iter_open_container(&dict, DBUS_TYPE_DICT_ENTRY, NULL, &entry);

			dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &prop_netmask);
			dbus_message_iter_open_container(&entry, DBUS_TYPE_VARIANT,
							DBUS_TYPE_STRING_AS_STRING, &sub_variant);
			dbus_message_iter_append_basic(&sub_variant, DBUS_TYPE_STRING, &netmask);
			dbus_message_iter_close_container(&entry, &sub_variant);

			dbus_message_iter_close_container(&dict, &entry);
		}

		if (strlen(gateway) >= NETPM_IPV4_STR_LEN_MIN) {
			dbus_message_iter_open_container(&dict, DBUS_TYPE_DICT_ENTRY, NULL, &entry);

			dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &prop_gateway);
			dbus_message_iter_open_container(&entry, DBUS_TYPE_VARIANT,
							DBUS_TYPE_STRING_AS_STRING, &sub_variant);
			dbus_message_iter_append_basic(&sub_variant, DBUS_TYPE_STRING, &gateway);
			dbus_message_iter_close_container(&entry, &sub_variant);

			dbus_message_iter_close_container(&dict, &entry);
		}
		NETWORK_LOG(NETWORK_HIGH, "DBus Message 2/2: %s %s %s %s %s %s %s %s\n",
				prop_method, manual_method, prop_address, ipaddress,
				prop_netmask, netmask, prop_gateway, gateway);
	} else {
		NETWORK_LOG(NETWORK_ERROR, "Invalid argument\n");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_INVALID_PARAM;
	}

	dbus_message_iter_close_container(&variant, &dict);
	dbus_message_iter_close_container(&itr, &variant);

	dbus_error_init(&error);

	reply = dbus_connection_send_with_reply_and_block(conn,
			message, DBUS_REPLY_TIMEOUT,
			&error);

	if (reply == NULL) {
		if (dbus_error_is_set (&error) == TRUE) {
			NETWORK_LOG(NETWORK_ERROR,
				"dbus_connection_send_with_reply_and_block() failed, Error[%s: %s]\n",
				error.name, error.message);
			Error = __net_error_string_to_enum(error.name);
			dbus_error_free(&error);
			dbus_message_unref(message);
			__NETWORK_FUNC_EXIT__;
			return Error;
		}

		dbus_message_unref(message);
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_UNKNOWN;
	}

	dbus_message_unref(reply);
	dbus_message_unref(message);

	NETWORK_LOG(NETWORK_HIGH, "Successfully configured IPv4.Configuration\n");

	dbus_connection_unref(conn);

	__NETWORK_FUNC_EXIT__;
	return NET_ERR_NONE;
}

int _net_dbus_set_profile_dns(net_profile_info_t* prof_info, char* profile_name)
{
	__NETWORK_FUNC_ENTER__;

	net_err_t Error = NET_ERR_NONE;
	DBusError error;

	const char *prop_nameserver_configuration = "Nameservers.Configuration";
	char dns_buffer[NET_DNS_ADDR_MAX][NETPM_IPV4_STR_LEN_MAX+1];
	char *dns_address[NET_DNS_ADDR_MAX];

	DBusMessage *message = NULL;
	DBusMessage *reply = NULL;
	DBusMessageIter itr;
	DBusConnection* conn = NULL;
	int i = 0;

	if ((prof_info == NULL) || (profile_name == NULL) || (strlen(profile_name) == 0) ||
	    (prof_info->ProfileInfo.Wlan.net_info.DnsCount > NET_DNS_ADDR_MAX))	{
		NETWORK_LOG(NETWORK_ERROR, "Invalid parameter\n");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_INVALID_PARAM;
	}

	for (i = 0; i < prof_info->ProfileInfo.Wlan.net_info.DnsCount; i++) {
		dns_buffer[i][0] = '\0';
		dns_address[i] = NULL;

		if (prof_info->ProfileInfo.Wlan.net_info.DnsAddr[i].Data.Ipv4.s_addr != 0)
			g_strlcpy(dns_buffer[i],
					inet_ntoa(prof_info->ProfileInfo.Wlan.net_info.DnsAddr[i].Data.Ipv4),
					NETPM_IPV4_STR_LEN_MAX + 1);

		dns_address[i] = dns_buffer[i];
	}

	conn = dbus_bus_get(DBUS_BUS_SYSTEM, NULL);
	if (conn == NULL) {
		NETWORK_LOG(NETWORK_ERROR, "Failed to get a system bus\n");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_UNKNOWN;
	}

	if (prof_info->ProfileInfo.Wlan.net_info.IpConfigType == NET_IP_CONFIG_TYPE_STATIC) {
		message = dbus_message_new_method_call(CONNMAN_SERVICE,
				profile_name, CONNMAN_SERVICE_INTERFACE, "SetProperty");

		if (message == NULL) {
			NETWORK_LOG(NETWORK_ERROR,
					"dbus_message_new_method_call() failed\n");
			__NETWORK_FUNC_EXIT__;
			return NET_ERR_UNKNOWN;
		}

		dbus_message_iter_init_append(message, &itr);
		dbus_message_iter_append_basic(&itr, DBUS_TYPE_STRING, &prop_nameserver_configuration);

		DBusMessageIter value, array;
		dbus_message_iter_open_container(&itr, DBUS_TYPE_VARIANT,
				DBUS_TYPE_ARRAY_AS_STRING DBUS_TYPE_STRING_AS_STRING, &value);

		dbus_message_iter_open_container(&value, DBUS_TYPE_ARRAY,
				DBUS_TYPE_STRING_AS_STRING, &array);

		for (i = 0; i < prof_info->ProfileInfo.Wlan.net_info.DnsCount; i++) {
			dbus_message_iter_append_basic(&array, DBUS_TYPE_STRING, &(dns_address[i]));
		}

		dbus_message_iter_close_container(&value, &array);
		dbus_message_iter_close_container(&itr, &value);

		dbus_error_init(&error);

		reply = dbus_connection_send_with_reply_and_block(conn,
				message, DBUS_REPLY_TIMEOUT,
				&error);

		if (reply == NULL) {
			if (dbus_error_is_set (&error) == TRUE) {
				NETWORK_LOG(NETWORK_ERROR,
					"dbus_connection_send_with_reply_and_block() failed, Error[%s: %s]\n",
					error.name, error.message);
				Error = __net_error_string_to_enum(error.name);
				dbus_error_free(&error);
				dbus_message_unref(message);
				__NETWORK_FUNC_EXIT__;
				return Error;
			}
			dbus_message_unref(message);
			__NETWORK_FUNC_EXIT__;
			return NET_ERR_UNKNOWN;
		}
		dbus_message_unref(reply);
		dbus_message_unref(message);
		NETWORK_LOG(NETWORK_HIGH, "Successfully configured Nameservers.Configuration\n");
	}

	__NETWORK_FUNC_EXIT__;
	return NET_ERR_NONE;
}

int _net_dbus_set_proxy(net_profile_info_t* prof_info, char* profile_name)
{
	__NETWORK_FUNC_ENTER__;

	net_err_t Error = NET_ERR_NONE;
	DBusError error;

	const char *direct_method = "direct";
	const char *auto_method = "auto";
	const char *manual_method = "manual";

	const char *prop_proxy_configuration = "Proxy.Configuration";
	const char *prop_method = "Method";
	const char *prop_url = "URL";
	const char *prop_servers = "Servers";

	char proxy_buffer[NET_PROXY_LEN_MAX+1] = "";
	char *proxy_address = proxy_buffer;

	DBusMessage *message = NULL;
	DBusMessage *reply = NULL;
	DBusMessageIter itr, variant, dict, entry, sub_variant, str_array;
	DBusConnection* conn = NULL;

	if ((prof_info == NULL) || (profile_name == NULL) || (strlen(profile_name) == 0)) {
		NETWORK_LOG(NETWORK_ERROR, "Invalid argument\n");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_INVALID_PARAM;
	}

	g_strlcpy(proxy_buffer,
			prof_info->ProfileInfo.Wlan.net_info.ProxyAddr, NET_PROXY_LEN_MAX+1);

	NETWORK_LOG(NETWORK_HIGH, "Method : %d, proxy address : %s\n",
			prof_info->ProfileInfo.Wlan.net_info.ProxyMethod, proxy_address);

	conn = dbus_bus_get(DBUS_BUS_SYSTEM, NULL);
	if (conn == NULL) {
		NETWORK_LOG(NETWORK_ERROR, "Failed to get a system bus\n");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_UNKNOWN;
	}

	/** Send proxy method, url, servers configuration */
	message = dbus_message_new_method_call(CONNMAN_SERVICE, profile_name,
			CONNMAN_SERVICE_INTERFACE, "SetProperty");
	if (message == NULL) {
		NETWORK_LOG(NETWORK_ERROR, "dbus_message_new_method_call() failed\n");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_UNKNOWN;
	}

	dbus_message_iter_init_append(message, &itr);
	dbus_message_iter_append_basic(&itr, DBUS_TYPE_STRING, &prop_proxy_configuration);

	dbus_message_iter_open_container
		(&itr, DBUS_TYPE_VARIANT,
		 (DBUS_TYPE_ARRAY_AS_STRING
		  DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
		  DBUS_TYPE_STRING_AS_STRING
		  DBUS_TYPE_VARIANT_AS_STRING
		  DBUS_DICT_ENTRY_END_CHAR_AS_STRING),
		 &variant);
	dbus_message_iter_open_container
		(&variant, DBUS_TYPE_ARRAY,
		 (DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
		  DBUS_TYPE_STRING_AS_STRING
		  DBUS_TYPE_VARIANT_AS_STRING
		  DBUS_DICT_ENTRY_END_CHAR_AS_STRING),
		 &dict);

	dbus_message_iter_open_container(&dict, DBUS_TYPE_DICT_ENTRY, NULL, &entry);
	dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &prop_method);
	
	dbus_message_iter_open_container(&entry, DBUS_TYPE_VARIANT,
			DBUS_TYPE_STRING_AS_STRING, &sub_variant);

	switch (prof_info->ProfileInfo.Wlan.net_info.ProxyMethod) {
	case NET_PROXY_TYPE_AUTO:
		dbus_message_iter_append_basic(&sub_variant, DBUS_TYPE_STRING, &auto_method);
		break;
	case NET_PROXY_TYPE_MANUAL:
		dbus_message_iter_append_basic(&sub_variant, DBUS_TYPE_STRING, &manual_method);
		break;
	default:
		dbus_message_iter_append_basic(&sub_variant, DBUS_TYPE_STRING, &direct_method);
		break;
	}

	dbus_message_iter_close_container(&entry, &sub_variant);
	dbus_message_iter_close_container(&dict, &entry);

	if (prof_info->ProfileInfo.Wlan.net_info.ProxyMethod == NET_PROXY_TYPE_AUTO &&
	    proxy_address[0] != '\0') {
		dbus_message_iter_open_container(&dict, DBUS_TYPE_DICT_ENTRY, NULL, &entry);
		dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &prop_url);
		
		dbus_message_iter_open_container(&entry, DBUS_TYPE_VARIANT,
				DBUS_TYPE_STRING_AS_STRING, &sub_variant);
		dbus_message_iter_append_basic(&sub_variant, DBUS_TYPE_STRING, &proxy_address);
		
		dbus_message_iter_close_container(&entry, &sub_variant);
		dbus_message_iter_close_container(&dict, &entry);
	}

	if (prof_info->ProfileInfo.Wlan.net_info.ProxyMethod == NET_PROXY_TYPE_MANUAL &&
	    proxy_address[0] != '\0') {
		dbus_message_iter_open_container(&dict, DBUS_TYPE_DICT_ENTRY, NULL, &entry);
		dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &prop_servers);

		dbus_message_iter_open_container(&entry, DBUS_TYPE_VARIANT,
				DBUS_TYPE_ARRAY_AS_STRING DBUS_TYPE_STRING_AS_STRING, &sub_variant);

		dbus_message_iter_open_container(&sub_variant, DBUS_TYPE_ARRAY,
				DBUS_TYPE_STRING_AS_STRING, &str_array);
		dbus_message_iter_append_basic(&str_array, DBUS_TYPE_STRING, &proxy_address);

		dbus_message_iter_close_container(&sub_variant, &str_array);
		dbus_message_iter_close_container(&entry, &sub_variant);
		dbus_message_iter_close_container(&dict, &entry);
	}

	dbus_message_iter_close_container(&variant, &dict);
	dbus_message_iter_close_container(&itr, &variant);

	dbus_error_init(&error);

	reply = dbus_connection_send_with_reply_and_block(conn,
			message, DBUS_REPLY_TIMEOUT,
			&error);

	if (reply == NULL) {
		if (dbus_error_is_set(&error) == TRUE) {
			NETWORK_LOG(NETWORK_ERROR,
				"dbus_connection_send_with_reply_and_block() failed, Error[%s: %s]\n",
				error.name, error.message);
			Error = __net_error_string_to_enum(error.name);
			dbus_error_free(&error);
			dbus_message_unref(message);
			__NETWORK_FUNC_EXIT__;
			return Error;
		}

		dbus_message_unref(message);
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_UNKNOWN;
	}

	dbus_message_unref(reply);
	dbus_message_unref(message);

	NETWORK_LOG(NETWORK_HIGH, "Successfully configured Proxy.Configuration\n");

	dbus_connection_unref(conn);

	__NETWORK_FUNC_EXIT__;
	return NET_ERR_NONE;
}


int _net_dbus_add_pdp_profile(net_profile_info_t *prof_info)
{
	__NETWORK_FUNC_ENTER__;

	net_err_t Error = NET_ERR_NONE;
	DBusError error;
	const char *service_type = "svc_ctg_id";
	const char *home_url = "home_url";
	const char *proxy_addr = "proxy_addr";
	const char *auth_pwd = "auth_pwd";
	const char *auth_type = "auth_type";
	const char *auth_id = "auth_id";
	const char *apn = "apn";
	const char *keyword = "keyword";

	char buff_svc_type[10] = "";
	char buff_auth_type[10] = "";
	char *temp_ptr = NULL;

	DBusMessage *message = NULL;
	DBusMessage *reply = NULL;
	DBusMessageIter iter, dict, entry;
	DBusConnection* conn = NULL;

	if (prof_info == NULL) {
		NETWORK_LOG(NETWORK_ERROR, "Invalid argument\n");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_INVALID_PARAM;
	}

	conn = dbus_bus_get(DBUS_BUS_SYSTEM, NULL);
	if (conn == NULL) {
		NETWORK_LOG(NETWORK_ERROR, "Failed to get a system bus\n");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_UNKNOWN;
	}

	/** Create message */
	message = dbus_message_new_method_call(TELEPHONY_SERVICE,
			TELEPHONY_MASTER_PATH, TELEPHONY_MASTER_INTERFACE, "AddProfile");
	if (message == NULL) {
		NETWORK_LOG(NETWORK_ERROR, "dbus_message_new_method_call() failed\n");
		dbus_connection_unref(conn);
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_UNKNOWN;
	}

	NETWORK_LOG(NETWORK_HIGH, "DBus Message 1/2 : %s %s %s %s\n", TELEPHONY_SERVICE,
			TELEPHONY_MASTER_PATH, TELEPHONY_MASTER_INTERFACE, ".AddProfile");

	dbus_message_iter_init_append(message, &iter);

	dbus_message_iter_open_container
		(&iter, DBUS_TYPE_ARRAY,
		 (DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
		  DBUS_TYPE_STRING_AS_STRING
		  DBUS_TYPE_STRING_AS_STRING
		  DBUS_DICT_ENTRY_END_CHAR_AS_STRING),
		 &dict);

	g_snprintf(buff_svc_type, 10, "%d", prof_info->ProfileInfo.Pdp.ServiceType);
	temp_ptr = buff_svc_type;

	NETWORK_LOG(NETWORK_HIGH, "DBus Message 2/2 : %s : %s\n",
			service_type, temp_ptr);

	dbus_message_iter_open_container(&dict, DBUS_TYPE_DICT_ENTRY, NULL, &entry);
	dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &service_type);
	dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &temp_ptr);
	dbus_message_iter_close_container(&dict, &entry);

	if (strlen(prof_info->ProfileInfo.Pdp.HomeURL) > 0) {
		temp_ptr = prof_info->ProfileInfo.Pdp.HomeURL;

		NETWORK_LOG(NETWORK_HIGH, "DBus Message 2/2 : %s : %s\n",
				home_url, temp_ptr);

		dbus_message_iter_open_container(&dict, DBUS_TYPE_DICT_ENTRY, NULL, &entry);
		dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &home_url);
		dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &temp_ptr);
		dbus_message_iter_close_container(&dict, &entry);
	}

	if (strlen(prof_info->ProfileInfo.Pdp.net_info.ProxyAddr) > 0) {
		temp_ptr = prof_info->ProfileInfo.Pdp.net_info.ProxyAddr;

		NETWORK_LOG(NETWORK_HIGH, "DBus Message 2/2 : %s : %s\n",
				proxy_addr, temp_ptr);

		dbus_message_iter_open_container(&dict, DBUS_TYPE_DICT_ENTRY, NULL, &entry);
		dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &proxy_addr);
		dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &temp_ptr);
		dbus_message_iter_close_container(&dict, &entry);
	}

	if (strlen(prof_info->ProfileInfo.Pdp.AuthInfo.Password) > 0) {
		temp_ptr = prof_info->ProfileInfo.Pdp.AuthInfo.Password;

		NETWORK_LOG(NETWORK_HIGH, "DBus Message 2/2 : %s : %s\n",
				auth_pwd, temp_ptr);

		dbus_message_iter_open_container(&dict, DBUS_TYPE_DICT_ENTRY, NULL, &entry);
		dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &auth_pwd);
		dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &temp_ptr);
		dbus_message_iter_close_container(&dict, &entry);
	}

	if (strlen(prof_info->ProfileInfo.Pdp.AuthInfo.UserName) > 0) {
		temp_ptr = prof_info->ProfileInfo.Pdp.AuthInfo.UserName;

		NETWORK_LOG(NETWORK_HIGH, "DBus Message 2/2 : %s : %s\n",
				auth_id, temp_ptr);

		dbus_message_iter_open_container(&dict, DBUS_TYPE_DICT_ENTRY, NULL, &entry);
		dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &auth_id);
		dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &temp_ptr);
		dbus_message_iter_close_container(&dict, &entry);
	}

	if (prof_info->ProfileInfo.Pdp.AuthInfo.AuthType >= NET_PDP_AUTH_NONE &&
			prof_info->ProfileInfo.Pdp.AuthInfo.AuthType <= NET_PDP_AUTH_CHAP) {
		g_snprintf(buff_auth_type, 10, "%d",
				prof_info->ProfileInfo.Pdp.AuthInfo.AuthType);

		temp_ptr = buff_auth_type;

		NETWORK_LOG(NETWORK_HIGH, "DBus Message 2/2 : %s : %s\n",
				auth_type, temp_ptr);

		dbus_message_iter_open_container(&dict, DBUS_TYPE_DICT_ENTRY, NULL, &entry);
		dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &auth_type);
		dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &temp_ptr);
		dbus_message_iter_close_container(&dict, &entry);
	}

	if (strlen(prof_info->ProfileInfo.Pdp.Apn) > 0) {
		temp_ptr = prof_info->ProfileInfo.Pdp.Apn;

		NETWORK_LOG(NETWORK_HIGH, "DBus Message 2/2 : %s : %s\n",
				apn, temp_ptr);

		dbus_message_iter_open_container(&dict, DBUS_TYPE_DICT_ENTRY, NULL, &entry);
		dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &apn);
		dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &temp_ptr);
		dbus_message_iter_close_container(&dict, &entry);
	}

	if (strlen(prof_info->ProfileInfo.Pdp.Keyword) > 0) {
		temp_ptr = prof_info->ProfileInfo.Pdp.Keyword;

		NETWORK_LOG(NETWORK_HIGH, "DBus Message 2/2 : %s : %s\n",
				keyword, temp_ptr);

		dbus_message_iter_open_container(&dict, DBUS_TYPE_DICT_ENTRY, NULL, &entry);
		dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &keyword);
		dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &temp_ptr);
		dbus_message_iter_close_container(&dict, &entry);
	}

	dbus_message_iter_close_container(&iter, &dict);
	dbus_error_init(&error);

	/** Send message */
	reply = dbus_connection_send_with_reply_and_block(conn,
			message, DBUS_REPLY_TIMEOUT,
			&error);

	/** Check Error */
	if (reply == NULL) {
		if (dbus_error_is_set (&error) == TRUE) {
			NETWORK_LOG(NETWORK_ERROR,
				"dbus_connection_send_with_reply_and_block() failed, Error[%s: %s]\n",
				error.name, error.message);
			Error = __net_error_string_to_enum(error.name);
			dbus_error_free(&error);
			dbus_message_unref(message);
			__NETWORK_FUNC_EXIT__;
			return Error;
		}

		dbus_message_unref(message);
		dbus_connection_unref(conn);
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_UNKNOWN;
	} else
		NETWORK_LOG(NETWORK_HIGH, "Successfully requested : Add PDP profile\n");

	/** Check Reply */
	DBusMessageIter iter2;
	int add_result = 0;

	dbus_message_iter_init(reply, &iter2);
	if (dbus_message_iter_get_arg_type(&iter2) == DBUS_TYPE_BOOLEAN) {
		dbus_message_iter_get_basic(&iter2, &add_result);
		NETWORK_LOG(NETWORK_HIGH, "Profile add result : %d\n", add_result);
	}

	if (add_result)
		Error = NET_ERR_NONE;
	else
		Error = NET_ERR_UNKNOWN;

	dbus_message_unref(reply);
	dbus_message_unref(message);
	dbus_connection_unref(conn);

	__NETWORK_FUNC_EXIT__;
	return Error;
}


int _net_dbus_modify_pdp_profile(net_profile_info_t *prof_info, const char *profile_name)
{
	__NETWORK_FUNC_ENTER__;

	net_err_t Error = NET_ERR_NONE;

	DBusError error;
	const char *service_type = "svc_ctg_id";
	const char *home_url = "home_url";
	const char *proxy_addr = "proxy_addr";
	const char *auth_pwd = "auth_pwd";
	const char *auth_type = "auth_type";
	const char *auth_id = "auth_id";
	const char *apn = "apn";
	const char *keyword = "keyword";
	const char *default_conn = "default_internet_conn";
	const char *hidden = "hidden";
	const char *editable = "editable";

	char buff_svc_type[10] = "";
	char buff_auth_type[10] = "";
	char *temp_ptr = NULL;

	DBusMessage *message = NULL;
	DBusMessage *reply = NULL;
	DBusMessageIter iter, dict, entry;
	DBusConnection* conn = NULL;

	if ((prof_info == NULL) || (profile_name == NULL)) {
		NETWORK_LOG(NETWORK_ERROR, "Invalid argument\n");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_INVALID_PARAM;
	}

	conn = dbus_bus_get(DBUS_BUS_SYSTEM, NULL);
	if (conn == NULL) {
		NETWORK_LOG(NETWORK_ERROR, "Failed to get a system bus\n");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_UNKNOWN;
	}

	/** Create message */
	message = dbus_message_new_method_call(TELEPHONY_SERVICE,
			profile_name, TELEPHONY_PROFILE_INTERFACE, "ModifyProfile");
	if (message == NULL) {
		NETWORK_LOG(NETWORK_ERROR, "dbus_message_new_method_call() failed\n");
		dbus_connection_unref(conn);
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_UNKNOWN;
	}

	NETWORK_LOG(NETWORK_HIGH, "DBus Message 1/2 : %s %s %s %s\n", TELEPHONY_SERVICE,
			profile_name, TELEPHONY_PROFILE_INTERFACE, ".ModifyProfile");

	dbus_message_iter_init_append(message, &iter);

	dbus_message_iter_open_container
		(&iter, DBUS_TYPE_ARRAY,
		 (DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
		  DBUS_TYPE_STRING_AS_STRING
		  DBUS_TYPE_STRING_AS_STRING
		  DBUS_DICT_ENTRY_END_CHAR_AS_STRING),
		 &dict);

	g_snprintf(buff_svc_type, 10, "%d", prof_info->ProfileInfo.Pdp.ServiceType);
	temp_ptr = buff_svc_type;

	NETWORK_LOG(NETWORK_HIGH, "DBus Message 2/2 : %s : %s\n",
			service_type, temp_ptr);

	dbus_message_iter_open_container(&dict, DBUS_TYPE_DICT_ENTRY, NULL, &entry);
	dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &service_type);
	dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &temp_ptr);
	dbus_message_iter_close_container(&dict, &entry);

	if (strlen(prof_info->ProfileInfo.Pdp.HomeURL) > 0) {
		temp_ptr = prof_info->ProfileInfo.Pdp.HomeURL;

		NETWORK_LOG(NETWORK_HIGH, "DBus Message 2/2 : %s : %s\n",
				home_url, temp_ptr);

		dbus_message_iter_open_container(&dict, DBUS_TYPE_DICT_ENTRY, NULL, &entry);
		dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &home_url);
		dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &temp_ptr);
		dbus_message_iter_close_container(&dict, &entry);
	}

	if (strlen(prof_info->ProfileInfo.Pdp.net_info.ProxyAddr) > 0) {
		temp_ptr = prof_info->ProfileInfo.Pdp.net_info.ProxyAddr;

		NETWORK_LOG(NETWORK_HIGH, "DBus Message 2/2 : %s : %s\n",
				proxy_addr, temp_ptr);

		dbus_message_iter_open_container(&dict, DBUS_TYPE_DICT_ENTRY, NULL, &entry);
		dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &proxy_addr);
		dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &temp_ptr);
		dbus_message_iter_close_container(&dict, &entry);
	}

	if (strlen(prof_info->ProfileInfo.Pdp.AuthInfo.Password) > 0) {
		temp_ptr = prof_info->ProfileInfo.Pdp.AuthInfo.Password;

		NETWORK_LOG(NETWORK_HIGH, "DBus Message 2/2 : %s : %s\n",
				auth_pwd, temp_ptr);

		dbus_message_iter_open_container(&dict, DBUS_TYPE_DICT_ENTRY, NULL, &entry);
		dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &auth_pwd);
		dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &temp_ptr);
		dbus_message_iter_close_container(&dict, &entry);
	}

	if (strlen(prof_info->ProfileInfo.Pdp.AuthInfo.UserName) > 0) {
		temp_ptr = prof_info->ProfileInfo.Pdp.AuthInfo.UserName;

		NETWORK_LOG(NETWORK_HIGH, "DBus Message 2/2 : %s : %s\n",
				auth_id, temp_ptr);

		dbus_message_iter_open_container(&dict, DBUS_TYPE_DICT_ENTRY, NULL, &entry);
		dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &auth_id);
		dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &temp_ptr);
		dbus_message_iter_close_container(&dict, &entry);
	}

	if (prof_info->ProfileInfo.Pdp.AuthInfo.AuthType >= NET_PDP_AUTH_NONE &&
	    prof_info->ProfileInfo.Pdp.AuthInfo.AuthType <= NET_PDP_AUTH_CHAP) {
		g_snprintf(buff_auth_type, 10, "%d",
				prof_info->ProfileInfo.Pdp.AuthInfo.AuthType);
		temp_ptr = buff_auth_type;

		NETWORK_LOG(NETWORK_HIGH, "DBus Message 2/2 : %s : %s\n",
				auth_type, temp_ptr);

		dbus_message_iter_open_container(&dict, DBUS_TYPE_DICT_ENTRY, NULL, &entry);
		dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &auth_type);
		dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &temp_ptr);
		dbus_message_iter_close_container(&dict, &entry);
	}

	if (strlen(prof_info->ProfileInfo.Pdp.Apn) > 0) {
		temp_ptr = prof_info->ProfileInfo.Pdp.Apn;

		NETWORK_LOG(NETWORK_HIGH, "DBus Message 2/2 : %s : %s\n",
				apn, temp_ptr);

		dbus_message_iter_open_container(&dict, DBUS_TYPE_DICT_ENTRY, NULL, &entry);
		dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &apn);
		dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &temp_ptr);
		dbus_message_iter_close_container(&dict, &entry);
	}

	if (strlen(prof_info->ProfileInfo.Pdp.Keyword) > 0) {
		temp_ptr = prof_info->ProfileInfo.Pdp.Keyword;

		NETWORK_LOG(NETWORK_HIGH, "DBus Message 2/2 : %s : %s\n",
				keyword, temp_ptr);

		dbus_message_iter_open_container(&dict, DBUS_TYPE_DICT_ENTRY, NULL, &entry);
		dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &keyword);
		dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &temp_ptr);
		dbus_message_iter_close_container(&dict, &entry);
	}

	if (prof_info->ProfileInfo.Pdp.Hidden)
		temp_ptr = "TRUE";
	else
		temp_ptr = "FALSE";

	NETWORK_LOG(NETWORK_HIGH, "DBus Message 2/2 : %s : %s\n",
			hidden, temp_ptr);

	dbus_message_iter_open_container(&dict, DBUS_TYPE_DICT_ENTRY, NULL, &entry);
	dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &hidden);
	dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &temp_ptr);
	dbus_message_iter_close_container(&dict, &entry);

	if (prof_info->ProfileInfo.Pdp.Editable)
		temp_ptr = "TRUE";
	else
		temp_ptr = "FALSE";

	NETWORK_LOG(NETWORK_HIGH, "DBus Message 2/2 : %s : %s\n",
			editable, temp_ptr);

	dbus_message_iter_open_container(&dict, DBUS_TYPE_DICT_ENTRY, NULL, &entry);
	dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &editable);
	dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &temp_ptr);
	dbus_message_iter_close_container(&dict, &entry);

	if (prof_info->ProfileInfo.Pdp.DefaultConn)
		temp_ptr = "TRUE";
	else
		temp_ptr = "FALSE";

	NETWORK_LOG(NETWORK_HIGH, "DBus Message 2/2 : %s : %s\n",
			default_conn, temp_ptr);

	dbus_message_iter_open_container(&dict, DBUS_TYPE_DICT_ENTRY, NULL, &entry);
	dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &default_conn);
	dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &temp_ptr);
	dbus_message_iter_close_container(&dict, &entry);

	dbus_message_iter_close_container(&iter, &dict);
	dbus_error_init(&error);

	/** Send message */
	reply = dbus_connection_send_with_reply_and_block(conn,
			message, DBUS_REPLY_TIMEOUT,
			&error);

	/** Check Error */
	if (reply == NULL) {
		if (dbus_error_is_set (&error) == TRUE) {
			NETWORK_LOG(NETWORK_ERROR,
				"dbus_connection_send_with_reply_and_block() failed, Error[%s: %s]\n",
				error.name, error.message);
			Error = __net_error_string_to_enum(error.name);
			dbus_error_free(&error);
			dbus_message_unref(message);
			__NETWORK_FUNC_EXIT__;
			return Error;
		}

		dbus_message_unref(message);
		dbus_connection_unref(conn);
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_UNKNOWN;
	} else
		NETWORK_LOG(NETWORK_HIGH, "Successfully requested : Modify PDP profile\n");

	/** Check Reply */
	DBusMessageIter iter2;
	int add_result = 0;

	dbus_message_iter_init(reply, &iter2);
	if (dbus_message_iter_get_arg_type(&iter2) == DBUS_TYPE_BOOLEAN) {
		dbus_message_iter_get_basic(&iter2, &add_result);
		NETWORK_LOG(NETWORK_HIGH, "Profile modify result : %d\n", add_result);
	}

	if (add_result)
		Error = NET_ERR_NONE;
	else
		Error = NET_ERR_UNKNOWN;

	dbus_message_unref(reply);
	dbus_message_unref(message);
	dbus_connection_unref(conn);

	__NETWORK_FUNC_EXIT__;
	return Error;
}

int _net_dbus_load_wifi_driver(void)
{
	__NETWORK_FUNC_ENTER__;

	net_err_t Error = NET_ERR_NONE;

	Error = _net_invoke_dbus_method_nonblock(NETCONFIG_SERVICE, NETCONFIG_WIFI_PATH,
			NETCONFIG_WIFI_INTERFACE, "LoadDriver", __net_wifi_power_reply);

	__NETWORK_FUNC_EXIT__;
	return Error;
}

int _net_dbus_remove_wifi_driver(void)
{
	__NETWORK_FUNC_ENTER__;

	net_err_t Error = NET_ERR_NONE;

	Error = _net_invoke_dbus_method_nonblock(NETCONFIG_SERVICE, NETCONFIG_WIFI_PATH,
			NETCONFIG_WIFI_INTERFACE, "RemoveDriver", __net_wifi_power_reply);

	__NETWORK_FUNC_EXIT__;
	return Error;
}

dbus_bool_t _net_dbus_is_pending_call_used(void)
{
	return network_dbus_pending_call_data.is_used;
}

void _net_dbus_set_pending_call_used(dbus_bool_t used)
{
	network_dbus_pending_call_data.is_used = used;
}

DBusPendingCall *_net_dbus_get_pending_call(void)
{
	return network_dbus_pending_call_data.pcall;
}

void _net_dbus_set_pending_call(DBusPendingCall *call)
{
	network_dbus_pending_call_data.pcall = call;
}

void _net_dbus_clear_pending_call(void)
{
	if (_net_dbus_is_pending_call_used()) {
		dbus_pending_call_cancel(_net_dbus_get_pending_call());

		_net_dbus_set_pending_call(NULL);
		_net_dbus_set_pending_call_used(FALSE);
	}
}

gboolean __net_dbus_abort_open_request(const char *profile_name)
{
	__NETWORK_FUNC_ENTER__;

	net_event_info_t event_data;
	char event_string[64];

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
		__NETWORK_FUNC_EXIT__;
		return FALSE;
	}

	g_strlcpy(event_data.ProfileName, profile_name, NET_PROFILE_NAME_LEN_MAX+1);
	event_data.Error = NET_ERR_OPERATION_ABORTED;
	event_data.Datalength = 0;
	event_data.Data = NULL;

	NETWORK_LOG(NETWORK_LOW, "%s, Error : %d\n", event_string, event_data.Error);
	_net_client_callback(&event_data);

	__NETWORK_FUNC_EXIT__;
	return TRUE;
}

int _net_dbus_specific_scan_request(const char *ssid)
{
	__NETWORK_FUNC_ENTER__;

	DBusMessage* message = NULL;
	DBusConnection* conn = NULL;
	DBusPendingCall *call = NULL;
	dbus_bool_t result = FALSE;

	conn = dbus_bus_get(DBUS_BUS_SYSTEM, NULL);
	if (conn == NULL) {
		NETWORK_LOG(NETWORK_ERROR, "Failed to get a system bus\n");

		__NETWORK_FUNC_EXIT__;
		return NET_ERR_UNKNOWN;
	}

	message = dbus_message_new_method_call(NETCONFIG_SERVICE,
			NETCONFIG_WIFI_PATH, NETCONFIG_WIFI_INTERFACE,
			"RequestSpecificScan");
	if (message == NULL) {
		NETWORK_LOG(NETWORK_ERROR, "dbus_message_new_method_call() failed\n");

		dbus_connection_unref(conn);

		__NETWORK_FUNC_EXIT__;
		return NET_ERR_UNKNOWN;
	}

	dbus_message_append_args(message, DBUS_TYPE_STRING, &ssid, NULL);

	result = dbus_connection_send_with_reply(conn, message, &call,
			6 * DBUS_REPLY_TIMEOUT);
	if (result == FALSE || call == NULL) {
		NETWORK_LOG(NETWORK_ERROR, "dbus_connection_send_with_reply() failed\n");

		dbus_message_unref(message);
		dbus_connection_unref(conn);

		__NETWORK_FUNC_EXIT__;
		return NET_ERR_UNKNOWN;
	}

	NETWORK_LOG(NETWORK_HIGH, "Successfully configured\n");

	dbus_pending_call_set_notify(call, __net_specific_scan_wifi_reply, NULL, NULL);
	network_dbus_pending_call_data.pcall = call;
	network_dbus_pending_call_data.is_used = TRUE;

	dbus_message_unref(message);
	dbus_connection_unref(conn);

	__NETWORK_FUNC_EXIT__;
	return NET_ERR_NONE;
}
