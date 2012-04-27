/*
 *
 * Network Client Library
 *
 * Copyright (c) 2012 Samsung Electronics Co., Ltd All Rights Reserved.
 *
 * PROPRIETARY/CONFIDENTIAL
 * This software is the confidential and proprietary information of
 * SAMSUNG ELECTRONICS ("Confidential Information").
 * You shall not disclose such Confidential Information and shall
 * use it only in accordance with the terms of the license agreement
 * you entered into with SAMSUNG ELECTRONICS.
 * SAMSUNG make no representations or warranties about the suitability
 * of the software, either express or implied, including but not limited
 * to the implied warranties of merchantability, fitness for a particular
 * purpose, or non-infringement. SAMSUNG shall not be liable for
 * any damages suffered by licensee as a result of using, modifying or
 * distributing this software or its derivatives.
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
#include <dbus/dbus-glib.h>
#include <dbus/dbus.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <vconf.h>

/*****************************************************************************
 * 	Platform headers
 *****************************************************************************/

#include "network-internal.h"
#include "network-dbus-request.h"

/*****************************************************************************
 * 	Macros and Typedefs
 *****************************************************************************/

#define DBUS_REPLY_TIMEOUT (120 * 1000)

/*****************************************************************************
 * 	Local Functions Declaration
 *****************************************************************************/

static int __net_error_string_to_enum(const char* error);
static int __net_netconfig_error_string_to_enum(const char* error);
static int _net_get_error_from_message(DBusMessage *message);
static int _net_get_error_from_netconfig_message(DBusMessage *message);
static void __net_open_connection_reply(DBusPendingCall *call, void *user_data);
static void __net_close_connection_reply(DBusPendingCall *call, void *user_data);
static void __net_wifi_power_reply(DBusPendingCall *call, void *user_data);

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
	return NET_ERR_UNKNOWN;
}

static int _net_get_error_from_message(DBusMessage *message)
{
	__NETWORK_FUNC_ENTER__;

	int MessageType = 0;

	MessageType = dbus_message_get_type(message);

	if (MessageType == DBUS_MESSAGE_TYPE_ERROR) {
		const char* ptr = dbus_message_get_error_name(message);
		NETWORK_LOG(NETWORK_ERROR, "Error!!! Error message received [%s]\n", ptr);
		__NETWORK_FUNC_EXIT__;
		return __net_error_string_to_enum(ptr);
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
		const char* ptr = dbus_message_get_error_name(message);
		const char* err_msg = _net_get_string(message);
		NETWORK_LOG(NETWORK_ERROR,
				"Error!!! Error message received [%s] [%s]\n", ptr, err_msg);
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

	net_event_info_t event_data = {0,};
	net_profile_info_t prof_info;
	network_request_table_t *open_info = &request_table[NETWORK_REQUEST_TYPE_OPEN_CONNECTION];
	network_request_table_t *wps_info = &request_table[NETWORK_REQUEST_TYPE_ENROLL_WPS];

	DBusMessage *reply = dbus_pending_call_steal_reply(call);
	net_err_t Error = _net_get_error_from_message(reply);

	if (Error == NET_ERR_NONE)
		goto done;

	NETWORK_LOG(NETWORK_ERROR,
		"Error!!! Connection open failed. Error code : [%d]\n", Error);

	if (open_info->flag == TRUE) {
		net_device_t device_type = _net_get_tech_type_from_path(open_info->ProfileName);

		if (Error == NET_ERR_IN_PROGRESS &&
		    device_type == NET_DEVICE_CELLULAR)
			goto done;

		snprintf(event_data.ProfileName,
			NET_PROFILE_NAME_LEN_MAX + 1, "%s",
			open_info->ProfileName);

		memset(open_info, 0, sizeof(network_request_table_t));

		event_data.Error = Error;

		if (Error == NET_ERR_ACTIVE_CONNECTION_EXISTS) {
			Error = net_get_profile_info(event_data.ProfileName, &prof_info);

			if (device_type == NET_DEVICE_CELLULAR)
				event_data.Error = NET_ERR_NONE;

			if (Error != NET_ERR_NONE) {
				NETWORK_LOG(NETWORK_ERROR,
					"Error!!! net_get_profile_info() failed [%s]\n",
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
		_net_client_callback(&event_data);
	} else if (wps_info->flag == TRUE) {

		snprintf(event_data.ProfileName,
			NET_PROFILE_NAME_LEN_MAX + 1, "%s",
			wps_info->ProfileName);

		memset(wps_info, 0, sizeof(network_request_table_t));

		event_data.Error = Error;

		if (Error == NET_ERR_ACTIVE_CONNECTION_EXISTS) {
			Error = net_get_profile_info(event_data.ProfileName, &prof_info);
			if (Error != NET_ERR_NONE) {
				NETWORK_LOG(NETWORK_ERROR,
					"Error!!! net_get_profile_info() failed [%s]\n",
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
		_net_client_callback(&event_data);
	}

done:
	dbus_message_unref(reply);
	dbus_pending_call_unref(call);

	network_dbus_pending_call_data.is_used = FALSE;
	network_dbus_pending_call_data.pcall = NULL;

	__NETWORK_FUNC_EXIT__;
}

static void __net_close_connection_reply(DBusPendingCall *call, void *user_data)
{
	__NETWORK_FUNC_ENTER__;

	NETWORK_LOG(NETWORK_LOW, "__net_close_connection_reply() called\n");

	net_event_info_t event_data = {0,};
	network_request_table_t *close_info = &request_table[NETWORK_REQUEST_TYPE_CLOSE_CONNECTION];

	DBusMessage *reply = dbus_pending_call_steal_reply(call);
	net_err_t Error = _net_get_error_from_message(reply);

	if (Error == NET_ERR_NONE)
		goto done;

	NETWORK_LOG(NETWORK_ERROR,
		"Error!!! Connection close failed. Error code : [%d]\n", Error);

	if (close_info->flag == TRUE) {
		net_device_t device_type = _net_get_tech_type_from_path(close_info->ProfileName);

		if (Error == NET_ERR_ACTIVE_CONNECTION_EXISTS &&
		    device_type == NET_DEVICE_CELLULAR)
			Error = NET_ERR_NONE;

		snprintf(event_data.ProfileName,
			NET_PROFILE_NAME_LEN_MAX + 1, "%s",
			close_info->ProfileName);

		memset(close_info, 0, sizeof(network_request_table_t));

		event_data.Error = Error;
		event_data.Datalength = 0;
		event_data.Data = NULL;
		event_data.Event = NET_EVENT_CLOSE_RSP;
		NETWORK_LOG(NETWORK_LOW, "Sending NET_EVENT_CLOSE_RSP Error = %s\n",
				_net_print_error(event_data.Error));
		_net_client_callback(&event_data);
	}

done:
	dbus_message_unref(reply);
	dbus_pending_call_unref(call);

	network_dbus_pending_call_data.is_used = FALSE;
	network_dbus_pending_call_data.pcall = NULL;

	__NETWORK_FUNC_EXIT__;
}

static void __net_wifi_power_reply(DBusPendingCall *call, void *user_data)
{
	__NETWORK_FUNC_ENTER__;

	DBusMessage *reply = dbus_pending_call_steal_reply(call);
	net_err_t Error = _net_get_error_from_netconfig_message(reply);

	if (Error == NET_ERR_NONE)
		goto done;

	net_event_info_t event_data = {0,};
	net_wifi_state_t wifi_state = WIFI_UNKNOWN;

	NETWORK_LOG(NETWORK_ERROR,
		"Error!!! Wifi Power on/off failed. Error code : [%d]\n", Error);

	if (request_table[NETWORK_REQUEST_TYPE_WIFI_POWER].flag == TRUE) {
		memset(&request_table[NETWORK_REQUEST_TYPE_WIFI_POWER],
				0, sizeof(network_request_table_t));

		event_data.Event = NET_EVENT_WIFI_POWER_RSP;
		event_data.Error = Error;
		event_data.Datalength = sizeof(net_wifi_state_t);
		event_data.Data = &wifi_state;
		NETWORK_LOG(NETWORK_LOW,
			"Sending NET_EVENT_WIFI_POWER_RSP Error = %d\n", event_data.Error);
		_net_client_callback(&event_data);
	}

done:
	dbus_message_unref(reply);
	dbus_pending_call_unref(call);

	network_dbus_pending_call_data.is_used = FALSE;
	network_dbus_pending_call_data.pcall = NULL;

	__NETWORK_FUNC_EXIT__;
}

static int __net_append_argument(DBusMessageIter *iter, int ArgType, const char *Value)
{
	__NETWORK_FUNC_ENTER__;

	double Double = 0;
	unsigned char ByteValue = 0;
	dbus_bool_t booleanvalue = 0;

	dbus_uint16_t Uint16 = 0;
	dbus_int16_t Int16 = 0;
	dbus_uint32_t Uint32 = 0;
	dbus_int32_t Int32 = 0;

	switch(ArgType) {
	case DBUS_TYPE_BYTE:
		ByteValue = strtoul(Value, NULL, 0);
		dbus_message_iter_append_basic(iter, DBUS_TYPE_BYTE, &ByteValue);
		break;

	case DBUS_TYPE_DOUBLE:
		Double = strtod(Value, NULL);
		dbus_message_iter_append_basic(iter, DBUS_TYPE_DOUBLE, &Double);
		break;

	case DBUS_TYPE_INT16:
		Int16 = strtol(Value, NULL, 0);
		dbus_message_iter_append_basic(iter, DBUS_TYPE_INT16, &Int16);
		break;

	case DBUS_TYPE_UINT16:
		Uint16 = strtoul(Value, NULL, 0);
		dbus_message_iter_append_basic(iter, DBUS_TYPE_UINT16, &Uint16);
		break;

	case DBUS_TYPE_INT32:
		Int32 = strtol(Value, NULL, 0);
		dbus_message_iter_append_basic(iter, DBUS_TYPE_INT32, &Int32);
		break;

	case DBUS_TYPE_UINT32:
		Uint32 = strtoul(Value, NULL, 0);
		dbus_message_iter_append_basic(iter, DBUS_TYPE_UINT32, &Uint32);
		break;

	case DBUS_TYPE_STRING:
		dbus_message_iter_append_basic(iter, DBUS_TYPE_STRING, &Value);
		break;

	case DBUS_TYPE_OBJECT_PATH:
		dbus_message_iter_append_basic(iter, DBUS_TYPE_OBJECT_PATH, &Value);
		break;

	case DBUS_TYPE_BOOLEAN:
		if( strcmp (Value, "true") == 0 ) {
			booleanvalue = TRUE;
			dbus_message_iter_append_basic(iter, DBUS_TYPE_BOOLEAN, &booleanvalue);
		} else if( strcmp (Value, "false") == 0 ) {
			booleanvalue = FALSE;
			dbus_message_iter_append_basic(iter, DBUS_TYPE_BOOLEAN, &booleanvalue);
		} else {
			NETWORK_LOG(NETWORK_ERROR, "Error!!! Expected \"true\" or \"false\" instead of \"%s\"\n", Value);
			__NETWORK_FUNC_EXIT__;
			return NET_ERR_UNKNOWN;
		}
		break;

	default:
		NETWORK_LOG( NETWORK_ERROR, "Error!!! Unsupported data ArgType %c\n", (char) ArgType);
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_UNKNOWN;
	}

	__NETWORK_FUNC_EXIT__;
	return NET_ERR_NONE;
}

static int __net_append_array(DBusMessageIter *iter, int ArgType, const char *Value)
{
	__NETWORK_FUNC_ENTER__;

	const char *Val = NULL;
	char *saveptr = NULL;
	char *DupValue = strdup(Value);

	Val = strtok_r(DupValue, ",", &saveptr);
	while(Val != NULL) {
		if( __net_append_argument(iter, ArgType, Val) != NET_ERR_NONE ) {
			NET_MEMFREE(DupValue);
			__NETWORK_FUNC_EXIT__;
			return  NET_ERR_UNKNOWN;
		}
		Val = strtok_r(NULL, ",", &saveptr);
	}
	NET_MEMFREE(DupValue);

	__NETWORK_FUNC_EXIT__;
	return NET_ERR_NONE;
}

static int __net_append_dict(DBusMessageIter *iter, int KeyType, int ValueType, const char *Value)
{
	__NETWORK_FUNC_ENTER__;

	const char *Val = NULL;
	char *saveptr = NULL;
	char *DupValue = strdup(Value);

	Val = strtok_r(DupValue, ",", &saveptr);
	while(Val != NULL) {
		DBusMessageIter SubIter;

		dbus_message_iter_open_container(iter,
				DBUS_TYPE_DICT_ENTRY,
				NULL,
				&SubIter);

		if( __net_append_argument (&SubIter, KeyType, Val) != NET_ERR_NONE ) {
			NETWORK_LOG(NETWORK_ERROR, "Error!!! __net_append_argument() failed\n");
			NET_MEMFREE(DupValue);
			__NETWORK_FUNC_EXIT__;
			return  NET_ERR_UNKNOWN;
		}

		Val = strtok_r(NULL, ",", &saveptr);
		if(Val == NULL) {
			NETWORK_LOG(NETWORK_ERROR, "Error!!! Crashed dictionary data\n");
			NET_MEMFREE(DupValue);
			__NETWORK_FUNC_EXIT__;
			return NET_ERR_UNKNOWN;
		}

		if( __net_append_argument (&SubIter, ValueType, Val) != NET_ERR_NONE ) {
			NETWORK_LOG(NETWORK_ERROR, "Error!!! __net_append_argument() failed\n");
			NET_MEMFREE(DupValue);
			__NETWORK_FUNC_EXIT__;
			return  NET_ERR_UNKNOWN;
		}

		dbus_message_iter_close_container (iter, &SubIter);
		Val = strtok_r(NULL, ",", &saveptr);
	}
	NET_MEMFREE(DupValue);
	__NETWORK_FUNC_EXIT__;
	return  NET_ERR_NONE;
}

static int __net_datatype_from_stringname(const char *Args)
{
	__NETWORK_FUNC_ENTER__;

	int ArgType = 0;

	if( !strcmp(Args, CONNMAN_CLIENT_DBUS_TYPE_STRING) )
		ArgType = DBUS_TYPE_STRING;
	else if( !strcmp(Args, CONNMAN_CLIENT_DBUS_TYPE_INT16) )
		ArgType = DBUS_TYPE_INT16;
	else if( !strcmp(Args, CONNMAN_CLIENT_DBUS_TYPE_UINT16) )
		ArgType = DBUS_TYPE_UINT16;
	else if( !strcmp(Args, CONNMAN_CLIENT_DBUS_TYPE_INT32) )
		ArgType = DBUS_TYPE_INT32;
	else if( !strcmp(Args, CONNMAN_CLIENT_DBUS_TYPE_UINT32) )
		ArgType = DBUS_TYPE_UINT32;
	else if( !strcmp(Args, CONNMAN_CLIENT_DBUS_TYPE_INT64) )
		ArgType = DBUS_TYPE_INT64;
	else if( !strcmp(Args, CONNMAN_CLIENT_DBUS_TYPE_UINT64) )
		ArgType = DBUS_TYPE_UINT64;
	else if( !strcmp(Args, CONNMAN_CLIENT_DBUS_TYPE_DOUBLE) )
		ArgType = DBUS_TYPE_DOUBLE;
	else if( !strcmp(Args, CONNMAN_CLIENT_DBUS_TYPE_BYTE) )
		ArgType = DBUS_TYPE_BYTE;
	else if( !strcmp(Args, CONNMAN_CLIENT_DBUS_TYPE_BOOLEAN) )
		ArgType = DBUS_TYPE_BOOLEAN;
	else if( !strcmp(Args, CONNMAN_CLIENT_DBUS_TYPE_OBJECT_PATH) )
		ArgType = DBUS_TYPE_OBJECT_PATH;
	else {
		NETWORK_LOG( NETWORK_ERROR, "Error!!! Unknown Argument Type \"%s\"\n", Args);
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_UNKNOWN;
	}

	__NETWORK_FUNC_EXIT__;
	return ArgType;
}
 
  
/*****************************************************************************
 * 	Global Functions Definition
 *****************************************************************************/

DBusMessage *_net_invoke_dbus_method(const char* dest, DBusConnection *connection,
		const char* path, char* interface_name, char* method, int *dbus_error)
{
	__NETWORK_FUNC_ENTER__;

	DBusError error;
	DBusMessage *reply = NULL;
	DBusMessage *message = NULL;

	*dbus_error = NET_ERR_NONE;

	message = dbus_message_new_method_call(dest, path, interface_name, method);
	if (message == NULL) {
		NETWORK_LOG(NETWORK_ERROR, "Error!!! dbus_message_new_method_call() failed\n");
		__NETWORK_FUNC_EXIT__;
		return NULL;
	}

	dbus_error_init(&error);

	reply = dbus_connection_send_with_reply_and_block(connection,
			message, DBUS_REPLY_TIMEOUT, &error);
	if (reply == NULL) {
		if (dbus_error_is_set(&error) == TRUE) {
			NETWORK_LOG(NETWORK_ERROR,
					"Error!!! dbus_connection_send_with_reply_and_block() failed. dbus error [%s: %s]\n",
					error.name, error.message);
			*dbus_error = __net_error_string_to_enum(error.name);
			dbus_error_free(&error);
		} else {
			NETWORK_LOG(NETWORK_ERROR, "Error!!! dbus_connection_send_with_reply_and_block() failed\n");
			*dbus_error = NET_ERR_UNKNOWN;
		}

		dbus_message_unref(message);
		__NETWORK_FUNC_EXIT__;
		return NULL;
	}

	dbus_message_unref(message);

	__NETWORK_FUNC_EXIT__;
	return reply;
}

int _net_invoke_dbus_method_nonblock(const char* dest, DBusConnection *connection,
		const char* path, char* interface_name, char* method,
		DBusPendingCallNotifyFunction notify_func)
{
	__NETWORK_FUNC_ENTER__;

	DBusMessage *message = NULL;
	DBusPendingCall *call;
	dbus_bool_t result;

	message = dbus_message_new_method_call(dest, path, interface_name, method);
	if (message == NULL) {
		NETWORK_LOG(NETWORK_ERROR, "Error!!! dbus_message_new_method_call() Failed\n");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_UNKNOWN;
	}

	result = dbus_connection_send_with_reply(connection,
			message, &call, DBUS_REPLY_TIMEOUT);

	if (result == FALSE || call == NULL) {
		NETWORK_LOG(NETWORK_ERROR, "Error!!! dbus_connection_send_with_reply() Failed\n");
		dbus_message_unref(message);
		return NET_ERR_UNKNOWN;
	}

	dbus_pending_call_set_notify(call, notify_func, NULL, NULL);
	network_dbus_pending_call_data.pcall = call;
	network_dbus_pending_call_data.is_used = TRUE;

	dbus_message_unref(message);

	__NETWORK_FUNC_EXIT__;
	return NET_ERR_NONE;
}


int _net_send_dbus_request(const char* destination, char *param_array[], DBusMessage** result)
{
	__NETWORK_FUNC_ENTER__;

	DBusConnection *connection = NULL;
	DBusError error;
	DBusMessage *message = NULL;
	net_err_t Error = NET_ERR_NONE;
	char *RequestMethod = NULL;
	int i = 0;
	const char *path = NULL;
	const char *name = NULL;
	int param_count = 0;
	// const char *destination = CONNMAN_SERVICE;
	DBusMessageIter iter;

	for (param_count = 0; param_array[param_count] != NULL; param_count++) {
		NETWORK_LOG(NETWORK_HIGH, "[%s]\n", param_array[param_count]);
	}
	NETWORK_LOG(NETWORK_HIGH, "Total Arguments [%d]\n", param_count);

	path = param_array[i++]; /** 0th is path */
	name = param_array[i++]; /** 1st is request name */

	if ((strlen(path) == 0) || (strlen(name) == 0) ) {
		NETWORK_LOG(NETWORK_ASSERT, "Error!!! Invalid parameters passed path [%s], requested name [%s]\n",
				path, name);
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_INVALID_PARAM;
	}

	dbus_error_init(&error);

	connection = dbus_bus_get(DBUS_BUS_SYSTEM, &error);
	if (connection == NULL) {
		NETWORK_LOG(NETWORK_EXCEPTION, "Error!!! Failed to get system dbus, error [%s]\n",
				error.message);
		dbus_error_free(&error);
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_UNKNOWN;
	}

	RequestMethod = strrchr(name, '.');
	if (RequestMethod == NULL) {
		NETWORK_LOG(NETWORK_ERROR, "Error!!! Invalid method in \"%s\"\n", name);
		dbus_connection_unref(connection);
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_UNKNOWN;
	}

	*RequestMethod = '\0';
	message = dbus_message_new_method_call(NULL, path, name, RequestMethod + 1);

	if (message == NULL) {
		NETWORK_LOG(NETWORK_ERROR, "Error!!! dbus_message_new_method_call() failed\n");
		__NETWORK_FUNC_EXIT__;
		Error = NET_ERR_UNKNOWN;
		goto end_error;
	}

	if (destination && !dbus_message_set_destination(message, destination)) {
		NETWORK_LOG(NETWORK_EXCEPTION, "Error!!! dbus_message_set_destination() failed\n");
		__NETWORK_FUNC_EXIT__;
		Error = NET_ERR_UNKNOWN;
		goto end_error;
	}

	dbus_message_iter_init_append(message, &iter);

	/** Two arguments name and path already extracted, so i == 2 */
	while (i < param_count) {
		char *Args = NULL;
		char *Ch = NULL;
		int ArgType = 0;
		int SecondaryType = 0;
		int ContainerType = 0;
		DBusMessageIter *TargetIter = NULL;
		DBusMessageIter ContainerIter;

		ArgType = DBUS_TYPE_INVALID;
		Args = param_array[i++];
		Ch = strchr (Args, ':');

		if (Ch == NULL) {
			NETWORK_LOG(NETWORK_ERROR, "Error!!! Invalid data format[\"%s\"]\n", Args);
			Error = NET_ERR_UNKNOWN;
			goto end_error;
		}

		*(Ch++) = 0;

		if (strcmp(Args, CONNMAN_CLIENT_DBUS_TYPE_VARIANT) == 0) {
			ContainerType = DBUS_TYPE_VARIANT;
		} else if (strcmp(Args, CONNMAN_CLIENT_DBUS_TYPE_ARRAY) == 0) {
			ContainerType = DBUS_TYPE_ARRAY;
		} else if (strcmp(Args, CONNMAN_CLIENT_DBUS_TYPE_DICT_ENTRY) == 0) {
			ContainerType = DBUS_TYPE_DICT_ENTRY;
		} else {
			ContainerType = DBUS_TYPE_INVALID;
		}

		if (ContainerType != DBUS_TYPE_INVALID) {
			Args = Ch;
			Ch = strchr(Args, ':');
			if (Ch == NULL) {
				NETWORK_LOG(NETWORK_ERROR, "Error!!! Invalid data format[\"%s\"]\n", Args);
				Error = NET_ERR_UNKNOWN;
				goto end_error;
			}
			*(Ch++) = 0;
		}

		if (Args[0] == 0) {
			ArgType = DBUS_TYPE_STRING;
		} else {
			ArgType = __net_datatype_from_stringname(Args);
			if (ArgType == NET_ERR_UNKNOWN) {
				NETWORK_LOG(NETWORK_ERROR, "Error!!! Unknown data type\n");
				Error = NET_ERR_UNKNOWN;
				goto end_error;
			}
		}

		if (ContainerType == DBUS_TYPE_DICT_ENTRY) {
			char Signature[5] = "";
			Args = Ch;
			Ch = strchr (Ch, ':');

			if (Ch == NULL) {
				NETWORK_LOG(NETWORK_ERROR, "Error!!! Invalid data format[\"%s\"]\n", Args);
				Error = NET_ERR_UNKNOWN;
				goto end_error;
			}

			*(Ch++) = 0;
			SecondaryType = __net_datatype_from_stringname(Args);

			if (SecondaryType == NET_ERR_UNKNOWN) {
				NETWORK_LOG(NETWORK_ERROR, "Error!!! Unknown datatype\n");
				Error = NET_ERR_UNKNOWN;
				goto end_error;
			}

			Signature[0] = DBUS_DICT_ENTRY_BEGIN_CHAR;
			Signature[1] = ArgType;
			Signature[2] = SecondaryType;
			Signature[3] = DBUS_DICT_ENTRY_END_CHAR;
			Signature[4] = '\0';

			dbus_message_iter_open_container(&iter,
					DBUS_TYPE_ARRAY,
					Signature,
					&ContainerIter);
			TargetIter = &ContainerIter;
		} else if (ContainerType != DBUS_TYPE_INVALID) {
			char Signature[2] = "";
			Signature[0] = ArgType;
			Signature[1] = '\0';

			dbus_message_iter_open_container(&iter,
					ContainerType,
					Signature,
					&ContainerIter);
			TargetIter = &ContainerIter;
		} else {
			TargetIter = &iter;
		}

		if (ContainerType == DBUS_TYPE_ARRAY) {
			if (__net_append_array(TargetIter, ArgType, Ch) != NET_ERR_NONE) {
				NETWORK_LOG(NETWORK_ERROR, "Error!!! __net_append_array() failed\n");
				Error = NET_ERR_UNKNOWN;
				goto end_error;
			}
		} else if (ContainerType == DBUS_TYPE_DICT_ENTRY) {
			if (__net_append_dict(TargetIter, ArgType, SecondaryType, Ch) != NET_ERR_NONE) {
				NETWORK_LOG(NETWORK_ERROR, "Error!!! __net_append_dict() failed\n");
				Error = NET_ERR_UNKNOWN;
				goto end_error;
			}
		} else {
			if (__net_append_argument(TargetIter, ArgType, Ch) != NET_ERR_NONE) {
				NETWORK_LOG(NETWORK_ERROR, "Error!!! __net_append_argument() failed\n");
				Error = NET_ERR_UNKNOWN;
				goto end_error;
			}
		}

		if (ContainerType != DBUS_TYPE_INVALID) {
			dbus_message_iter_close_container(&iter, &ContainerIter);
		}
	}

	DBusMessage *reply = NULL;

	dbus_error_init (&error);

	reply = dbus_connection_send_with_reply_and_block(connection,
			message,
			DBUS_REPLY_TIMEOUT,
			&error);
	if (reply == NULL) {
		if (dbus_error_is_set(&error) == TRUE) {
			NETWORK_LOG(NETWORK_ERROR,
					"Error!!! dbus_connection_send_with_reply_and_block() failed, Error[%s: %s]\n",
					error.name,
					error.message);
			Error = __net_error_string_to_enum(error.name);
			dbus_error_free(&error);
		} else
			Error = NET_ERR_UNKNOWN;

		goto end_error;
	} else {
		if (result != NULL) {
			*result = reply;
		} else {
			dbus_message_unref(reply);
		}
	}

end_error:
	dbus_message_unref(message);
	dbus_connection_unref(connection);

	if (Error == NET_ERR_NONE)
		NETWORK_LOG(NETWORK_HIGH, "Successfully requested\n");

	__NETWORK_FUNC_EXIT__;
	return Error;
}


int _net_dbus_open_connection(const char* profile_name)
{
	__NETWORK_FUNC_ENTER__;

	net_err_t Error = NET_ERR_NONE;
	DBusConnection* conn = NULL;

	conn = dbus_bus_get(DBUS_BUS_SYSTEM, NULL);

	if (conn == NULL) {
		NETWORK_LOG(NETWORK_EXCEPTION, "Error!!! Can't get on system bus\n");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_UNKNOWN;
	}

	NETWORK_LOG(NETWORK_HIGH,  "Requesting [%s %s]\n",
			profile_name, CONNMAN_SERVICE_INTERFACE ".Connect");

	Error = _net_invoke_dbus_method_nonblock(CONNMAN_SERVICE, conn, profile_name,
			CONNMAN_SERVICE_INTERFACE, "Connect", __net_open_connection_reply);

	dbus_connection_unref(conn);

	__NETWORK_FUNC_EXIT__;
	return Error;
}


int _net_dbus_close_connection(const char* profile_name)
{
	__NETWORK_FUNC_ENTER__;

	net_err_t Error = NET_ERR_NONE;
	DBusConnection* conn = NULL;

	conn = dbus_bus_get(DBUS_BUS_SYSTEM, NULL);

	if (conn == NULL) {
		NETWORK_LOG(NETWORK_EXCEPTION, "Error!!! Can't get on system bus\n");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_UNKNOWN;
	}

	NETWORK_LOG(NETWORK_HIGH,  "Requesting [%s %s]\n",
			profile_name, CONNMAN_SERVICE_INTERFACE ".Disconnect");

	Error = _net_invoke_dbus_method_nonblock(CONNMAN_SERVICE, conn, profile_name,
			CONNMAN_SERVICE_INTERFACE, "Disconnect", __net_close_connection_reply);

	dbus_connection_unref(conn);

	__NETWORK_FUNC_EXIT__;
	return Error;
}


int _net_dbus_scan_request(void)
{
	__NETWORK_FUNC_ENTER__;

	net_err_t Error = NET_ERR_NONE;

	/** dbus-send --system --print-reply --dest=net.connman / net.connman.Manager.RequestScan string:wifi */
	char request[] = CONNMAN_MANAGER_INTERFACE ".RequestScan";
	char param1[] = "string:wifi";
	char path[CONNMAN_MAX_BUFLEN] = "/";
	char* param_array[] = {NULL, NULL, NULL, NULL};
	param_array[0] = path;
	param_array[1] = request;
	param_array[2] = param1;

	NETWORK_LOG(NETWORK_HIGH, "path [%s]\n", path);
	NETWORK_LOG(NETWORK_HIGH, "Requesting [%s %s %s]\n", param_array[0], param_array[1], param_array[2]);

	if( (Error = _net_send_dbus_request(CONNMAN_SERVICE, param_array, NULL)) != NET_ERR_NONE ) {
		NETWORK_LOG(NETWORK_ERROR, "Error!!! _net_send_dbus_request failed\n");
		__NETWORK_FUNC_EXIT__;
		return Error;
	}

	__NETWORK_FUNC_EXIT__;
	return NET_ERR_NONE;
}

int _net_dbus_provision_service(gchar * config_str, int len)
{
	__NETWORK_FUNC_ENTER__;

	net_err_t Error = NET_ERR_NONE;

	/** dbus-send --system --print-reply --dest=net.connman / net.connman.Manager.ProvisionService string:xxx..*/
	char request[] = CONNMAN_MANAGER_INTERFACE ".ProvisionService";
	char *param1 = NULL;
	int param1_len = len + strlen("string:");
	char path[CONNMAN_MAX_BUFLEN] = "/";
	char* param_array[] = {NULL, NULL, NULL, NULL};

	param1 = (char*)calloc(param1_len, sizeof(char));
	if(param1 == NULL)
		return NET_ERR_UNKNOWN;

	snprintf(param1, param1_len, "string:%s", config_str);

	param_array[0] = path;
	param_array[1] = request;
	param_array[2] = param1;

	if( (Error = _net_send_dbus_request(CONNMAN_SERVICE, param_array, NULL)) != NET_ERR_NONE ) {
		NETWORK_LOG(NETWORK_ERROR, "Error!!! _net_send_dbus_request failed\n");
		NET_MEMFREE(param1);
		__NETWORK_FUNC_EXIT__;
		return Error;
	}

	NET_MEMFREE(param1);
	__NETWORK_FUNC_EXIT__;
	return NET_ERR_NONE;
}


int _net_dbus_set_bgscan_mode(net_wifi_background_scan_mode_t mode)
{
	__NETWORK_FUNC_ENTER__;

	/** TODO device interface missing */

	net_err_t Error = NET_ERR_NONE;
	/** dbus-send --system --print-reply --dest=net.connman / net.connman.Manager.SetProperty string:ScanMode variant:uint16:0/1/2 */
	char request[] = NETCONFIG_WIFI_INTERFACE ".SetBgscan";
	char param1[64] = "";
	char path[CONNMAN_MAX_BUFLEN] = NETCONFIG_WIFI_PATH;
	char* param_array[] = {NULL, NULL, NULL, NULL};

	NETWORK_LOG(NETWORK_HIGH, "path [%s]\n", path);

	snprintf(param1, 64, "uint32:%d", mode);
	
	param_array[0] = path;
	param_array[1] = request;
	param_array[2] = param1;

	NETWORK_LOG(NETWORK_HIGH,  "Requesting [%s %s %s]\n",
		param_array[0],
		param_array[1],
		param_array[2]
		);

	Error = _net_send_dbus_request(NETCONFIG_SERVICE, param_array, NULL);
	if (Error != NET_ERR_NONE) {
		NETWORK_LOG(NETWORK_ERROR,  "Error!!! Request failed\n");
		__NETWORK_FUNC_EXIT__;
		return Error;
	}

	__NETWORK_FUNC_EXIT__;
	return NET_ERR_NONE;
}

int _net_dbus_get_technology_state(network_get_tech_state_info_t* tech_state)
{
	__NETWORK_FUNC_ENTER__;

	net_err_t Error = NET_ERR_NONE;
	DBusConnection* conn = NULL;
	DBusMessage *message = NULL;

	if ((tech_state == NULL) || (strlen(tech_state->technology) == 0)) {
		NETWORK_LOG(NETWORK_EXCEPTION, "Error!!! Invalid parameter\n");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_INVALID_PARAM;
	}

	conn = dbus_bus_get(DBUS_BUS_SYSTEM, NULL);
	if (conn == NULL) {
		NETWORK_LOG(NETWORK_EXCEPTION,
				"Error!!! Can't get on system bus\n");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_UNKNOWN;
	}

	if (strcmp(tech_state->technology, "wifi") == 0) {
		int hotspot_state = 0;
		vconf_get_int(VCONFKEY_MOBILE_HOTSPOT_MODE, &hotspot_state);

		if (hotspot_state & VCONFKEY_MOBILE_HOTSPOT_MODE_WIFI)
			goto done;
	}

	message = _net_invoke_dbus_method(CONNMAN_SERVICE, conn, CONNMAN_MANAGER_PATH,
			CONNMAN_MANAGER_INTERFACE, "GetProperties", &Error);

	if (message == NULL) {
		NETWORK_LOG(NETWORK_ERROR,
				"Error!!! Failed to get technology info\n");
		goto done;
	}

	Error = _net_get_tech_state(message, tech_state);

	NETWORK_LOG(NETWORK_HIGH,
			"technology [%s]\n"
			"AvailableTechnology [%d]\n"
			"EnabledTechnology [%d]\n"
			"ConnectedTechnology [%d]\n"
			"DefaultTechnology [%d]\n",
			tech_state->technology, 
			tech_state->AvailableTechnology, 
			tech_state->EnabledTechnology, 
			tech_state->ConnectedTechnology, 
			tech_state->DefaultTechnology);

	dbus_message_unref(message);

done:
	dbus_connection_unref(conn);
	__NETWORK_FUNC_EXIT__;
	return Error;
}


int _net_dbus_get_network_status(net_device_t device_type, net_cm_network_status_t* network_status)
{
	__NETWORK_FUNC_ENTER__;

	net_err_t Error = NET_ERR_NONE;
	network_get_tech_state_info_t tech_state = {{0,},};

	if (device_type == NET_DEVICE_WIFI)
		snprintf(tech_state.technology, NET_TECH_LENGTH_MAX, "%s", "wifi");
	else if (device_type == NET_DEVICE_CELLULAR)
		snprintf(tech_state.technology, NET_TECH_LENGTH_MAX, "%s", "cellular");
	else {
		Error = NET_ERR_INVALID_PARAM;
		goto done;
	}

	Error = _net_dbus_get_technology_state(&tech_state);
	if (Error != NET_ERR_NONE) {
		NETWORK_LOG(NETWORK_ERROR,
			"Error!!! _net_dbus_get_technology_state() failed. Error [%s]\n",
			_net_print_error(Error));
		goto done;
	}

	if (tech_state.ConnectedTechnology == TRUE)
		*network_status = NET_STATUS_AVAILABLE;
	else
		*network_status = NET_STATUS_UNAVAILABLE;

done:
	__NETWORK_FUNC_EXIT__;
	return Error;
}


int _net_dbus_get_state(char* state)
{
	__NETWORK_FUNC_ENTER__;

	net_err_t Error = NET_ERR_NONE;
	DBusConnection* conn = NULL;
	DBusMessage *message = NULL;
	char *net_state = NULL;

	conn = dbus_bus_get(DBUS_BUS_SYSTEM, NULL); 
	if (conn == NULL) {
		NETWORK_LOG(NETWORK_EXCEPTION,
				"Error!!! Can't get on system bus\n");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_UNKNOWN;
	}

	message = _net_invoke_dbus_method(
			CONNMAN_SERVICE, conn, CONNMAN_MANAGER_PATH,
			CONNMAN_MANAGER_INTERFACE, "GetState", &Error);
	if (message == NULL) {
		NETWORK_LOG(NETWORK_ERROR,
				"Error!!! Failed to get service properties\n");
		dbus_connection_unref(conn);
		__NETWORK_FUNC_EXIT__;
		return Error;
	}

	net_state = _net_get_string(message);
	snprintf(state, strlen(net_state)+1, "%s", net_state);
	
	NETWORK_LOG( NETWORK_HIGH, "State : [%s]\n", state);

	dbus_message_unref(message);
	dbus_connection_unref(conn);

	__NETWORK_FUNC_EXIT__;
	return Error;
}


int _net_dbus_connect_service(const net_wifi_connect_service_info_t* wifi_connection_info)
{
	__NETWORK_FUNC_ENTER__;

	net_err_t Error = NET_ERR_NONE;
	DBusError error;

	const char *prop_type = "Type";
	const char *prop_mode = "Mode";
	const char *prop_ssid = "SSID";
	const char *prop_security = "Security";
	const char *prop_passphrase = "Passphrase";

	DBusMessage* msg = NULL;
	DBusMessage* reply = NULL;
	DBusMessageIter dict, entry, array,value;
	DBusConnection* conn = NULL;

	conn = dbus_bus_get(DBUS_BUS_SYSTEM, NULL); 
	if(conn == NULL) {
		NETWORK_LOG(NETWORK_EXCEPTION, "Error!!! Can't get on system bus\n");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_UNKNOWN;
	}

	msg = dbus_message_new_method_call(CONNMAN_SERVICE, CONNMAN_MANAGER_PATH, CONNMAN_MANAGER_INTERFACE, "ConnectService");
	if(msg == NULL) {
		NETWORK_LOG(NETWORK_EXCEPTION, "Error!!! dbus_message_new_method_call() failed\n");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_UNKNOWN;
	}

	dbus_message_iter_init_append(msg, &array);
	dbus_message_iter_open_container(&array, DBUS_TYPE_ARRAY, "{sv}", &dict);

	dbus_message_iter_open_container(&dict, DBUS_TYPE_DICT_ENTRY, 0, &entry);
	dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &prop_type);
	dbus_message_iter_open_container(&entry, DBUS_TYPE_VARIANT, DBUS_TYPE_STRING_AS_STRING, &value);
	dbus_message_iter_append_basic(&value, DBUS_TYPE_STRING, &wifi_connection_info->type);
	dbus_message_iter_close_container(&entry, &value);
	dbus_message_iter_close_container(&dict, &entry);

	dbus_message_iter_open_container(&dict, DBUS_TYPE_DICT_ENTRY, 0, &entry);
	dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &prop_mode);
	dbus_message_iter_open_container(&entry, DBUS_TYPE_VARIANT, DBUS_TYPE_STRING_AS_STRING, &value);
	dbus_message_iter_append_basic(&value, DBUS_TYPE_STRING, &wifi_connection_info->mode);
	dbus_message_iter_close_container(&entry, &value);
	dbus_message_iter_close_container(&dict, &entry);

	dbus_message_iter_open_container(&dict, DBUS_TYPE_DICT_ENTRY, 0, &entry);
	dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &prop_ssid);
	dbus_message_iter_open_container(&entry, DBUS_TYPE_VARIANT, DBUS_TYPE_STRING_AS_STRING, &value);
	dbus_message_iter_append_basic(&value, DBUS_TYPE_STRING, &wifi_connection_info->ssid);
	dbus_message_iter_close_container(&entry, &value);
	dbus_message_iter_close_container(&dict, &entry);

	dbus_message_iter_open_container(&dict, DBUS_TYPE_DICT_ENTRY, 0, &entry);
	dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &prop_security);
	dbus_message_iter_open_container(&entry, DBUS_TYPE_VARIANT, DBUS_TYPE_STRING_AS_STRING, &value);
	dbus_message_iter_append_basic(&value, DBUS_TYPE_STRING, &wifi_connection_info->security);
	dbus_message_iter_close_container(&entry, &value);
	dbus_message_iter_close_container(&dict, &entry);

	if( strcmp(wifi_connection_info->security, "ieee8021x") == 0 ) {
		/** TODO Handle EAP */
	} else {
		/** none, wep, psk, rsn */
		dbus_message_iter_open_container(&dict, DBUS_TYPE_DICT_ENTRY, 0, &entry);
		dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &prop_passphrase);
		dbus_message_iter_open_container(&entry, DBUS_TYPE_VARIANT, DBUS_TYPE_STRING_AS_STRING, &value);
		dbus_message_iter_append_basic(&value, DBUS_TYPE_STRING, &wifi_connection_info->passphrase);
		dbus_message_iter_close_container(&entry, &value);
		dbus_message_iter_close_container(&dict, &entry);
	}

	dbus_message_iter_close_container(&array, &dict);

	dbus_error_init(&error);
	reply = dbus_connection_send_with_reply_and_block(conn,
			msg,
			6 * DBUS_REPLY_TIMEOUT, /** Special case - here profile is created and returned so this need more time */
			&error);

	if(reply == NULL) {
		if( dbus_error_is_set(&error) == TRUE ) {
			NETWORK_LOG(NETWORK_ERROR,
					"Error!!! dbus_connection_send_with_reply_and_block() failed, Error[%s: %s]\n",
					error.name,
					error.message);
			Error = __net_error_string_to_enum(error.name);
			dbus_error_free(&error);
			dbus_message_unref(msg);
			__NETWORK_FUNC_EXIT__;
			return Error;
		}
		dbus_message_unref(msg);
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_UNKNOWN;
	} else {
		char *ProfileName = NULL;
		ProfileName = _net_get_object(reply);
		NETWORK_LOG(NETWORK_HIGH, "ObjectPath/ProfileName [%s]\n", ProfileName);
	}

	dbus_message_unref(reply);
	dbus_message_unref(msg);

	NETWORK_LOG(NETWORK_HIGH, "Successfully configured\n");

	dbus_connection_unref(conn);
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

	DBusMessage *msg = NULL;
	DBusMessage *reply = NULL;
	DBusMessageIter itr, variant, dict, entry;
	DBusConnection* conn = NULL;

	if ((prof_info == NULL) || (profile_name == NULL) || (strlen(profile_name) == 0)) {
		NETWORK_LOG(NETWORK_ASSERT,  "Error!!! Invalid argument\n");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_INVALID_PARAM;
	}

	snprintf(ip_buffer, NETPM_IPV4_STR_LEN_MAX + 1, "%s",
			inet_ntoa(prof_info->ProfileInfo.Wlan.net_info.IpAddr.Data.Ipv4));
	snprintf(netmask_buffer, NETPM_IPV4_STR_LEN_MAX + 1, "%s",
			inet_ntoa(prof_info->ProfileInfo.Wlan.net_info.SubnetMask.Data.Ipv4));
	snprintf(gateway_buffer, NETPM_IPV4_STR_LEN_MAX + 1, "%s",
			inet_ntoa(prof_info->ProfileInfo.Wlan.net_info.GatewayAddr.Data.Ipv4));

	NETWORK_LOG(NETWORK_ASSERT, "ipaddress : %s, netmask : %s, gateway : %s\n",
			ipaddress, netmask, gateway);

	conn = dbus_bus_get(DBUS_BUS_SYSTEM, NULL); 
	if (conn == NULL) {
		NETWORK_LOG(NETWORK_ERROR,  "Error!!! Can't get on system bus\n");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_UNKNOWN;
	}

	/** Send ipaddress, netmask, gateway configuration */
	msg = dbus_message_new_method_call(CONNMAN_SERVICE,
			profile_name, CONNMAN_SERVICE_INTERFACE, "SetProperty");
	if (msg == NULL) {
		NETWORK_LOG( NETWORK_ERROR,  "Error!!! dbus_message_new_method_call() failed\n");
		dbus_connection_unref(conn);
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_UNKNOWN;
	}
	NETWORK_LOG(NETWORK_ASSERT, "DBus Message 1/2 : %s %s %s %s\n", CONNMAN_SERVICE,
			profile_name, CONNMAN_SERVICE_INTERFACE, "SetProperty");

	dbus_message_iter_init_append(msg, &itr);
	dbus_message_iter_append_basic(&itr, DBUS_TYPE_STRING, &prop_ipv4_configuration);

	dbus_message_iter_open_container
		(&itr, DBUS_TYPE_VARIANT,
		 (DBUS_TYPE_ARRAY_AS_STRING
		  DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
		  DBUS_TYPE_STRING_AS_STRING
		  DBUS_TYPE_STRING_AS_STRING
		  DBUS_DICT_ENTRY_END_CHAR_AS_STRING),
		 &variant);
	dbus_message_iter_open_container
		(&variant, DBUS_TYPE_ARRAY,
		 (DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
		  DBUS_TYPE_STRING_AS_STRING
		  DBUS_TYPE_STRING_AS_STRING
		  DBUS_DICT_ENTRY_END_CHAR_AS_STRING),
		 &dict);
		
	if (prof_info->ProfileInfo.Wlan.net_info.IpConfigType == NET_IP_CONFIG_TYPE_DYNAMIC ||
	    prof_info->ProfileInfo.Wlan.net_info.IpConfigType == NET_IP_CONFIG_TYPE_AUTO_IP) {
		dbus_message_iter_open_container(&dict, DBUS_TYPE_DICT_ENTRY, NULL, &entry);
		dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &prop_method);
		dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &dhcp_method);
		dbus_message_iter_close_container(&dict, &entry);
		NETWORK_LOG(NETWORK_ASSERT,  "DBus Message 2/2 : %s %s\n", prop_method, dhcp_method);
	} else if (prof_info->ProfileInfo.Wlan.net_info.IpConfigType == NET_IP_CONFIG_TYPE_OFF) {
		dbus_message_iter_open_container(&dict, DBUS_TYPE_DICT_ENTRY, NULL, &entry);
		dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &prop_method);
		dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &off_method);
		dbus_message_iter_close_container(&dict, &entry);
		NETWORK_LOG(NETWORK_ASSERT,  "DBus Message 2/2 : %s %s\n", prop_method, off_method);
	} else if (prof_info->ProfileInfo.Wlan.net_info.IpConfigType == NET_IP_CONFIG_TYPE_STATIC) {
		dbus_message_iter_open_container(&dict, DBUS_TYPE_DICT_ENTRY, NULL, &entry);
		dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &prop_method);
		dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &manual_method);
		dbus_message_iter_close_container(&dict, &entry);

		if (strlen(ipaddress) >= NETPM_IPV4_STR_LEN_MIN) {
			dbus_message_iter_open_container(&dict, DBUS_TYPE_DICT_ENTRY, NULL, &entry);
			dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &prop_address);
			dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &ipaddress);
			dbus_message_iter_close_container(&dict, &entry);
		}

		if (strlen(netmask) >= NETPM_IPV4_STR_LEN_MIN) {
			dbus_message_iter_open_container(&dict, DBUS_TYPE_DICT_ENTRY, NULL, &entry);
			dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &prop_netmask);
			dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &netmask);
			dbus_message_iter_close_container(&dict, &entry);
		}

		if (strlen(gateway) >= NETPM_IPV4_STR_LEN_MIN) {
			dbus_message_iter_open_container(&dict, DBUS_TYPE_DICT_ENTRY, NULL, &entry);
			dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &prop_gateway);
			dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &gateway);
			dbus_message_iter_close_container(&dict, &entry);
		}
		NETWORK_LOG(NETWORK_ASSERT,  "DBus Message 2/2 : %s %s %s %s %s %s %s %s\n",
				prop_method, manual_method, prop_address, ipaddress,
				prop_netmask, netmask, prop_gateway, gateway);
	} else {
		NETWORK_LOG(NETWORK_ASSERT,  "Error!!! Invalid argument\n");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_INVALID_PARAM;
	}

	dbus_message_iter_close_container(&variant, &dict);
	dbus_message_iter_close_container(&itr, &variant);

	dbus_error_init(&error);

	reply = dbus_connection_send_with_reply_and_block(conn,
			msg, DBUS_REPLY_TIMEOUT,			
			&error);

	if (reply == NULL) {
		if (dbus_error_is_set (&error) == TRUE) {
			NETWORK_LOG(NETWORK_ERROR,
				"Error!!! dbus_connection_send_with_reply_and_block() failed, Error[%s: %s]\n",
				error.name,
				error.message);
			Error = __net_error_string_to_enum(error.name);
			dbus_error_free(&error); 
			dbus_message_unref(msg);
			__NETWORK_FUNC_EXIT__;
			return Error;
		}

		dbus_message_unref(msg);
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_UNKNOWN;
	}

	dbus_message_unref(reply);
	dbus_message_unref(msg);

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

	DBusMessage *msg = NULL;
	DBusMessage *reply = NULL;
	DBusMessageIter itr;
	DBusConnection* conn = NULL;
	int i = 0;

	if ((prof_info == NULL) || (profile_name == NULL) || (strlen(profile_name) == 0) ||
	    (prof_info->ProfileInfo.Wlan.net_info.DnsCount > NET_DNS_ADDR_MAX))	{
		NETWORK_LOG(NETWORK_ASSERT,  "Error!!! Invalid parameter\n");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_INVALID_PARAM;
	}

	for (i = 0;i < prof_info->ProfileInfo.Wlan.net_info.DnsCount;i++) {
		dns_buffer[i][0] = '\0';
		dns_address[i] = NULL;
		
		snprintf(dns_buffer[i],  NETPM_IPV4_STR_LEN_MAX + 1, "%s",
				inet_ntoa(prof_info->ProfileInfo.Wlan.net_info.DnsAddr[i].Data.Ipv4));
		if (strlen(dns_buffer[i]) >= NETPM_IPV4_STR_LEN_MIN)
			dns_address[i] = dns_buffer[i];
	}
	
	conn = dbus_bus_get(DBUS_BUS_SYSTEM, NULL); 
	if (conn == NULL) {
		NETWORK_LOG(NETWORK_ERROR,  "Error!!! Can't get on system bus\n");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_UNKNOWN;
	}

	if (prof_info->ProfileInfo.Wlan.net_info.IpConfigType == NET_IP_CONFIG_TYPE_STATIC) {
		msg = dbus_message_new_method_call(CONNMAN_SERVICE,
				profile_name, CONNMAN_SERVICE_INTERFACE, "SetProperty");

		if (msg == NULL) {
			NETWORK_LOG(NETWORK_ERROR,
					"Error!!! dbus_message_new_method_call() failed\n");
			__NETWORK_FUNC_EXIT__;
			return NET_ERR_UNKNOWN;
		}

		dbus_message_iter_init_append(msg, &itr);
		dbus_message_iter_append_basic(&itr, DBUS_TYPE_STRING, &prop_nameserver_configuration);

		DBusMessageIter value, array;
		dbus_message_iter_open_container(&itr, DBUS_TYPE_VARIANT,
				DBUS_TYPE_ARRAY_AS_STRING DBUS_TYPE_STRING_AS_STRING, &value);

		dbus_message_iter_open_container(&value, DBUS_TYPE_ARRAY,
				DBUS_TYPE_STRING_AS_STRING, &array);

		for (i = 0;i < prof_info->ProfileInfo.Wlan.net_info.DnsCount;i++) {
			dbus_message_iter_append_basic(&array, DBUS_TYPE_STRING, &(dns_address[i]));
		}

		dbus_message_iter_close_container(&value, &array);
		dbus_message_iter_close_container(&itr, &value);

		dbus_error_init(&error);

		reply = dbus_connection_send_with_reply_and_block(conn,
				msg, DBUS_REPLY_TIMEOUT,
				&error);

		if (reply == NULL) {
			if (dbus_error_is_set (&error) == TRUE) {
				NETWORK_LOG(NETWORK_ERROR,
						"Error!!! dbus_connection_send_with_reply_and_block() failed, Error[%s: %s]\n",
						error.name,
						error.message);
				Error = __net_error_string_to_enum(error.name);
				dbus_error_free(&error);
				dbus_message_unref(msg);
				__NETWORK_FUNC_EXIT__;
				return Error;
			}
			dbus_message_unref(msg);
			__NETWORK_FUNC_EXIT__;
			return NET_ERR_UNKNOWN;
		}
		dbus_message_unref(reply);
		dbus_message_unref(msg);
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
	
	const char *direct_method = "direct"; /* not method[] as gcc screws it with dbus */
	const char *auto_method = "auto"; /* not method[] as gcc screws it with dbus */
	const char *manual_method = "manual"; /* not method[] as gcc screws it with dbus */

	const char *prop_proxy_configuration = "Proxy.Configuration";
	const char *prop_method = "Method";
	const char *prop_url = "URL";
	const char *prop_servers = "Servers";

	char proxy_buffer[NET_PROXY_LEN_MAX+1] = "";
	char *proxy_address = proxy_buffer;

	DBusMessage *msg = NULL;
	DBusMessage *reply = NULL;
	DBusMessageIter itr, variant, dict, entry, sub_variant, str_array;
	DBusConnection* conn = NULL;

	snprintf(proxy_buffer, NET_PROXY_LEN_MAX + 1, "%s", prof_info->ProfileInfo.Wlan.net_info.ProxyAddr);

	NETWORK_LOG(NETWORK_ASSERT, "Method : %d, proxy address : %s\n",
			prof_info->ProfileInfo.Wlan.net_info.ProxyMethod, proxy_address);

	if ((prof_info == NULL) || (profile_name == NULL) || (strlen(profile_name) == 0)) {
		NETWORK_LOG(NETWORK_ASSERT,  "Error!!! Invalid argument\n");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_INVALID_PARAM;
	}

	conn = dbus_bus_get(DBUS_BUS_SYSTEM, NULL); 
	if (conn == NULL) {
		NETWORK_LOG(NETWORK_ERROR,  "Error!!! Can't get on system bus\n");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_UNKNOWN;
	}

	/** Send proxy method, url, servers configuration */
	msg = dbus_message_new_method_call(CONNMAN_SERVICE, profile_name,
			CONNMAN_SERVICE_INTERFACE, "SetProperty");
	if (msg == NULL) {
		NETWORK_LOG(NETWORK_ERROR,  "Error!!! dbus_message_new_method_call() failed\n");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_UNKNOWN;
	}

	dbus_message_iter_init_append(msg, &itr);
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

	if (prof_info->ProfileInfo.Wlan.net_info.ProxyMethod == NET_PROXY_TYPE_AUTO) {
		dbus_message_iter_open_container(&dict, DBUS_TYPE_DICT_ENTRY, NULL, &entry);
		dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &prop_url);
		
		dbus_message_iter_open_container(&entry, DBUS_TYPE_VARIANT,
				DBUS_TYPE_STRING_AS_STRING, &sub_variant);
		dbus_message_iter_append_basic(&sub_variant, DBUS_TYPE_STRING, &proxy_address);
		
		dbus_message_iter_close_container(&entry, &sub_variant);
		dbus_message_iter_close_container(&dict, &entry);		
	}

	if (prof_info->ProfileInfo.Wlan.net_info.ProxyMethod == NET_PROXY_TYPE_MANUAL) {
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
			msg, DBUS_REPLY_TIMEOUT,			
			&error);

	if (reply == NULL) {
		if (dbus_error_is_set(&error) == TRUE) {
			NETWORK_LOG( NETWORK_ERROR,
					"Error!!! dbus_connection_send_with_reply_and_block() failed, Error[%s: %s]\n",
					error.name,
					error.message);
			Error = __net_error_string_to_enum(error.name);
			dbus_error_free(&error); 
			dbus_message_unref(msg);
			__NETWORK_FUNC_EXIT__;
			return Error;
		}

		dbus_message_unref(msg);
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_UNKNOWN;
	}

	dbus_message_unref(reply);
	dbus_message_unref(msg);

	NETWORK_LOG( NETWORK_HIGH, "Successfully configured Proxy.Configuration\n");
	
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

	char buff_svc_type[10] = "";
	char buff_auth_type[10] = "";
	char *temp_ptr = NULL;

	DBusMessage *msg = NULL;
	DBusMessage *reply = NULL;
	DBusMessageIter iter, dict, entry;
	DBusConnection* conn = NULL;

	if (prof_info == NULL) {
		NETWORK_LOG(NETWORK_ASSERT, "Error!!! Invalid argument\n");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_INVALID_PARAM;
	}

	conn = dbus_bus_get(DBUS_BUS_SYSTEM, NULL);
	if (conn == NULL) {
		NETWORK_LOG(NETWORK_ERROR, "Error!!! Can't get on system bus\n");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_UNKNOWN;
	}

	/** Create message */
	msg = dbus_message_new_method_call(TELEPHONY_SERVCE,
			TELEPHONY_MASTER_PATH, TELEPHONY_MASTER_INTERFACE, "AddProfile");
	if (msg == NULL) {
		NETWORK_LOG(NETWORK_ERROR, "Error!!! dbus_message_new_method_call() failed\n");
		dbus_connection_unref(conn);
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_UNKNOWN;
	}

	NETWORK_LOG(NETWORK_ASSERT, "DBus Message 1/2 : %s %s %s %s\n", TELEPHONY_SERVCE,
			TELEPHONY_MASTER_PATH, TELEPHONY_MASTER_INTERFACE, ".AddProfile");

	dbus_message_iter_init_append(msg, &iter);

	dbus_message_iter_open_container
		(&iter, DBUS_TYPE_ARRAY,
		 (DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
		  DBUS_TYPE_STRING_AS_STRING
		  DBUS_TYPE_STRING_AS_STRING
		  DBUS_DICT_ENTRY_END_CHAR_AS_STRING),
		 &dict);

	if (prof_info->ProfileInfo.Pdp.ServiceType > NET_SERVICE_UNKNOWN &&
	    prof_info->ProfileInfo.Pdp.ServiceType <= NET_SERVICE_PREPAID_MMS) {
		snprintf(buff_svc_type, 10, "%d", prof_info->ProfileInfo.Pdp.ServiceType);
		temp_ptr = buff_svc_type;

		dbus_message_iter_open_container(&dict, DBUS_TYPE_DICT_ENTRY, NULL, &entry);
		dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &service_type);
		dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &temp_ptr);
		dbus_message_iter_close_container(&dict, &entry);

		NETWORK_LOG(NETWORK_ASSERT, "DBus Message 2/2 : %s : %s\n",
				service_type, temp_ptr);
	}

	if (strlen(prof_info->ProfileInfo.Pdp.HomeURL) > 0) {
		temp_ptr = prof_info->ProfileInfo.Pdp.HomeURL;

		dbus_message_iter_open_container(&dict, DBUS_TYPE_DICT_ENTRY, NULL, &entry);
		dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &home_url);
		dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &temp_ptr);
		dbus_message_iter_close_container(&dict, &entry);

		NETWORK_LOG(NETWORK_ASSERT, "DBus Message 2/2 : %s : %s\n",
				home_url, temp_ptr);
	}

	if (strlen(prof_info->ProfileInfo.Pdp.net_info.ProxyAddr) > 0) {
		temp_ptr = prof_info->ProfileInfo.Pdp.net_info.ProxyAddr;

		dbus_message_iter_open_container(&dict, DBUS_TYPE_DICT_ENTRY, NULL, &entry);
		dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &proxy_addr);
		dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &temp_ptr);
		dbus_message_iter_close_container(&dict, &entry);

		NETWORK_LOG(NETWORK_ASSERT, "DBus Message 2/2 : %s : %s\n",
				proxy_addr, temp_ptr);
	}

	if (strlen(prof_info->ProfileInfo.Pdp.AuthInfo.Password) > 0) {
		temp_ptr = prof_info->ProfileInfo.Pdp.AuthInfo.Password;

		dbus_message_iter_open_container(&dict, DBUS_TYPE_DICT_ENTRY, NULL, &entry);
		dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &auth_pwd);
		dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &temp_ptr);
		dbus_message_iter_close_container(&dict, &entry);

		NETWORK_LOG(NETWORK_ASSERT, "DBus Message 2/2 : %s : %s\n",
				auth_pwd, temp_ptr);
	}

	if (strlen(prof_info->ProfileInfo.Pdp.AuthInfo.UserName) > 0) {
		temp_ptr = prof_info->ProfileInfo.Pdp.AuthInfo.UserName;

		dbus_message_iter_open_container(&dict, DBUS_TYPE_DICT_ENTRY, NULL, &entry);
		dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &auth_id);
		dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &temp_ptr);
		dbus_message_iter_close_container(&dict, &entry);

		NETWORK_LOG(NETWORK_ASSERT, "DBus Message 2/2 : %s : %s\n",
				auth_id, temp_ptr);
	}

	if (prof_info->ProfileInfo.Pdp.AuthInfo.AuthType >= NET_PDP_AUTH_NONE &&
	    prof_info->ProfileInfo.Pdp.AuthInfo.AuthType <= NET_PDP_AUTH_CHAP) {
		snprintf(buff_auth_type, 10, "%d", prof_info->ProfileInfo.Pdp.AuthInfo.AuthType);
		temp_ptr = buff_auth_type;

		dbus_message_iter_open_container(&dict, DBUS_TYPE_DICT_ENTRY, NULL, &entry);
		dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &auth_type);
		dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &temp_ptr);
		dbus_message_iter_close_container(&dict, &entry);

		NETWORK_LOG(NETWORK_ASSERT, "DBus Message 2/2 : %s : %s\n",
				auth_type, temp_ptr);
	}

	if (strlen(prof_info->ProfileInfo.Pdp.Apn) > 0) {
		temp_ptr = prof_info->ProfileInfo.Pdp.Apn;

		dbus_message_iter_open_container(&dict, DBUS_TYPE_DICT_ENTRY, NULL, &entry);
		dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &apn);
		dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &temp_ptr);
		dbus_message_iter_close_container(&dict, &entry);

		NETWORK_LOG(NETWORK_ASSERT, "DBus Message 2/2 : %s : %s\n",
				apn, temp_ptr);
	}

	dbus_message_iter_close_container(&iter, &dict);
	dbus_error_init(&error);

	/** Send message */
	reply = dbus_connection_send_with_reply_and_block(conn,
			msg, DBUS_REPLY_TIMEOUT,
			&error);

	/** Check Error */
	if (reply == NULL) {
		if (dbus_error_is_set (&error) == TRUE) {
			NETWORK_LOG(NETWORK_ERROR,
				"Error!!! dbus_connection_send_with_reply_and_block() failed, Error[%s: %s]\n",
				error.name,
				error.message);
			Error = __net_error_string_to_enum(error.name);
			dbus_error_free(&error);
			dbus_message_unref(msg);
			__NETWORK_FUNC_EXIT__;
			return Error;
		}

		dbus_message_unref(msg);
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
	dbus_message_unref(msg);
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

	char buff_svc_type[10] = "";
	char buff_auth_type[10] = "";
	char *temp_ptr = NULL;

	DBusMessage *msg = NULL;
	DBusMessage *reply = NULL;
	DBusMessageIter iter, dict, entry;
	DBusConnection* conn = NULL;

	if ((prof_info == NULL) || (profile_name == NULL)) {
		NETWORK_LOG(NETWORK_ASSERT, "Error!!! Invalid argument\n");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_INVALID_PARAM;
	}

	conn = dbus_bus_get(DBUS_BUS_SYSTEM, NULL);
	if (conn == NULL) {
		NETWORK_LOG(NETWORK_ERROR, "Error!!! Can't get on system bus\n");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_UNKNOWN;
	}

	/** Create message */
	msg = dbus_message_new_method_call(TELEPHONY_SERVCE,
			profile_name, TELEPHONY_PROFILE_INTERFACE, "ModifyProfile");
	if (msg == NULL) {
		NETWORK_LOG(NETWORK_ERROR, "Error!!! dbus_message_new_method_call() failed\n");
		dbus_connection_unref(conn);
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_UNKNOWN;
	}

	NETWORK_LOG(NETWORK_ASSERT, "DBus Message 1/2 : %s %s %s %s\n", TELEPHONY_SERVCE,
			profile_name, TELEPHONY_PROFILE_INTERFACE, ".ModifyProfile");

	dbus_message_iter_init_append(msg, &iter);

	dbus_message_iter_open_container
		(&iter, DBUS_TYPE_ARRAY,
		 (DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
		  DBUS_TYPE_STRING_AS_STRING
		  DBUS_TYPE_STRING_AS_STRING
		  DBUS_DICT_ENTRY_END_CHAR_AS_STRING),
		 &dict);

	if (prof_info->ProfileInfo.Pdp.ServiceType > NET_SERVICE_UNKNOWN &&
	    prof_info->ProfileInfo.Pdp.ServiceType <= NET_SERVICE_PREPAID_MMS) {
		snprintf(buff_svc_type, 10, "%d", prof_info->ProfileInfo.Pdp.ServiceType);
		temp_ptr = buff_svc_type;

		dbus_message_iter_open_container(&dict, DBUS_TYPE_DICT_ENTRY, NULL, &entry);
		dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &service_type);
		dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &temp_ptr);
		dbus_message_iter_close_container(&dict, &entry);

		NETWORK_LOG(NETWORK_ASSERT, "DBus Message 2/2 : %s : %s\n",
				service_type, temp_ptr);
	}

	if (strlen(prof_info->ProfileInfo.Pdp.HomeURL) > 0) {
		temp_ptr = prof_info->ProfileInfo.Pdp.HomeURL;

		dbus_message_iter_open_container(&dict, DBUS_TYPE_DICT_ENTRY, NULL, &entry);
		dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &home_url);
		dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &temp_ptr);
		dbus_message_iter_close_container(&dict, &entry);

		NETWORK_LOG(NETWORK_ASSERT, "DBus Message 2/2 : %s : %s\n",
				home_url, temp_ptr);
	}

	if (strlen(prof_info->ProfileInfo.Pdp.net_info.ProxyAddr) > 0) {
		temp_ptr = prof_info->ProfileInfo.Pdp.net_info.ProxyAddr;

		dbus_message_iter_open_container(&dict, DBUS_TYPE_DICT_ENTRY, NULL, &entry);
		dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &proxy_addr);
		dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &temp_ptr);
		dbus_message_iter_close_container(&dict, &entry);

		NETWORK_LOG(NETWORK_ASSERT, "DBus Message 2/2 : %s : %s\n",
				proxy_addr, temp_ptr);
	}

	if (strlen(prof_info->ProfileInfo.Pdp.AuthInfo.Password) > 0) {
		temp_ptr = prof_info->ProfileInfo.Pdp.AuthInfo.Password;

		dbus_message_iter_open_container(&dict, DBUS_TYPE_DICT_ENTRY, NULL, &entry);
		dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &auth_pwd);
		dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &temp_ptr);
		dbus_message_iter_close_container(&dict, &entry);

		NETWORK_LOG(NETWORK_ASSERT, "DBus Message 2/2 : %s : %s\n",
				auth_pwd, temp_ptr);
	}

	if (strlen(prof_info->ProfileInfo.Pdp.AuthInfo.UserName) > 0) {
		temp_ptr = prof_info->ProfileInfo.Pdp.AuthInfo.UserName;

		dbus_message_iter_open_container(&dict, DBUS_TYPE_DICT_ENTRY, NULL, &entry);
		dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &auth_id);
		dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &temp_ptr);
		dbus_message_iter_close_container(&dict, &entry);

		NETWORK_LOG(NETWORK_ASSERT, "DBus Message 2/2 : %s : %s\n",
				auth_id, temp_ptr);
	}

	if (prof_info->ProfileInfo.Pdp.AuthInfo.AuthType >= NET_PDP_AUTH_NONE &&
	    prof_info->ProfileInfo.Pdp.AuthInfo.AuthType <= NET_PDP_AUTH_CHAP) {
		snprintf(buff_auth_type, 10, "%d", prof_info->ProfileInfo.Pdp.AuthInfo.AuthType);
		temp_ptr = buff_auth_type;

		dbus_message_iter_open_container(&dict, DBUS_TYPE_DICT_ENTRY, NULL, &entry);
		dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &auth_type);
		dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &temp_ptr);
		dbus_message_iter_close_container(&dict, &entry);

		NETWORK_LOG(NETWORK_ASSERT, "DBus Message 2/2 : %s : %s\n",
				auth_type, temp_ptr);
	}

	if (strlen(prof_info->ProfileInfo.Pdp.Apn) > 0) {
		temp_ptr = prof_info->ProfileInfo.Pdp.Apn;

		dbus_message_iter_open_container(&dict, DBUS_TYPE_DICT_ENTRY, NULL, &entry);
		dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &apn);
		dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &temp_ptr);
		dbus_message_iter_close_container(&dict, &entry);

		NETWORK_LOG(NETWORK_ASSERT, "DBus Message 2/2 : %s : %s\n",
				apn, temp_ptr);
	}

	dbus_message_iter_close_container(&iter, &dict);
	dbus_error_init(&error);

	/** Send message */
	reply = dbus_connection_send_with_reply_and_block(conn,
			msg, DBUS_REPLY_TIMEOUT,
			&error);

	/** Check Error */
	if (reply == NULL) {
		if (dbus_error_is_set (&error) == TRUE) {
			NETWORK_LOG(NETWORK_ERROR,
				"Error!!! dbus_connection_send_with_reply_and_block() failed, Error[%s: %s]\n",
				error.name,
				error.message);
			Error = __net_error_string_to_enum(error.name);
			dbus_error_free(&error);
			dbus_message_unref(msg);
			__NETWORK_FUNC_EXIT__;
			return Error;
		}

		dbus_message_unref(msg);
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
	dbus_message_unref(msg);
	dbus_connection_unref(conn);

	__NETWORK_FUNC_EXIT__;
	return Error;
}


int _net_dbus_load_wifi_driver(void)
{
	__NETWORK_FUNC_ENTER__;

	net_err_t Error = NET_ERR_NONE;
	DBusConnection* conn = NULL;

	conn = dbus_bus_get(DBUS_BUS_SYSTEM, NULL);

	if (conn == NULL) {
		NETWORK_LOG(NETWORK_EXCEPTION, "Error!!! Can't get on system bus\n");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_UNKNOWN;
	}

	NETWORK_LOG(NETWORK_HIGH,  "Requesting [%s %s]\n",
			NETCONFIG_WIFI_PATH, NETCONFIG_WIFI_INTERFACE ".LoadDriver");

	Error = _net_invoke_dbus_method_nonblock(NETCONFIG_SERVICE, conn, NETCONFIG_WIFI_PATH,
			NETCONFIG_WIFI_INTERFACE, "LoadDriver", __net_wifi_power_reply);

	dbus_connection_unref(conn);

	__NETWORK_FUNC_EXIT__;
	return Error;
}

int _net_dbus_remove_wifi_driver(void)
{
	__NETWORK_FUNC_ENTER__;

	net_err_t Error = NET_ERR_NONE;
	DBusConnection* conn = NULL;

	conn = dbus_bus_get(DBUS_BUS_SYSTEM, NULL);

	if (conn == NULL) {
		NETWORK_LOG(NETWORK_EXCEPTION, "Error!!! Can't get on system bus\n");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_UNKNOWN;
	}

	NETWORK_LOG(NETWORK_HIGH,  "Requesting [%s %s]\n",
			NETCONFIG_WIFI_PATH, NETCONFIG_WIFI_INTERFACE ".RemoveDriver");

	Error = _net_invoke_dbus_method_nonblock(NETCONFIG_SERVICE, conn, NETCONFIG_WIFI_PATH,
			NETCONFIG_WIFI_INTERFACE, "RemoveDriver", __net_wifi_power_reply);

	dbus_connection_unref(conn);

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

#ifdef __cplusplus
}
#endif /* __cplusplus */
