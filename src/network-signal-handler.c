/*
 * Copyright 2012  Samsung Electronics Co., Ltd
 *
 * Licensed under the Flora License, Version 1.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.tizenopensource.org/license
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
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
static char* __net_get_property(DBusMessage* msg, char** property);
static int __net_handle_scan_rsp(DBusMessage* msg);
static int __net_handle_wifi_power_rsp(const char *state);
static int __net_svc_error_string_to_enum(const char *error);
static void __net_handle_svc_failure_ind(const char *profile_name, const char *svc_error);
static void __net_handle_state_ind(const char* profile_name, net_state_type_t profile_state);

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

static char* __net_get_property(DBusMessage* msg, char** property)
{
	DBusMessageIter args, variant;
	char* sigvalue = NULL;

	__NETWORK_FUNC_ENTER__;

	if (!dbus_message_iter_init(msg, &args))
	{
		NETWORK_LOG( NETWORK_LOW, "Message does not have parameters\n");
	}
	else if (dbus_message_iter_get_arg_type(&args) != DBUS_TYPE_STRING)
	{
		NETWORK_LOG( NETWORK_LOW, "Argument is not string\n");
	}
	else
	{
		dbus_message_iter_get_basic(&args, &sigvalue);
		dbus_message_iter_next(&args);
		dbus_message_iter_recurse(&args, &variant);
		if (dbus_message_iter_get_arg_type(&variant) == DBUS_TYPE_STRING)
			dbus_message_iter_get_basic(&variant, property);
		else
			*property = NULL;
	}

	__NETWORK_FUNC_EXIT__;
	return sigvalue;

}

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

static int __net_handle_wifi_power_rsp(const char *state)
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

	if (strcmp(state, "offline") == 0 && NetworkInfo.wifi_state != WIFI_OFF) {
		NetworkInfo.wifi_state = WIFI_OFF;
		wifi_state_flag = 1;
		event_data.Error = NET_ERR_NONE;

		if(request_table[NETWORK_REQUEST_TYPE_SCAN].flag == TRUE)
			memset(&request_table[NETWORK_REQUEST_TYPE_SCAN],
					0, sizeof(network_request_table_t));

	} else if (strcmp(state, "enabled") == 0 && NetworkInfo.wifi_state != WIFI_ON) {
		NetworkInfo.wifi_state = WIFI_ON;
		wifi_state_flag = 1;
		event_data.Error = NET_ERR_NONE;
		usleep(300000); /* This will be removed after connman upgrade */
	} else if (strcmp(state, "available") == 0 && NetworkInfo.wifi_state != WIFI_OFF) {
		NetworkInfo.wifi_state = WIFI_OFF;
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

static int __net_svc_error_string_to_enum(const char *error)
{
	if (strcmp(error, "out-of-range") == 0)
		return NET_ERR_CONNECTION_OUT_OF_RANGE;
	else if(strcmp(error, "pin-missing") == 0)
		return NET_ERR_CONNECTION_PIN_MISSING;
	else if(strcmp(error, "dhcp-failed") == 0)
		return NET_ERR_CONNECTION_DHCP_FAILED;
	else if(strcmp(error, "connect-failed") == 0)
		return NET_ERR_CONNECTION_CONNECT_FAILED;
	else if(strcmp(error, "login-failed") == 0)
		return NET_ERR_CONNECTION_LOGIN_FAILED;
	else if(strcmp(error, "auth-failed") == 0)
		return NET_ERR_CONNECTION_AUTH_FAILED;
	else if(strcmp(error, "invalid-key") == 0)
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
	    strcmp(profile_name, svc_name1) == 0) {

		memset(&request_table[NETWORK_REQUEST_TYPE_OPEN_CONNECTION], 0,
				sizeof(network_request_table_t));

		event_data.Event = NET_EVENT_OPEN_RSP;
		g_strlcpy(event_string, "Sending NET_EVENT_OPEN_RSP", 64);
	} else if (request_table[NETWORK_REQUEST_TYPE_ENROLL_WPS].flag == TRUE &&
	           strcmp(profile_name, svc_name2) == 0) {

		memset(&request_table[NETWORK_REQUEST_TYPE_ENROLL_WPS], 0,
				sizeof(network_request_table_t));

		event_data.Event = NET_EVENT_WIFI_WPS_RSP;
		g_strlcpy(event_string, "Sending NET_EVENT_WIFI_WPS_RSP", 64);
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
	
	char* sigvalue = NULL;
	net_event_info_t event_data = {0,};
	net_err_t Error = NET_ERR_NONE;
	net_device_t device_type = NET_DEVICE_UNKNOWN;
	
	if(msg == NULL)
	{
		NETWORK_LOG( NETWORK_LOW, "Invalid Message. Ignore\n");
		/* We have handled this message, don't pass it on */
		__NETWORK_FUNC_EXIT__;
		return DBUS_HANDLER_RESULT_HANDLED;
	}
				
	if (dbus_message_is_signal(msg, CONNMAN_MANAGER_INTERFACE, CONNMAN_SIGNAL_PROPERTY_CHANGED))
	{
		sigvalue = _net_get_string(msg);
		if(sigvalue == NULL)
		{
			/* We have handled this message, don't pass it on */
			__NETWORK_FUNC_EXIT__;
			return DBUS_HANDLER_RESULT_HANDLED;
		}
		NETWORK_LOG( NETWORK_LOW, "[Manager : PropertyChanged] Got Signal with value [%s]\n", sigvalue);

		if(strcmp(sigvalue, "Services") == 0)
		{
			/** Ignore - compared for future use */
		}
		else if(strcmp(sigvalue, "ConnectedTechnologies") == 0)
		{
			/** Ignore - compared for future use */
		}
		else if(strcmp(sigvalue, "State") == 0)
		{
			/** Ignore - compared for future use */
		}
		else if(strcmp(sigvalue, "DefaultTechnology") == 0)
		{
			/** Ignore - compared for future use */
		}
		else
		{
			NETWORK_LOG( NETWORK_LOW, "-------[Manager : PropertyChanged]--------\n");
		}

		/* We have handled this message, don't pass it on */
		__NETWORK_FUNC_EXIT__;
		return DBUS_HANDLER_RESULT_HANDLED;
	}
	else if (dbus_message_is_signal(msg, CONNMAN_MANAGER_INTERFACE, CONNMAN_SIGNAL_STATE_CHANGED))
	{
		sigvalue = _net_get_string(msg);
		if(sigvalue == NULL)
		{
			/* We have handled this message, don't pass it on */
			__NETWORK_FUNC_EXIT__;
			return DBUS_HANDLER_RESULT_HANDLED;
		}
		NETWORK_LOG( NETWORK_LOW, "[Manager : StateChanged] Got Signal with value [%s]\n", sigvalue);

		if(strcmp(sigvalue, "online") == 0)
		{
			/** Ignore - compared for future use */
		}

		/* We have handled this message, don't pass it on */
		__NETWORK_FUNC_EXIT__;
		return DBUS_HANDLER_RESULT_HANDLED;
	}
	else if (dbus_message_is_signal(msg, CONNMAN_MANAGER_INTERFACE, CONNMAN_SIGNAL_SCAN_COMPLETED))
	{
		__net_handle_scan_rsp(msg);

		/* We have handled this message, don't pass it on */
		__NETWORK_FUNC_EXIT__;
		return DBUS_HANDLER_RESULT_HANDLED;
	}
	else if (dbus_message_is_signal(msg, CONNMAN_TECHNOLOGY_INTERFACE, CONNMAN_SIGNAL_PROPERTY_CHANGED))
	{
		char* property = NULL;

		sigvalue = __net_get_property(msg, &property);
		if(sigvalue == NULL)
		{
			/* We have handled this message, don't pass it on */
			__NETWORK_FUNC_EXIT__;
			return DBUS_HANDLER_RESULT_HANDLED;
		}
		
		memset(ProfileName, 0, sizeof(ProfileName));
		_net_get_path(msg, ProfileName);

		NETWORK_LOG( NETWORK_LOW,
				"[Technology : PropertyChanged] Got Signal with value [%s] path [%s] state [%s]\n",
				sigvalue, ProfileName, property);

		if(strstr(ProfileName, "/wifi") == NULL)
		{
			__NETWORK_FUNC_EXIT__;
			return DBUS_HANDLER_RESULT_HANDLED;
		}

		if(strcmp(sigvalue, "State") == 0 && property != NULL)
		{
			__net_handle_wifi_power_rsp(property);
		}
		/* We have handled this message, don't pass it on */
		__NETWORK_FUNC_EXIT__;
		return DBUS_HANDLER_RESULT_HANDLED;
	}
	else if (dbus_message_is_signal(msg, CONNMAN_SERVICE_INTERFACE, CONNMAN_SIGNAL_PROPERTY_CHANGED))
	{
		sigvalue = _net_get_string(msg);
		if(sigvalue == NULL)
		{
			/* We have handled this message, don't pass it on */
			__NETWORK_FUNC_EXIT__;
			return DBUS_HANDLER_RESULT_HANDLED;
		}
		NETWORK_LOG( NETWORK_LOW, "[Service : PropertyChanged] Got Signal with value [%s]\n", sigvalue);

		if(strcmp(sigvalue, "Strength") == 0)
		{
			/** Ignore - compared for future use */
		}
		else if(strcmp(sigvalue, "PassphraseRequired") == 0)
		{
			/** Ignore - compared for future use */
		}
		else if(strcmp(sigvalue, "State") == 0)
		{
			memset(ProfileName, 0, sizeof(ProfileName));
			_net_get_path(msg, ProfileName);

			device_type = _net_get_tech_type_from_path(ProfileName);

			if(device_type == NET_DEVICE_UNKNOWN)
			{
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
		
			if(strcmp(svc_state, "idle") == 0)
			{
				service_state_table[device_type] = NET_STATE_TYPE_IDLE;
				__net_handle_state_ind(ProfileName, NET_STATE_TYPE_IDLE);
			}
			else if(strcmp(svc_state, "association") == 0)
			{
				service_state_table[device_type] = NET_STATE_TYPE_ASSOCIATION;
				__net_handle_state_ind(ProfileName, NET_STATE_TYPE_ASSOCIATION);
			}
			else if(strcmp(svc_state, "configuration") == 0)
			{
				service_state_table[device_type] = NET_STATE_TYPE_CONFIGURATION;
				__net_handle_state_ind(ProfileName, NET_STATE_TYPE_CONFIGURATION);
			}
			else if(strcmp(svc_state, "ready") == 0 ||
			        strcmp(svc_state, "online") == 0)
			{
				if(service_state_table[device_type] != NET_STATE_TYPE_READY &&
				   service_state_table[device_type] != NET_STATE_TYPE_ONLINE)
				{
					svc_name1 = request_table[NETWORK_REQUEST_TYPE_OPEN_CONNECTION].ProfileName;
					svc_name2 = request_table[NETWORK_REQUEST_TYPE_ENROLL_WPS].ProfileName;
					
					if(request_table[NETWORK_REQUEST_TYPE_OPEN_CONNECTION].flag == TRUE &&
					   strcmp(sig_path, svc_name1) == 0)
					{
						memset(&request_table[NETWORK_REQUEST_TYPE_OPEN_CONNECTION], 0,
								sizeof(network_request_table_t));

						event_data.Event =  NET_EVENT_OPEN_RSP;
						NETWORK_LOG( NETWORK_LOW, "Sending NET_EVENT_OPEN_RSP\n");
					}
					else if(request_table[NETWORK_REQUEST_TYPE_ENROLL_WPS].flag == TRUE &&
					   strcmp(sig_path, svc_name2) == 0)
					{
						memset(&request_table[NETWORK_REQUEST_TYPE_ENROLL_WPS], 0,
								sizeof(network_request_table_t));

						event_data.Event =  NET_EVENT_WIFI_WPS_RSP;
						NETWORK_LOG( NETWORK_LOW, "Sending NET_EVENT_WIFI_WPS_RSP\n");
					}
					else
					{
						event_data.Event =  NET_EVENT_OPEN_IND;
						NETWORK_LOG( NETWORK_LOW, "Sending NET_EVENT_OPEN_IND\n");
					}

					net_profile_info_t prof_info;
					if((Error = net_get_profile_info(ProfileName, &prof_info)) != NET_ERR_NONE)
					{
						NETWORK_LOG( NETWORK_ERROR, "Error!!! net_get_profile_info() failed [%s]\n",
								_net_print_error(Error));
						event_data.Datalength = 0;
						event_data.Data = NULL;
					}
					else
					{
						event_data.Datalength = sizeof(net_profile_info_t);
						event_data.Data = &prof_info;
					}

					event_data.Error = Error;
					snprintf(event_data.ProfileName, NET_PROFILE_NAME_LEN_MAX + 1, "%s", ProfileName);
					open_connection_rsp_sent = TRUE;
					_net_client_callback(&event_data);
				}
				else
				{
					if (strcmp(svc_state, "ready") == 0)
						__net_handle_state_ind(ProfileName, NET_STATE_TYPE_READY);
					else
						__net_handle_state_ind(ProfileName, NET_STATE_TYPE_ONLINE);
				}

				if (strcmp(svc_state, "ready") == 0)
					service_state_table[device_type] = NET_STATE_TYPE_READY;
				else
					service_state_table[device_type] = NET_STATE_TYPE_ONLINE;
			}
			else if(strcmp(svc_state, "disconnect") == 0)
			{
				svc_name1 = request_table[NETWORK_REQUEST_TYPE_CLOSE_CONNECTION].ProfileName;
				svc_name2 = request_table[NETWORK_REQUEST_TYPE_OPEN_CONNECTION].ProfileName;
				svc_name3 = request_table[NETWORK_REQUEST_TYPE_ENROLL_WPS].ProfileName;

				if(request_table[NETWORK_REQUEST_TYPE_OPEN_CONNECTION].flag == TRUE &&
				   strcmp(sig_path, svc_name2) == 0)
				{
					memset(&request_table[NETWORK_REQUEST_TYPE_OPEN_CONNECTION], 0,
							sizeof(network_request_table_t));

					/** Send Open Resp */
					event_data.Error = NET_ERR_OPERATION_ABORTED;
					event_data.Event =  NET_EVENT_OPEN_RSP;
					snprintf(event_data.ProfileName,
							NET_PROFILE_NAME_LEN_MAX+1, "%s", ProfileName);

					event_data.Datalength = 0;
					event_data.Data = NULL;
					NETWORK_LOG( NETWORK_LOW, "Sending NET_EVENT_OPEN_RSP\n");
					_net_client_callback(&event_data);
				}
				else if(request_table[NETWORK_REQUEST_TYPE_ENROLL_WPS].flag == TRUE &&
					strcmp(sig_path, svc_name3) == 0)
				{
					memset(&request_table[NETWORK_REQUEST_TYPE_ENROLL_WPS], 0,
							sizeof(network_request_table_t));

					/** Send WPS Resp */
					event_data.Error = NET_ERR_OPERATION_ABORTED;
					event_data.Event =  NET_EVENT_WIFI_WPS_RSP;
					snprintf(event_data.ProfileName,
							NET_PROFILE_NAME_LEN_MAX+1, "%s", ProfileName);

					event_data.Datalength = 0;
					event_data.Data = NULL;
					NETWORK_LOG( NETWORK_LOW, "Sending NET_EVENT_WIFI_WPS_RSP\n");
					_net_client_callback(&event_data);
				}
				else if(request_table[NETWORK_REQUEST_TYPE_CLOSE_CONNECTION].flag == TRUE &&
				   strcmp(sig_path, svc_name1) == 0)
				{
					memset(&request_table[NETWORK_REQUEST_TYPE_CLOSE_CONNECTION], 0, 
							sizeof(network_request_table_t));

					/** Send Close Resp */
					event_data.Error = Error;
					event_data.Event =  NET_EVENT_CLOSE_RSP;
					snprintf(event_data.ProfileName,
							NET_PROFILE_NAME_LEN_MAX+1, "%s", ProfileName);

					event_data.Datalength = 0;
					event_data.Data = NULL;
					NETWORK_LOG( NETWORK_LOW, "Sending NET_EVENT_CLOSE_RSP\n");
					_net_client_callback(&event_data);

				}
				else
				{
					/** Send Close Ind */
					event_data.Error = Error;
					event_data.Event =  NET_EVENT_CLOSE_IND;
					snprintf(event_data.ProfileName,
							NET_PROFILE_NAME_LEN_MAX+1, "%s", ProfileName);

					event_data.Datalength = 0;
					event_data.Data = NULL;
					NETWORK_LOG( NETWORK_LOW, "Sending NET_EVENT_CLOSE_IND\n");
					_net_client_callback(&event_data);
				}

				service_state_table[device_type] = NET_STATE_TYPE_DISCONNECT;
			}
			else if(strcmp(svc_state, "failure") == 0)
			{
				__net_handle_svc_failure_ind(sig_path, (char*)svc_error);
				service_state_table[device_type] = NET_STATE_TYPE_FAILURE;
				__NETWORK_FUNC_EXIT__;
				return DBUS_HANDLER_RESULT_HANDLED;
			}
		}
		else if(strcmp(sigvalue, "Nameservers") == 0)
		{
			/* We have handled this message, don't pass it on */
			__NETWORK_FUNC_EXIT__;
			return DBUS_HANDLER_RESULT_HANDLED;
		}
		else if(strcmp(sigvalue, "IPv4") == 0)
		{
			/** Ignore - compared for future use */
		}
		else if(strcmp(sigvalue, "Ethernet") == 0)
		{
			/** Ignore - compared for future use */
		}
		else if(strcmp(sigvalue, "Domains") == 0)
		{
			/** Ignore - compared for future use */
		}
		else if(strcmp(sigvalue, "IPv4.Configuration") == 0)
		{
			/** Ignore - compared for future use */
		}
		else
		{
			/** Ignore - compared for future use */
		}

		/* We have handled this message, don't pass it on */
		__NETWORK_FUNC_EXIT__;
		return DBUS_HANDLER_RESULT_HANDLED;
	}

	if (dbus_message_is_signal(msg, CONNMAN_COUNTER_INTERFACE, "Usage"))
	{
		NETWORK_LOG( NETWORK_LOW, "Received [COUNTER_USAGE_SIGNAL] signal from modman\n");
	}
	else if (dbus_message_is_signal(msg, CONNMAN_COUNTER_INTERFACE, "Release"))
	{
		NETWORK_LOG( NETWORK_LOW, "Received [COUNTER_RELEASE_SIGNAL] signal from modman\n");
	}

	NETWORK_LOG( NETWORK_LOW, "Useless signal. Ignored !!!\n");
	__NETWORK_FUNC_EXIT__;
	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

/*****************************************************************************
 * 	Global Functions
 *****************************************************************************/

int _net_deregister_signal(void)
{
	__NETWORK_FUNC_ENTER__;

	if (signal_conn == NULL) {
		NETWORK_LOG(NETWORK_HIGH, "Already de-registered. Nothing to be done\n");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_NONE;
	}

	dbus_connection_remove_filter(signal_conn, __net_signal_filter, NULL);
	NETWORK_LOG(NETWORK_HIGH, "dbus_connection_remove_filter() successful\n");
	NETWORK_LOG(NETWORK_LOW, "Successfully removed signal filter rules\n");

	/* If DBusPendingCall remains, it should be released */
	if (_net_dbus_is_pending_call_used() == TRUE)
	{
		dbus_pending_call_cancel(_net_dbus_get_pending_call());
		_net_dbus_set_pending_call(NULL);
		_net_dbus_set_pending_call_used(FALSE);
		NETWORK_LOG(NETWORK_HIGH, "DBus pending call successfully removed\n");
	}

	dbus_connection_unref(signal_conn);
	signal_conn = NULL;
	__NETWORK_FUNC_EXIT__;
	return NET_ERR_NONE;
}

int _net_register_signal(void)
{
	DBusConnection* conn = NULL;
	DBusError err;

	__NETWORK_FUNC_ENTER__;

	dbus_error_init(&err);
	conn = dbus_bus_get(DBUS_BUS_SYSTEM, NULL); 
	if (conn == NULL) {
		NETWORK_LOG(NETWORK_EXCEPTION, "Error!!! Failed to connect to the D-BUS daemon: [%s]\n", err.message);
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
		NETWORK_LOG(NETWORK_ERROR, "Error!!! Match Error (%s)\n", err.message);
		dbus_error_free(&err);
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_UNKNOWN;
	}

	dbus_bus_add_match(conn, CONNMAN_TECHNOLOGY_SIGNAL_FILTER, &err); 
	dbus_connection_flush(conn);
	if (dbus_error_is_set(&err)) {
		NETWORK_LOG(NETWORK_ERROR, "Error!!! Match Error (%s)\n", err.message);
		dbus_error_free(&err);
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_UNKNOWN;
	}

	dbus_bus_add_match(conn, CONNMAN_SERVICE_SIGNAL_FILTER, &err);
	dbus_connection_flush(conn);
	if (dbus_error_is_set(&err)) {
		NETWORK_LOG(NETWORK_ERROR, "Error!!! Match Error (%s)\n", err.message);
		dbus_error_free(&err);
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_UNKNOWN;
	}

	dbus_bus_add_match(conn, CONNMAN_NETWORK_COUNTER_FILTER, &err); 
	dbus_connection_flush(conn);
	if (dbus_error_is_set(&err)) {
		NETWORK_LOG(NETWORK_ERROR, "Error!!! Match Error (%s)\n", err.message);
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

	Error = net_get_network_status(NET_DEVICE_WIFI, &network_status);
	if (Error != NET_ERR_NONE) {
		__NETWORK_FUNC_EXIT__;
		return Error;
	}

	if (network_status == NET_STATUS_AVAILABLE)
		service_state_table[NET_DEVICE_WIFI] = NET_STATE_TYPE_READY;

	Error = net_get_network_status(NET_DEVICE_CELLULAR, &network_status);
	if (Error != NET_ERR_NONE) {
		__NETWORK_FUNC_EXIT__;
		return Error;
	}

	if (network_status == NET_STATUS_AVAILABLE)
		service_state_table[NET_DEVICE_CELLULAR] = NET_STATE_TYPE_READY;

	NETWORK_LOG(NETWORK_HIGH, "init service state table. wifi:%d, cellular:%d\n",
			service_state_table[NET_DEVICE_WIFI],
			service_state_table[NET_DEVICE_CELLULAR]);

	__NETWORK_FUNC_EXIT__;
	return NET_ERR_NONE;
}

#ifdef __cplusplus
}
#endif /* __cplusplus */
