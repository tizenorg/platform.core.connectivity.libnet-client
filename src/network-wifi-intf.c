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

#include "network-internal.h"
#include "network-dbus-request.h"
#include "network-signal-handler.h"

/*****************************************************************************
 * 	Macros and Typedefs
 *****************************************************************************/

/*****************************************************************************
 * 	Local Functions Declaration
 *****************************************************************************/

static net_wifi_state_t __net_get_wifi_service_state();

/*****************************************************************************
 * 	Global Functions
 *****************************************************************************/

/*****************************************************************************
 * 	Extern Variables
 *****************************************************************************/

extern network_info_t NetworkInfo;
extern network_request_table_t request_table[NETWORK_REQUEST_TYPE_MAX];

/*****************************************************************************
 * 	Global Variables
 *****************************************************************************/

/*****************************************************************************
 * 	Local Functions Definition
 *****************************************************************************/

static net_wifi_state_t __net_get_wifi_service_state(char *profile_name)
{
	__NETWORK_FUNC_ENTER__;

	net_err_t Error = NET_ERR_NONE;
	net_wifi_state_t wifi_state = NetworkInfo.wifi_state;
	int profile_count = 0;
	int i = 0;
	net_profile_info_t* profile_info = NULL;

	Error = _net_get_profile_list(NET_DEVICE_WIFI, &profile_info, &profile_count);

	if (Error != NET_ERR_NONE) {
		NETWORK_LOG(NETWORK_ERROR,
				"Failed to get service(profile) list. Error [%s]\n",
				_net_print_error(Error));

		NET_MEMFREE(profile_info);

		__NETWORK_FUNC_EXIT__;
		return wifi_state;
	}

	for (i = 0;i < profile_count;i++) {
		switch (profile_info->ProfileState) {
		case NET_STATE_TYPE_ASSOCIATION :
		case NET_STATE_TYPE_CONFIGURATION :
			wifi_state = WIFI_CONNECTING;
			g_strlcpy(profile_name, profile_info->ProfileName,
					sizeof(profile_info->ProfileName));
			break;
		case NET_STATE_TYPE_READY :
		case NET_STATE_TYPE_ONLINE :
			wifi_state = WIFI_CONNECTED;
			g_strlcpy(profile_name, profile_info->ProfileName,
					sizeof(profile_info->ProfileName));
			break;
		case NET_STATE_TYPE_UNKNOWN :
		case NET_STATE_TYPE_IDLE :
		case NET_STATE_TYPE_FAILURE :
		case NET_STATE_TYPE_DISCONNECT :
			break;
		}
		profile_info++;
	}

	if (wifi_state == WIFI_CONNECTED &&
	    request_table[NETWORK_REQUEST_TYPE_CLOSE_CONNECTION].flag == TRUE)
		wifi_state = WIFI_DISCONNECTING;

	__NETWORK_FUNC_EXIT__;
	return wifi_state;
}

/*****************************************************************************
 * 	ConnMan Wi-Fi Client Interface Async API Definition
 *****************************************************************************/
EXPORT_API int net_specific_scan_wifi(const char *ssid)
{
	__NETWORK_FUNC_ENTER__;

	net_err_t Error = NET_ERR_NONE;

	if (ssid == NULL) {
		NETWORK_LOG(NETWORK_ERROR, "Invalid parameter\n");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_INVALID_PARAM;
	}

	if (g_atomic_int_get(&NetworkInfo.ref_count) == 0) {
		NETWORK_LOG(NETWORK_ERROR, "Application is not registered\n");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_APP_NOT_REGISTERED;
	}

	if (request_table[NETWORK_REQUEST_TYPE_SPECIFIC_SCAN].flag == TRUE) {
		NETWORK_LOG(NETWORK_ERROR, "Find hidden AP request in progress\n");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_IN_PROGRESS;
	}

	if (_net_get_wifi_state() != WIFI_ON) {
		NETWORK_LOG(NETWORK_ERROR, "Wi-Fi is powered off!\n");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_INVALID_OPERATION;
	}

	if (_net_dbus_is_pending_call_used() == TRUE) {
		NETWORK_LOG(NETWORK_ERROR, "pending call in progress\n");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_INVALID_OPERATION;
	}

	request_table[NETWORK_REQUEST_TYPE_SPECIFIC_SCAN].flag = TRUE;

	Error = _net_dbus_specific_scan_request(ssid);
	if (Error != NET_ERR_NONE) {
		NETWORK_LOG(NETWORK_ERROR,
				"_net_dbus_specific_scan_request() failed. Error [%s]\n",
				_net_print_error(Error));

		memset(&request_table[NETWORK_REQUEST_TYPE_SPECIFIC_SCAN], 0,
				sizeof(network_request_table_t));
	}

	__NETWORK_FUNC_EXIT__;
	return Error;
}

EXPORT_API int net_open_connection_with_wifi_info(const net_wifi_connection_info_t *wifi_info)
{
	__NETWORK_FUNC_ENTER__;

	net_err_t Error = NET_ERR_NONE;

	if (wifi_info == NULL) {
		NETWORK_LOG(NETWORK_ERROR, "Invalid parameter\n");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_INVALID_PARAM;
	}

	if (g_atomic_int_get(&NetworkInfo.ref_count) == 0) {
		NETWORK_LOG(NETWORK_ERROR, "Application is not registered\n");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_APP_NOT_REGISTERED;
	}

	if (request_table[NETWORK_REQUEST_TYPE_OPEN_CONNECTION].flag == TRUE) {
		NETWORK_LOG(NETWORK_ERROR, "Connection open request in progress\n");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_IN_PROGRESS;
	}

	if (_net_get_wifi_state() != WIFI_ON) {
		NETWORK_LOG(NETWORK_ERROR, "Wi-Fi is powered off!\n");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_INVALID_OPERATION;
	}

	if (_net_dbus_is_pending_call_used() == TRUE) {
		NETWORK_LOG(NETWORK_ERROR, "pending call in progress\n");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_INVALID_OPERATION;
	}

	request_table[NETWORK_REQUEST_TYPE_OPEN_CONNECTION].flag = TRUE;

	Error = _net_open_connection_with_wifi_info(wifi_info);
	if (Error != NET_ERR_NONE) {
		NETWORK_LOG(NETWORK_ERROR,
				"net_open_connection_with_wifi_info() failed. Error [%s]\n",
				_net_print_error(Error));

		memset(&request_table[NETWORK_REQUEST_TYPE_OPEN_CONNECTION], 0,
				sizeof(network_request_table_t));

		__NETWORK_FUNC_EXIT__;
		return Error;
	}

	__NETWORK_FUNC_EXIT__;
	return NET_ERR_NONE;
}

EXPORT_API int net_wifi_power_on(void)
{
	__NETWORK_FUNC_ENTER__;

	net_err_t Error = NET_ERR_NONE;
	int hotspot_state = 0;

	if (g_atomic_int_get(&NetworkInfo.ref_count) == 0) {
		NETWORK_LOG(NETWORK_ERROR, "Application is not registered\n");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_APP_NOT_REGISTERED;
	}

	vconf_get_int(VCONFKEY_MOBILE_HOTSPOT_MODE, &hotspot_state);
	if (hotspot_state & VCONFKEY_MOBILE_HOTSPOT_MODE_WIFI) {
		NETWORK_LOG(NETWORK_ERROR, "Wi-Fi hotspot is enabled!\n");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_INVALID_OPERATION;
	}

	if (NetworkInfo.wifi_state != WIFI_OFF) {
		NETWORK_LOG(NETWORK_ERROR, "Wi-Fi is powered on already!\n");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_INVALID_OPERATION;
	}

	if (request_table[NETWORK_REQUEST_TYPE_WIFI_POWER].flag == TRUE) {
		NETWORK_LOG(NETWORK_ERROR, "Request in progress\n");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_IN_PROGRESS;
	}

	if (_net_dbus_is_pending_call_used() == TRUE) {
		NETWORK_LOG(NETWORK_ERROR, "Error!! pending call already in progress\n");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_INVALID_OPERATION;
	}

	request_table[NETWORK_REQUEST_TYPE_WIFI_POWER].flag = TRUE;

	Error = _net_dbus_load_wifi_driver();
	if (Error != NET_ERR_NONE) {
		NETWORK_LOG(NETWORK_ERROR,
				"Failed to request Wi-Fi power on/off. Error [%s]\n",
				_net_print_error(Error));

		memset(&request_table[NETWORK_REQUEST_TYPE_WIFI_POWER], 0,
				sizeof(network_request_table_t));

		__NETWORK_FUNC_EXIT__;
		return Error;
	}

	NETWORK_LOG(NETWORK_HIGH, "Sent driver load request successfully\n");

	__NETWORK_FUNC_EXIT__;
	return NET_ERR_NONE;
}

EXPORT_API int net_wifi_power_off(void)
{
	__NETWORK_FUNC_ENTER__;

	net_err_t Error = NET_ERR_NONE;

	if(g_atomic_int_get(&NetworkInfo.ref_count) == 0) {
		NETWORK_LOG(NETWORK_ERROR, "Application is not registered\n");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_APP_NOT_REGISTERED;
	}

	if(NetworkInfo.wifi_state == WIFI_OFF) {
		NETWORK_LOG(NETWORK_ERROR, "Wi-Fi is powered off already!\n");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_INVALID_OPERATION;
	}

	if (request_table[NETWORK_REQUEST_TYPE_WIFI_POWER].flag == TRUE) {
		NETWORK_LOG(NETWORK_ERROR, "Request in progress\n");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_IN_PROGRESS;
	}

	_net_dbus_clear_pending_call();
	memset(request_table, 0, sizeof(request_table));

	request_table[NETWORK_REQUEST_TYPE_WIFI_POWER].flag = TRUE;

	Error = _net_dbus_remove_wifi_driver();
	if (Error != NET_ERR_NONE ) {
		NETWORK_LOG(NETWORK_ERROR,
				"Failed to request Wi-Fi power on/off. Error [%s]\n",
				_net_print_error(Error));

		memset(&request_table[NETWORK_REQUEST_TYPE_WIFI_POWER], 0, sizeof(network_request_table_t));

		__NETWORK_FUNC_EXIT__;
		return Error;
	}

	NETWORK_LOG(NETWORK_HIGH, "Sent driver remove request successfully\n");

	__NETWORK_FUNC_EXIT__;
	return NET_ERR_NONE;
}

EXPORT_API int net_scan_wifi(void)
{
	__NETWORK_FUNC_ENTER__;

	net_err_t Error = NET_ERR_NONE;

	if (g_atomic_int_get(&NetworkInfo.ref_count) == 0) {
		NETWORK_LOG(NETWORK_ERROR, "Application is not registered\n");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_APP_NOT_REGISTERED;
	}

	if (request_table[NETWORK_REQUEST_TYPE_SCAN].flag == TRUE) {
		NETWORK_LOG(NETWORK_ERROR, "Request in progress\n");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_IN_PROGRESS;
	}

	if (_net_get_wifi_state() != WIFI_ON) {
		NETWORK_LOG(NETWORK_ERROR, "Wi-Fi powered off!\n");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_INVALID_OPERATION;
	}

	if (_net_dbus_is_pending_call_used() == TRUE) {
		if (request_table[NETWORK_REQUEST_TYPE_SCAN].flag == TRUE) {
			NETWORK_LOG(NETWORK_ERROR, "Pending call already in progress\n");
			__NETWORK_FUNC_EXIT__;
			return NET_ERR_IN_PROGRESS;
		} else {
			__NETWORK_FUNC_EXIT__;
			return NET_ERR_INVALID_OPERATION;
		}
	}

	request_table[NETWORK_REQUEST_TYPE_SCAN].flag = TRUE;

	Error = _net_dbus_scan_request();
	if (Error != NET_ERR_NONE) {
		NETWORK_LOG(NETWORK_ERROR, "Failed to request scan. Error [%s]\n",
				_net_print_error(Error));

		memset(&request_table[NETWORK_REQUEST_TYPE_SCAN], 0,
				sizeof(network_request_table_t));

		__NETWORK_FUNC_EXIT__;
		return Error;
	}

	NETWORK_LOG(NETWORK_HIGH, "Wi-Fi scan requested successfully\n");

	__NETWORK_FUNC_EXIT__;
	return NET_ERR_NONE;
}

EXPORT_API int net_wifi_enroll_wps(const char *profile_name, net_wifi_wps_info_t *wps_info)
{
	__NETWORK_FUNC_ENTER__;

	net_err_t Error = NET_ERR_NONE;

	if (_net_check_profile_name(profile_name) != NET_ERR_NONE) {
		NETWORK_LOG(NETWORK_ERROR, "Invalid profile name\n");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_INVALID_PARAM;
	}

	if (g_atomic_int_get(&NetworkInfo.ref_count) == 0) {
		NETWORK_LOG(NETWORK_ERROR, "Application is not registered\n");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_APP_NOT_REGISTERED;
	}

	if (request_table[NETWORK_REQUEST_TYPE_ENROLL_WPS].flag == TRUE) {
		NETWORK_LOG(NETWORK_ERROR, "Request in progress\n");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_IN_PROGRESS;
	}

	if (_net_get_wifi_state() != WIFI_ON) {
		NETWORK_LOG(NETWORK_ERROR, "Wi-Fi is powered off!\n");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_INVALID_OPERATION;
	}

	if (_net_dbus_is_pending_call_used() == TRUE) {
		NETWORK_LOG(NETWORK_ERROR, "pending call in progress\n");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_INVALID_OPERATION;
	}

	request_table[NETWORK_REQUEST_TYPE_ENROLL_WPS].flag = TRUE;
	g_strlcpy(request_table[NETWORK_REQUEST_TYPE_ENROLL_WPS].ProfileName,
			profile_name, NET_PROFILE_NAME_LEN_MAX+1);

	if (wps_info->type == WIFI_WPS_PBC) {
		Error = _net_dbus_open_connection(profile_name);
		if (Error != NET_ERR_NONE) {
			NETWORK_LOG(NETWORK_ERROR,
					"Failed to request open connection, Error [%s]\n",
					_net_print_error(Error));

			memset(&request_table[NETWORK_REQUEST_TYPE_ENROLL_WPS], 0,
					sizeof(network_request_table_t));

			__NETWORK_FUNC_EXIT__;
			return Error;
		}
	} else if(wps_info->type == WIFI_WPS_PIN) {
		// TODO: handle wps pin
	} else {
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_INVALID_PARAM;
	}

	__NETWORK_FUNC_EXIT__;
	return NET_ERR_NONE;
}

/*****************************************************************************
 * 	ConnMan Wi-Fi Client Interface Sync Function Definition
 *****************************************************************************/
EXPORT_API int net_get_wifi_state(net_wifi_state_t *current_state, net_profile_name_t *profile_name)
{
	__NETWORK_FUNC_ENTER__;

	net_wifi_state_t wifi_state;

	if (g_atomic_int_get(&NetworkInfo.ref_count) == 0) {
		NETWORK_LOG(NETWORK_ERROR, "Application is not registered\n");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_APP_NOT_REGISTERED;
	}

	if (profile_name == NULL) {
		NETWORK_LOG(NETWORK_ERROR, "profile_name is NULL\n");
		return NET_ERR_INVALID_PARAM;
	}

	memset(profile_name, 0, sizeof(net_profile_name_t));

	wifi_state = _net_get_wifi_state();

	if (wifi_state == WIFI_OFF) {
		*current_state = WIFI_OFF;
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_NONE;
	}

	*current_state = __net_get_wifi_service_state(profile_name->ProfileName);
	
	NETWORK_LOG(NETWORK_HIGH, "current state : %d, profile name : %s\n",
			*current_state, profile_name->ProfileName);

	__NETWORK_FUNC_EXIT__;
	return NET_ERR_NONE;
}

EXPORT_API int net_wifi_set_background_scan_mode(net_wifi_background_scan_mode_t scan_mode)
{
	__NETWORK_FUNC_ENTER__;

	net_err_t Error = NET_ERR_NONE;

	if (g_atomic_int_get(&NetworkInfo.ref_count) == 0) {
		NETWORK_LOG(NETWORK_ERROR, "Application is not registered\n");

		__NETWORK_FUNC_EXIT__;
		return NET_ERR_APP_NOT_REGISTERED;
	}

	if (_net_get_wifi_state() != WIFI_ON) {
		NETWORK_LOG(NETWORK_ERROR, "Wi-Fi is powered off!\n");

		__NETWORK_FUNC_EXIT__;
		return NET_ERR_INVALID_OPERATION;
	}

	NETWORK_LOG(NETWORK_HIGH, "BGScan Mode [%d]\n", scan_mode);

	if ((Error = _net_dbus_set_bgscan_mode(scan_mode)) != NET_ERR_NONE) {
		NETWORK_LOG(NETWORK_ERROR,
				"Failed to set bgscan mode. Error [%s]\n",
				_net_print_error(Error));

		__NETWORK_FUNC_EXIT__;
		return Error;
	}

	__NETWORK_FUNC_EXIT__;
	return NET_ERR_NONE;
}
