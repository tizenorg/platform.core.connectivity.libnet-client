/*
 * Network Client Library
 *
 * Copyright 2012 Samsung Electronics Co., Ltd
 *
 * Licensed under the Flora License, Version 1.1 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.tizenopensource.org/license
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#include <vconf.h>
#include <vconf-keys.h>

#include "network-internal.h"
#include "network-dbus-request.h"
#include "network-signal-handler.h"

/*****************************************************************************
 * 	Extern Variables
 *****************************************************************************/
extern __thread network_info_t NetworkInfo;
extern __thread network_request_table_t request_table[NETWORK_REQUEST_TYPE_MAX];

static int __net_check_get_privilege()
{
	__NETWORK_FUNC_ENTER__;

	net_err_t Error = NET_ERR_NONE;
	GVariant *message = NULL;

	message = _net_invoke_dbus_method(NETCONFIG_SERVICE, NETCONFIG_NETWORK_PATH,
			NETCONFIG_NETWORK_INTERFACE, "CheckGetPrivilege", NULL, &Error);
	if (message == NULL) {
		NETWORK_LOG(NETWORK_ERROR, "Failed to check get privilege");
		return Error;
	}

	g_variant_unref(message);

	return Error;
}

static int __net_check_profile_privilege()
{
	__NETWORK_FUNC_ENTER__;

	net_err_t Error = NET_ERR_NONE;
	GVariant *message = NULL;

	message = _net_invoke_dbus_method(NETCONFIG_SERVICE, NETCONFIG_NETWORK_PATH,
			NETCONFIG_NETWORK_INTERFACE, "CheckProfilePrivilege", NULL, &Error);
	if (message == NULL) {
		NETWORK_LOG(NETWORK_ERROR, "Failed to check profile privilege");
		return Error;
	}

	g_variant_unref(message);

	return Error;
}

/*****************************************************************************
 * 	Local Functions Definition
 *****************************************************************************/
static net_wifi_state_t __net_get_wifi_service_state(char *profile_name, net_err_t *net_error)
{
	int i = 0, profile_count = 0;
	net_err_t Error = NET_ERR_NONE;
	net_wifi_state_t wifi_state = NetworkInfo.wifi_state;
	net_profile_info_t *temp = NULL, *profile_info = NULL;

	__NETWORK_FUNC_ENTER__;
	Error = _net_get_profile_list(NET_DEVICE_WIFI, &profile_info, &profile_count);

	if (Error != NET_ERR_NONE) {
		NETWORK_LOG(NETWORK_ERROR, "Failed to get service list[%s]",
				_net_print_error(Error));

		NET_MEMFREE(profile_info);
		*net_error = Error;

		__NETWORK_FUNC_EXIT__;
		return wifi_state;
	}

	if (profile_count == 0) {
		wifi_state = WIFI_ON;
		NET_MEMFREE(profile_info);
		*net_error = Error;

		__NETWORK_FUNC_EXIT__;
		return wifi_state;
	}

	/* Assign 'profile_info' to 'temp' to free memory at the end */
	temp = profile_info;
	for (i = 0; i < profile_count; i++) {
		switch (profile_info->ProfileState) {
		case NET_STATE_TYPE_ASSOCIATION:
			wifi_state = WIFI_ASSOCIATION;
			g_strlcpy(profile_name, profile_info->ProfileName,
					sizeof(profile_info->ProfileName));
			break;
		case NET_STATE_TYPE_CONFIGURATION:
			wifi_state = WIFI_CONFIGURATION;
			g_strlcpy(profile_name, profile_info->ProfileName,
					sizeof(profile_info->ProfileName));
			break;
		case NET_STATE_TYPE_READY:
		case NET_STATE_TYPE_ONLINE:
			wifi_state = WIFI_CONNECTED;
			g_strlcpy(profile_name, profile_info->ProfileName,
					sizeof(profile_info->ProfileName));
			break;
		case NET_STATE_TYPE_UNKNOWN:
		case NET_STATE_TYPE_IDLE:
		case NET_STATE_TYPE_FAILURE:
		case NET_STATE_TYPE_DISCONNECT:
			break;
		}
		profile_info++;
	}

	if (wifi_state == WIFI_CONNECTED &&
	    request_table[NETWORK_REQUEST_TYPE_CLOSE_CONNECTION].flag == TRUE)
		wifi_state = WIFI_DISCONNECTING;

	NET_MEMFREE(temp);
	*net_error = Error;

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
		NETWORK_LOG(NETWORK_ERROR, "Invalid parameter");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_INVALID_PARAM;
	}

	if (NetworkInfo.ref_count < 1) {
		NETWORK_LOG(NETWORK_ERROR, "Application is not registered");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_APP_NOT_REGISTERED;
	}

	if (request_table[NETWORK_REQUEST_TYPE_SPECIFIC_SCAN].flag == TRUE) {
		NETWORK_LOG(NETWORK_ERROR, "Find hidden AP request in progress");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_IN_PROGRESS;
	}

	if (NetworkInfo.wifi_state == WIFI_OFF) {
		if ((NetworkInfo.wifi_state = _net_get_wifi_state(&Error)) == WIFI_OFF) {
			NETWORK_LOG(NETWORK_ERROR, "Wi-Fi is powered off!");
			__NETWORK_FUNC_EXIT__;
			return NET_ERR_INVALID_OPERATION;
		}
	}

	if (_net_dbus_is_pending_call_used() == TRUE) {
		NETWORK_LOG(NETWORK_ERROR, "pending call in progress");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_INVALID_OPERATION;
	}

	request_table[NETWORK_REQUEST_TYPE_SPECIFIC_SCAN].flag = TRUE;

	Error = _net_dbus_specific_scan_request(ssid);
	if (Error != NET_ERR_NONE) {
		NETWORK_LOG(NETWORK_ERROR,
				"_net_dbus_specific_scan_request() failed. Error [%s]",
				_net_print_error(Error));

		memset(&request_table[NETWORK_REQUEST_TYPE_SPECIFIC_SCAN], 0,
				sizeof(network_request_table_t));
	}

	__NETWORK_FUNC_EXIT__;
	return Error;
}

EXPORT_API int net_wps_scan_wifi(void)
{
	__NETWORK_FUNC_ENTER__;

	net_err_t Error = NET_ERR_NONE;

	if (NetworkInfo.ref_count < 1) {
		NETWORK_LOG(NETWORK_ERROR, "Application is not registered");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_APP_NOT_REGISTERED;
	}

	if (_net_dbus_is_pending_call_used() == TRUE) {
		NETWORK_LOG(NETWORK_ERROR, "pending call in progress");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_INVALID_OPERATION;
	}

	request_table[NETWORK_REQUEST_TYPE_WPS_SCAN].flag = TRUE;

	Error = _net_dbus_wps_scan_request();
	if (Error != NET_ERR_NONE) {
		NETWORK_LOG(NETWORK_ERROR,
				"_net_dbus_wps_scan_request() failed. Error [%s]",
				_net_print_error(Error));

		memset(&request_table[NETWORK_REQUEST_TYPE_WPS_SCAN], 0,
				sizeof(network_request_table_t));
	}

	__NETWORK_FUNC_EXIT__;
	return Error;
}
EXPORT_API int net_get_wps_pin(char **wps_pin)
{
	net_err_t error = NET_ERR_NONE;
	error = _net_dbus_get_wps_pin(wps_pin);

	if (error != NET_ERR_NONE)
		NETWORK_LOG(NETWORK_ERROR, "Failed to get wps pin : %d", error);

	return error;
}

EXPORT_API int net_wifi_get_passpoint(int *enabled)
{
	__NETWORK_FUNC_ENTER__;

	net_err_t Error = NET_ERR_NONE;

	if (NetworkInfo.ref_count < 1) {
		NETWORK_LOG(NETWORK_ERROR, "Application is not registered");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_APP_NOT_REGISTERED;
	}

	if (NetworkInfo.wifi_state == WIFI_OFF) {
		if ((NetworkInfo.wifi_state = _net_get_wifi_state(&Error)) == WIFI_OFF) {
			NETWORK_LOG(NETWORK_ERROR, "Wi-Fi is powered off!");
			__NETWORK_FUNC_EXIT__;
			return NET_ERR_INVALID_OPERATION;
		}
	}

	if (_net_dbus_is_pending_call_used() == TRUE) {
		NETWORK_LOG(NETWORK_ERROR, "pending call in progress");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_INVALID_OPERATION;
	}

	Error = _net_dbus_get_passpoint(enabled);
	if (Error != NET_ERR_NONE) {
		NETWORK_LOG(NETWORK_ERROR,
				"_net_dbus_get_passpoint() failed. Error [%s]",
				_net_print_error(Error));
	}

	__NETWORK_FUNC_EXIT__;
	return Error;
}

EXPORT_API int net_wifi_set_passpoint(int enable)
{
	__NETWORK_FUNC_ENTER__;

	net_err_t Error = NET_ERR_NONE;

	if (NetworkInfo.ref_count < 1) {
		NETWORK_LOG(NETWORK_ERROR, "Application is not registered");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_APP_NOT_REGISTERED;
	}

	if (NetworkInfo.wifi_state == WIFI_OFF) {
		if ((NetworkInfo.wifi_state = _net_get_wifi_state(&Error)) == WIFI_OFF) {
			NETWORK_LOG(NETWORK_ERROR, "Wi-Fi is powered off!");
			__NETWORK_FUNC_EXIT__;
			return NET_ERR_INVALID_OPERATION;
		}
	}

	if (_net_dbus_is_pending_call_used() == TRUE) {
		NETWORK_LOG(NETWORK_ERROR, "pending call in progress");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_INVALID_OPERATION;
	}

	Error = _net_dbus_set_passpoint(enable);
	if (Error != NET_ERR_NONE) {
		NETWORK_LOG(NETWORK_ERROR,
				"_net_dbus_set_passpoint() failed. Error [%s]",
				_net_print_error(Error));
	}

	__NETWORK_FUNC_EXIT__;
	return Error;
}

/*****************************************************************************
 * 	ConnMan Wi-Fi Client Interface Async API Definition
 *****************************************************************************/
EXPORT_API int net_open_connection_with_wifi_info(const net_wifi_connection_info_t *wifi_info)
{
	__NETWORK_FUNC_ENTER__;

	net_err_t Error = NET_ERR_NONE;

	if (wifi_info == NULL) {
		NETWORK_LOG(NETWORK_ERROR, "Invalid parameter");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_INVALID_PARAM;
	}

	if (NetworkInfo.ref_count < 1) {
		NETWORK_LOG(NETWORK_ERROR, "Application is not registered");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_APP_NOT_REGISTERED;
	}

	if (request_table[NETWORK_REQUEST_TYPE_OPEN_CONNECTION].flag == TRUE) {
		NETWORK_LOG(NETWORK_ERROR, "Connection open request in progress");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_IN_PROGRESS;
	}

	if (NetworkInfo.wifi_state == WIFI_OFF) {
		if ((NetworkInfo.wifi_state = _net_get_wifi_state(&Error)) == WIFI_OFF) {
			NETWORK_LOG(NETWORK_ERROR, "Wi-Fi is powered off!");
			__NETWORK_FUNC_EXIT__;
			return NET_ERR_INVALID_OPERATION;
		}
	}

	if (_net_dbus_is_pending_call_used() == TRUE) {
		NETWORK_LOG(NETWORK_ERROR, "pending call in progress");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_INVALID_OPERATION;
	}

	request_table[NETWORK_REQUEST_TYPE_OPEN_CONNECTION].flag = TRUE;

	Error = _net_open_connection_with_wifi_info(wifi_info);
	if (Error != NET_ERR_NONE) {
		NETWORK_LOG(NETWORK_ERROR,
				"net_open_connection_with_wifi_info() failed. Error [%s]",
				_net_print_error(Error));

		if (request_table[NETWORK_REQUEST_TYPE_OPEN_CONNECTION].flag != 0)
			memset(&request_table[NETWORK_REQUEST_TYPE_OPEN_CONNECTION], 0,
					sizeof(network_request_table_t));

		__NETWORK_FUNC_EXIT__;
		return Error;
	}

	__NETWORK_FUNC_EXIT__;
	return NET_ERR_NONE;
}

EXPORT_API int net_wifi_power_on(gboolean wifi_picker_test)
{
	__NETWORK_FUNC_ENTER__;

	net_err_t Error = NET_ERR_NONE;
	int hotspot_state = 0;

	if (NetworkInfo.ref_count < 1) {
		NETWORK_LOG(NETWORK_ERROR, "Application is not registered");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_APP_NOT_REGISTERED;
	}

	vconf_get_int(VCONFKEY_MOBILE_HOTSPOT_MODE, &hotspot_state);
	if (hotspot_state & VCONFKEY_MOBILE_HOTSPOT_MODE_WIFI) {
		NETWORK_LOG(NETWORK_ERROR, "Wi-Fi hotspot is enabled!");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_INVALID_OPERATION;
	}

	if (NetworkInfo.wifi_state != WIFI_OFF) {
		if ((NetworkInfo.wifi_state = _net_get_wifi_state(&Error)) == WIFI_ON) {
			NETWORK_LOG(NETWORK_ERROR, "Wi-Fi is powered on already!");
			__NETWORK_FUNC_EXIT__;
			return NET_ERR_ALREADY_EXISTS;
		}
		else if (Error != NET_ERR_NONE) {
			NETWORK_LOG(NETWORK_ERROR, "Failed to get Wi-Fi state");
			__NETWORK_FUNC_EXIT__;
			return Error;
		}
	}

	if (request_table[NETWORK_REQUEST_TYPE_WIFI_POWER].flag == TRUE) {
		NETWORK_LOG(NETWORK_ERROR, "Request in progress");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_IN_PROGRESS;
	}

	_net_dbus_pending_call_unref();
	memset(request_table, 0, sizeof(request_table));

	request_table[NETWORK_REQUEST_TYPE_WIFI_POWER].flag = TRUE;

	Error = _net_dbus_load_wifi_driver(wifi_picker_test);
	if (Error != NET_ERR_NONE) {
		NETWORK_LOG(NETWORK_ERROR,
				"Failed to request Wi-Fi power on/off. Error [%s]",
				_net_print_error(Error));

		memset(&request_table[NETWORK_REQUEST_TYPE_WIFI_POWER], 0,
				sizeof(network_request_table_t));

		__NETWORK_FUNC_EXIT__;
		return Error;
	}

	__NETWORK_FUNC_EXIT__;
	return NET_ERR_NONE;
}

EXPORT_API int net_wifi_power_off(void)
{
	__NETWORK_FUNC_ENTER__;

	net_err_t Error = NET_ERR_NONE;

	if (NetworkInfo.ref_count < 1) {
		NETWORK_LOG(NETWORK_ERROR, "Application is not registered");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_APP_NOT_REGISTERED;
	}

	if (NetworkInfo.wifi_state == WIFI_OFF) {
		if ((NetworkInfo.wifi_state = _net_get_wifi_state(&Error)) == WIFI_OFF) {
			NETWORK_LOG(NETWORK_ERROR, "Wi-Fi is powered off already!");
			__NETWORK_FUNC_EXIT__;
			return NET_ERR_ALREADY_EXISTS;
		}
	}

	if (request_table[NETWORK_REQUEST_TYPE_WIFI_POWER].flag == TRUE) {
		NETWORK_LOG(NETWORK_ERROR, "Request in progress");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_IN_PROGRESS;
	}

	if (_net_dbus_is_pending_call_used() == TRUE) {
		if (request_table[NETWORK_REQUEST_TYPE_SCAN].flag == TRUE) {
			_net_dbus_pending_call_unref();

			memset(&request_table[NETWORK_REQUEST_TYPE_SCAN],
					0, sizeof(network_request_table_t));
		}

		if (request_table[NETWORK_REQUEST_TYPE_OPEN_CONNECTION].flag == TRUE) {
			_net_dbus_pending_call_unref();

			memset(&request_table[NETWORK_REQUEST_TYPE_OPEN_CONNECTION],
					0, sizeof(network_request_table_t));
		}

		if (request_table[NETWORK_REQUEST_TYPE_ENROLL_WPS].flag == TRUE) {
			_net_dbus_pending_call_unref();

			memset(&request_table[NETWORK_REQUEST_TYPE_ENROLL_WPS],
					0, sizeof(network_request_table_t));
		}

		if (request_table[NETWORK_REQUEST_TYPE_CLOSE_CONNECTION].flag == TRUE) {
			_net_dbus_pending_call_unref();

			memset(&request_table[NETWORK_REQUEST_TYPE_CLOSE_CONNECTION],
					0, sizeof(network_request_table_t));
		}

		if (request_table[NETWORK_REQUEST_TYPE_SPECIFIC_SCAN].flag == TRUE) {
			_net_dbus_pending_call_unref();

			memset(&request_table[NETWORK_REQUEST_TYPE_SPECIFIC_SCAN],
					0, sizeof(network_request_table_t));
		}

		if (request_table[NETWORK_REQUEST_TYPE_WPS_SCAN].flag == TRUE) {
			_net_dbus_pending_call_unref();

			memset(&request_table[NETWORK_REQUEST_TYPE_WPS_SCAN],
					0, sizeof(network_request_table_t));
		}

		if (_net_dbus_is_pending_call_used() == TRUE) {
			NETWORK_LOG(NETWORK_ERROR, "pending call in progress");

			__NETWORK_FUNC_EXIT__;
			return NET_ERR_INVALID_OPERATION;
		}
	}

	request_table[NETWORK_REQUEST_TYPE_WIFI_POWER].flag = TRUE;

	Error = _net_dbus_remove_wifi_driver();
	if (Error != NET_ERR_NONE ) {
		NETWORK_LOG(NETWORK_ERROR,
				"Failed to request Wi-Fi power on/off. Error [%s]",
				_net_print_error(Error));

		memset(&request_table[NETWORK_REQUEST_TYPE_WIFI_POWER], 0, sizeof(network_request_table_t));

		__NETWORK_FUNC_EXIT__;
		return Error;
	}

	__NETWORK_FUNC_EXIT__;
	return NET_ERR_NONE;
}

EXPORT_API int net_scan_wifi(void)
{
	__NETWORK_FUNC_ENTER__;

	net_err_t Error = NET_ERR_NONE;

	if (NetworkInfo.ref_count < 1) {
		NETWORK_LOG(NETWORK_ERROR, "Application is not registered");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_APP_NOT_REGISTERED;
	}

	if (request_table[NETWORK_REQUEST_TYPE_SCAN].flag == TRUE) {
		NETWORK_LOG(NETWORK_ERROR, "Request in progress");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_IN_PROGRESS;
	}

	if (NetworkInfo.wifi_state == WIFI_OFF) {
		if ((NetworkInfo.wifi_state = _net_get_wifi_state(&Error)) == WIFI_OFF) {
			NETWORK_LOG(NETWORK_ERROR, "Wi-Fi powered off!");
			__NETWORK_FUNC_EXIT__;
			return NET_ERR_INVALID_OPERATION;
		}
	}

	if (_net_dbus_is_pending_call_used() == TRUE) {
		if (request_table[NETWORK_REQUEST_TYPE_SCAN].flag == TRUE) {
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
		NETWORK_LOG(NETWORK_ERROR, "Failed to request scan. Error [%s]",
				_net_print_error(Error));

		memset(&request_table[NETWORK_REQUEST_TYPE_SCAN], 0,
				sizeof(network_request_table_t));

		__NETWORK_FUNC_EXIT__;
		return Error;
	}

	__NETWORK_FUNC_EXIT__;
	return NET_ERR_NONE;
}

EXPORT_API int net_wifi_enroll_wps(const char *profile_name, net_wifi_wps_info_t *wps_info)
{
	__NETWORK_FUNC_ENTER__;

	net_err_t Error = NET_ERR_NONE;

	if (_net_check_profile_name(profile_name) != NET_ERR_NONE) {
		NETWORK_LOG(NETWORK_ERROR, "Invalid profile name");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_INVALID_PARAM;
	}

	if (NetworkInfo.ref_count < 1) {
		NETWORK_LOG(NETWORK_ERROR, "Application is not registered");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_APP_NOT_REGISTERED;
	}

	if (request_table[NETWORK_REQUEST_TYPE_ENROLL_WPS].flag == TRUE) {
		NETWORK_LOG(NETWORK_ERROR, "Request in progress");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_IN_PROGRESS;
	}

	if (NetworkInfo.wifi_state == WIFI_OFF) {
		if ((NetworkInfo.wifi_state = _net_get_wifi_state(&Error)) == WIFI_OFF) {
			NETWORK_LOG(NETWORK_ERROR, "Wi-Fi is powered off!");
			__NETWORK_FUNC_EXIT__;
			return NET_ERR_INVALID_OPERATION;
		}
	}

	if (_net_dbus_is_pending_call_used() == TRUE) {
		NETWORK_LOG(NETWORK_ERROR, "pending call in progress");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_INVALID_OPERATION;
	}

	request_table[NETWORK_REQUEST_TYPE_ENROLL_WPS].flag = TRUE;
	g_strlcpy(request_table[NETWORK_REQUEST_TYPE_ENROLL_WPS].ProfileName,
			profile_name, NET_PROFILE_NAME_LEN_MAX+1);

	if (wps_info->type == WIFI_WPS_PBC)
		Error = _net_dbus_set_agent_wps_pbc_and_connect(profile_name);
	else if (wps_info->type == WIFI_WPS_PIN)
		Error = _net_dbus_set_agent_wps_pin_and_connect(wps_info->pin, profile_name);
	else
		Error = NET_ERR_INVALID_PARAM;

	if (NET_ERR_NONE != Error) {
		NETWORK_LOG(NETWORK_ERROR,
				"WPS configuration failed(%s)", _net_print_error(Error));

		memset(&request_table[NETWORK_REQUEST_TYPE_ENROLL_WPS], 0,
				sizeof(network_request_table_t));
	}

	__NETWORK_FUNC_EXIT__;
	return Error;
}

#if defined TIZEN_TV
EXPORT_API int net_wifi_cancel_wps(void)
{
	__NETWORK_FUNC_ENTER__;

	net_err_t Error = NET_ERR_NONE;
	NETWORK_LOG(NETWORK_ERROR, "net_wifi_wps_cancel called\n");

	if (g_atomic_int_get(&NetworkInfo.ref_count) == 0) {
		NETWORK_LOG(NETWORK_ERROR, "Application is not registered\n");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_APP_NOT_REGISTERED;
	}

	if (request_table[NETWORK_REQUEST_TYPE_ENROLL_WPS].flag == FALSE) {
		NETWORK_LOG(NETWORK_ERROR, "No pending call in progress\n");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_INVALID_OPERATION;
	}

	if (_net_get_wifi_state(&Error) != WIFI_ON) {
		NETWORK_LOG(NETWORK_ERROR, "Wi-Fi is powered off!\n");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_INVALID_OPERATION;
	}

	if (_net_dbus_is_pending_call_used() == TRUE) {
		NETWORK_LOG(NETWORK_ERROR, "pending call in progress\n");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_INVALID_OPERATION;
	}

	if(request_table[NETWORK_REQUEST_TYPE_ENROLL_WPS].ProfileName[0] != '\0') {
		net_delete_profile(request_table[NETWORK_REQUEST_TYPE_ENROLL_WPS].ProfileName);
	}

	Error = _net_dbus_cancel_wps();
	if (Error != NET_ERR_NONE) {
		NETWORK_LOG(NETWORK_ERROR,
			"Failed to request cancel WPS, Error [%s]\n",
			_net_print_error(Error));
	}

	memset(&request_table[NETWORK_REQUEST_TYPE_ENROLL_WPS], 0,
			sizeof(network_request_table_t));

	__NETWORK_FUNC_EXIT__;
	return Error;
}
#endif


/*****************************************************************************
 * 	ConnMan Wi-Fi Client Interface Sync Function Definition
 *****************************************************************************/
EXPORT_API int net_get_wifi_state(net_wifi_state_t *current_state, net_profile_name_t *profile_name)
{
	__NETWORK_FUNC_ENTER__;

	net_wifi_state_t wifi_state;
	net_err_t Error = NET_ERR_NONE;

	if (NetworkInfo.ref_count < 1) {
		NETWORK_LOG(NETWORK_ERROR, "Application is not registered");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_APP_NOT_REGISTERED;
	}

	if (profile_name == NULL) {
		NETWORK_LOG(NETWORK_ERROR, "profile_name is NULL");
		return NET_ERR_INVALID_PARAM;
	}

	memset(profile_name, 0, sizeof(net_profile_name_t));

	wifi_state = _net_get_wifi_state(&Error);

	if (wifi_state == WIFI_OFF) {
		*current_state = WIFI_OFF;
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_NONE;
	}

	*current_state = __net_get_wifi_service_state(profile_name->ProfileName, &Error);

	__NETWORK_FUNC_EXIT__;
	return Error;
}

EXPORT_API int net_wifi_set_background_scan_mode(net_wifi_background_scan_mode_t scan_mode)
{
	__NETWORK_FUNC_ENTER__;

	net_err_t Error = NET_ERR_NONE;

	if (NetworkInfo.ref_count < 1) {
		NETWORK_LOG(NETWORK_ERROR, "Application is not registered");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_APP_NOT_REGISTERED;
	}

	if (NetworkInfo.wifi_state == WIFI_OFF) {
		if ((NetworkInfo.wifi_state = _net_get_wifi_state(&Error)) == WIFI_OFF) {
			NETWORK_LOG(NETWORK_ERROR, "Wi-Fi is powered off!");
			__NETWORK_FUNC_EXIT__;
			return NET_ERR_INVALID_OPERATION;
		}
	}

	if ((Error = _net_dbus_set_bgscan_mode(scan_mode)) != NET_ERR_NONE) {
		NETWORK_LOG(NETWORK_ERROR,
				"Failed to set bgscan mode. Error [%s]",
				_net_print_error(Error));

		__NETWORK_FUNC_EXIT__;
		return Error;
	}

	__NETWORK_FUNC_EXIT__;
	return NET_ERR_NONE;
}

EXPORT_API int net_check_get_privilege()
{
	net_err_t Error = NET_ERR_NONE;

	Error = __net_check_get_privilege();
	if (Error != NET_ERR_NONE) {
		NETWORK_LOG(NETWORK_ERROR, "Failed to check get privilege. Error [%s]",
		_net_print_error(Error));

		return Error;
	}

	return Error;
}

EXPORT_API int net_check_profile_privilege()
{
	net_err_t Error = NET_ERR_NONE;

	Error = __net_check_profile_privilege();
	if (Error != NET_ERR_NONE) {
		NETWORK_LOG(NETWORK_ERROR, "Failed to check profile privilege. Error [%s]",
		_net_print_error(Error));

		return Error;
	}

	return Error;
}
#if defined TIZEN_TV
EXPORT_API int net_wifi_enroll_wps_without_ssid(net_wifi_wps_info_t *wps_info)
{
	__NETWORK_FUNC_ENTER__;

	net_err_t Error = NET_ERR_NONE;

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

	if (_net_get_wifi_state(&Error) != WIFI_ON) {
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

	if (wps_info->type == WIFI_WPS_PBC) {
		/* Look How to change the use of Connman agent */
		Error = _net_dbus_set_agent_wps_pbc();
		if (NET_ERR_NONE != Error) {
			NETWORK_LOG(NETWORK_ERROR,
				"_net_dbus_set_agent_wps_pbc() failed\n");
			__NETWORK_FUNC_EXIT__;
			return NET_ERR_INVALID_OPERATION;
		}
	} else if (wps_info->type == WIFI_WPS_PIN) {
		Error = _net_dbus_set_agent_wps_pin(wps_info->pin);
		if (NET_ERR_NONE != Error){
			NETWORK_LOG(NETWORK_ERROR,
					"_net_dbus_set_agent_wps_pin() failed\n");
			__NETWORK_FUNC_EXIT__;
			return NET_ERR_INVALID_OPERATION;
		}
	}else {
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_INVALID_PARAM;
	}

	if(wps_info->type == WIFI_WPS_PBC) {
		Error = _net_dbus_open_connection_without_ssid();
	} else if(wps_info->type == WIFI_WPS_PIN) {
		Error = _net_dbus_open_pin_connection_without_ssid(wps_info->pin);
	}else{
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_INVALID_PARAM;
	}

	if (Error != NET_ERR_NONE) {
		NETWORK_LOG(NETWORK_ERROR,
				"Failed to request open connection, Error [%s]\n",
				_net_print_error(Error));

		memset(&request_table[NETWORK_REQUEST_TYPE_ENROLL_WPS], 0,
				sizeof(network_request_table_t));
	}

	__NETWORK_FUNC_EXIT__;
	return Error;
}
#endif

EXPORT_API int net_wifi_tdls_disconnect(const char* peer_mac_addr)
{
	__NETWORK_FUNC_ENTER__;

	net_err_t Error = NET_ERR_NONE;

	if (peer_mac_addr == NULL) {
		NETWORK_LOG(NETWORK_ERROR, "invalid parameter\n");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_INVALID_PARAM;
	}

	if (g_atomic_int_get(&NetworkInfo.ref_count) == 0) {
		NETWORK_LOG(NETWORK_ERROR, "Application is not registered\n");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_APP_NOT_REGISTERED;
	}

	Error = _net_dbus_tdls_disconnect(peer_mac_addr);

	if (Error != NET_ERR_NONE)
		NETWORK_LOG(NETWORK_ERROR, "_net_dbus_tdls_set_device_type failed\n");


	__NETWORK_FUNC_EXIT__;
	return Error;

}

EXPORT_API int net_wifi_tdls_connected_peer(char** peer_mac_addr)
{
	__NETWORK_FUNC_ENTER__;

	net_err_t Error = NET_ERR_NONE;

	if (peer_mac_addr == NULL) {
		NETWORK_LOG(NETWORK_ERROR, "invalid parameter\n");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_INVALID_PARAM;
	}

	if (g_atomic_int_get(&NetworkInfo.ref_count) == 0) {
		NETWORK_LOG(NETWORK_ERROR, "Application is not registered\n");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_APP_NOT_REGISTERED;
	}

	Error = _net_dbus_tdls_connected_peer(peer_mac_addr);

	if (Error != NET_ERR_NONE)
		NETWORK_LOG(NETWORK_ERROR, "net_wifi_tdls_connected_peer failed\n");


	__NETWORK_FUNC_EXIT__;
	return Error;

}