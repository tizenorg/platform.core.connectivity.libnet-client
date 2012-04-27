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

#include <vconf.h>
#include <dbus/dbus.h> 

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
				"Error!!! failed to get service(profile) list. Error [%s]\n",
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

EXPORT_API int net_open_connection_with_wifi_info(const net_wifi_connection_info_t *wifi_info)
{
	__NETWORK_FUNC_ENTER__;

	net_err_t Error = NET_ERR_NONE;

	if (wifi_info == NULL) {
		NETWORK_LOG(NETWORK_ERROR, "Error!!! Invalid parameter\n");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_INVALID_PARAM;
	}

	if (NetworkInfo.ClientEventCb == NULL) {
		NETWORK_LOG(NETWORK_ERROR, "Error!!! Application was not registered\n");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_APP_NOT_REGISTERED;
	}

	if (_net_get_wifi_state() != WIFI_ON) {
		NETWORK_LOG( NETWORK_ERROR, "Error!!! wifi is powered off!\n");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_INVALID_OPERATION;
	}

	Error = _net_open_connection_with_wifi_info(wifi_info);
	if (Error != NET_ERR_NONE) {
		NETWORK_LOG(NETWORK_ERROR, "Error!!! net_open_connection_with_wifi_info() failed. Error [%s]\n",
				_net_print_error(Error));
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

	if (NetworkInfo.ClientEventCb == NULL) {
		NETWORK_LOG(NETWORK_ERROR, "Error!!! Application was not registered\n");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_APP_NOT_REGISTERED;
	}

	vconf_get_int(VCONFKEY_MOBILE_HOTSPOT_MODE, &hotspot_state);
	if (hotspot_state & VCONFKEY_MOBILE_HOTSPOT_MODE_WIFI) {
		NETWORK_LOG(NETWORK_ERROR, "Error!!! Wi-Fi hotspot is enabled!\n");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_INVALID_OPERATION;
	}

	if (NetworkInfo.wifi_state != WIFI_OFF) {
		NETWORK_LOG(NETWORK_ERROR, "Error!!! wifi is powered on already!\n");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_INVALID_OPERATION;
	}

	if (request_table[NETWORK_REQUEST_TYPE_WIFI_POWER].flag == TRUE) {
		NETWORK_LOG(NETWORK_ASSERT, "Error!! Request already in progress\n");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_INVALID_OPERATION;
	}

	request_table[NETWORK_REQUEST_TYPE_WIFI_POWER].flag = TRUE;

	Error = _net_dbus_load_wifi_driver();
	if (Error != NET_ERR_NONE ) {
		NETWORK_LOG(NETWORK_EXCEPTION,
				"Error!!! Failed to request wifi power on/off. Error [%s]\n",
				_net_print_error(Error));
		memset(&request_table[NETWORK_REQUEST_TYPE_WIFI_POWER], 0, sizeof(network_request_table_t));
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

	if(NetworkInfo.ClientEventCb == NULL) {
		NETWORK_LOG(NETWORK_ERROR, "Error!!! Application was not registered\n");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_APP_NOT_REGISTERED;
	}

	if(NetworkInfo.wifi_state == WIFI_OFF) {
		NETWORK_LOG(NETWORK_ERROR, "Error!!! wifi is powered off already!\n");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_INVALID_OPERATION;
	}

	if (request_table[NETWORK_REQUEST_TYPE_WIFI_POWER].flag == TRUE) {
		NETWORK_LOG(NETWORK_ASSERT, "Error!! Request already in progress\n");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_INVALID_OPERATION;
	}

	request_table[NETWORK_REQUEST_TYPE_WIFI_POWER].flag = TRUE;

	Error = _net_dbus_remove_wifi_driver();
	if (Error != NET_ERR_NONE ) {
		NETWORK_LOG(NETWORK_EXCEPTION,
				"Error!!! Failed to request wifi power on/off. Error [%s]\n",
				_net_print_error(Error));
		memset(&request_table[NETWORK_REQUEST_TYPE_WIFI_POWER], 0, sizeof(network_request_table_t));
		__NETWORK_FUNC_EXIT__;
		return Error;
	}

	NETWORK_LOG(NETWORK_HIGH, "Driver remove successfully\n");

	__NETWORK_FUNC_EXIT__;
	return NET_ERR_NONE;
}


EXPORT_API int net_scan_wifi(void)
{
	__NETWORK_FUNC_ENTER__;

	net_err_t Error = NET_ERR_NONE;

	if(NetworkInfo.ClientEventCb == NULL) {
		NETWORK_LOG(NETWORK_ERROR, "Error!!! Application was not registered\n");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_APP_NOT_REGISTERED;
	}

	if(request_table[NETWORK_REQUEST_TYPE_SCAN].flag == TRUE) {
		NETWORK_LOG(NETWORK_ASSERT, "Error!! Request already in progress\n");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_INVALID_OPERATION;
	}

	if (_net_get_wifi_state() != WIFI_ON) {
		NETWORK_LOG( NETWORK_ERROR, "Error!!! wifi is powered off!\n");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_INVALID_OPERATION;
	}

	request_table[NETWORK_REQUEST_TYPE_SCAN].flag = TRUE;

	if ((Error = _net_dbus_scan_request()) != NET_ERR_NONE ) {
		NETWORK_LOG(NETWORK_EXCEPTION,
				"Error!!! Failed to request scan. Error [%s]\n",
				_net_print_error(Error));
		memset(&request_table[NETWORK_REQUEST_TYPE_SCAN], 0, sizeof(network_request_table_t));
		__NETWORK_FUNC_EXIT__;
		return Error;;
	}

	NETWORK_LOG(NETWORK_HIGH, "ConnMan successfully finished Wi-Fi scanning\n");

	__NETWORK_FUNC_EXIT__;
	return NET_ERR_NONE;
}


EXPORT_API int net_wifi_enroll_wps(const char *profile_name, net_wifi_wps_info_t *wps_info)
{
	__NETWORK_FUNC_ENTER__;

	net_err_t Error = NET_ERR_NONE;

	if (_net_check_profile_name(profile_name) != NET_ERR_NONE) {
		NETWORK_LOG(NETWORK_ERROR, "Error!!! Invalid ProfileName passed\n");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_INVALID_PARAM;
	}

	if (NetworkInfo.ClientEventCb == NULL) {
		NETWORK_LOG(NETWORK_ERROR, "Error!!! Application was not registered\n");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_APP_NOT_REGISTERED;
	}

	if (_net_get_wifi_state() != WIFI_ON) {
		NETWORK_LOG( NETWORK_ERROR, "Error!!! wifi is powered off!\n");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_INVALID_OPERATION;
	}

	if (request_table[NETWORK_REQUEST_TYPE_ENROLL_WPS].flag == TRUE) {
		NETWORK_LOG(NETWORK_ASSERT, "Error!! Request already in progress\n");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_INVALID_OPERATION;
	}
	
	request_table[NETWORK_REQUEST_TYPE_ENROLL_WPS].flag = TRUE;
	snprintf(request_table[NETWORK_REQUEST_TYPE_ENROLL_WPS].ProfileName,
			NET_PROFILE_NAME_LEN_MAX+1, "%s", profile_name);

	if(wps_info->type == WIFI_WPS_PBC) {
		Error = _net_dbus_open_connection(profile_name);
		if(Error != NET_ERR_NONE)
		{
			NETWORK_LOG(NETWORK_ERROR,
					"Error!! Failed to request open connection, Error [%s]\n", 
					_net_print_error(Error));
			
			memset(&request_table[NETWORK_REQUEST_TYPE_ENROLL_WPS], 0, sizeof(network_request_table_t));
			
			__NETWORK_FUNC_EXIT__;
			return Error;
		}
	}
	else if(wps_info->type == WIFI_WPS_PIN) {
		// TODO: handle wps pin
	}
	else {
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

	if (NetworkInfo.ClientEventCb == NULL) {
		NETWORK_LOG(NETWORK_ERROR, "Error!!! Application was not registered\n");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_APP_NOT_REGISTERED;
	}

	if (profile_name == NULL) {
		NETWORK_LOG(NETWORK_ERROR, "Error!!! profile_name is NULL\n");
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
		
	if (NetworkInfo.ClientEventCb == NULL) {
		NETWORK_LOG(NETWORK_ERROR, "Error!!! Application not registered\n");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_APP_NOT_REGISTERED;
	}

	if (_net_get_wifi_state() != WIFI_ON) {
		NETWORK_LOG( NETWORK_ERROR, "Error!!! wifi is powered off!\n");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_INVALID_OPERATION;
	}

	NETWORK_LOG(NETWORK_HIGH,  "BGScan Mode [%d]\n", scan_mode);

	if ((Error = _net_dbus_set_bgscan_mode(scan_mode)) != NET_ERR_NONE) {
		NETWORK_LOG(NETWORK_EXCEPTION,
				"Error!!! Failed to set bgscan mode. Error [%s]\n",
				_net_print_error(Error));

		__NETWORK_FUNC_EXIT__;
		return Error;
	}
		
	NETWORK_LOG(NETWORK_HIGH, "Set BGScan mode Request to connman is successfull\n");
	
	__NETWORK_FUNC_EXIT__;	
	return NET_ERR_NONE;
}


#ifdef __cplusplus
}
#endif /* __cplusplus */

