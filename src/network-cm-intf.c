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

static int __net_get_default_profile(void *param, net_profile_info_t *active_profile_info);

/*****************************************************************************
 * 	Global Functions
 *****************************************************************************/

/*****************************************************************************
 * 	Extern Variables
 *****************************************************************************/

extern network_request_table_t request_table[NETWORK_REQUEST_TYPE_MAX];

/*****************************************************************************
 * 	Global Variables
 *****************************************************************************/

network_info_t NetworkInfo = {0, };

/*****************************************************************************
 * 	Local Functions Definition
 *****************************************************************************/

static int __net_get_default_profile(void *param, net_profile_info_t *active_profile_info)
{
	__NETWORK_FUNC_ENTER__;

	net_err_t Error = NET_ERR_NONE;

	if (NetworkInfo.ClientEventCb == NULL) {
		NETWORK_LOG(NETWORK_ERROR, "Error!!! Application was not registered\n");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_APP_NOT_REGISTERED;
	}

	if (param == NULL) {
		NETWORK_LOG(NETWORK_ERROR, "Error!!! Invalid parameter\n");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_INVALID_PARAM;
	}

	Error = _net_get_default_profile_info(active_profile_info);

	if (Error != NET_ERR_NONE) {
		NETWORK_LOG(NETWORK_ERROR,
				"Error!!! _net_get_default_profile_info() failed. Error [%s]\n",
				_net_print_error(Error));

		__NETWORK_FUNC_EXIT__;
		return Error;
	}

	__NETWORK_FUNC_EXIT__;
	return NET_ERR_NONE;
}

/*****************************************************************************
 * 	ConnMan Client Common Interface API Definition
 *****************************************************************************/

/**
 * @fn  EXPORT_API int net_register_client(net_event_cb_t event_cb, void *user_data)
 *
 * This function registers callback with the network client
 * This is Sync API.
 *
 * @return       int - NET_ERR_NONE on success, negative values for errors
 * @param[in]    net_event_cb_t event_cb - Pointer to callback function
 *		 void* user_data - Pointer to user data 
 * @param[out]   none 
 */
EXPORT_API int net_register_client(net_event_cb_t event_cb, void *user_data)
{
	__NETWORK_FUNC_ENTER__;

	net_err_t Error = NET_ERR_NONE;

	if (event_cb == NULL) {
		 NETWORK_LOG(NETWORK_ASSERT, "Error!! Invalid EventCb parameter\n");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_INVALID_PARAM;
	}
	
	if (NetworkInfo.ClientEventCb != NULL) {
		NETWORK_LOG(NETWORK_ERROR, "Error!!! Application Already registered\n");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_APP_ALREADY_REGISTERED;
	}

	if (_net_mutex_init() != NET_ERR_NONE) {
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_UNKNOWN;
	}

	Error = _net_register_signal();
	if (Error != NET_ERR_NONE) {
		NETWORK_LOG(NETWORK_ERROR, "Error!!! _net_register_signal() failed. Error [%s]\n",
				_net_print_error(Error));
		_net_mutex_destroy();
		__NETWORK_FUNC_EXIT__;
		return Error;
	}

	NetworkInfo.ClientEventCb = event_cb;
	NetworkInfo.user_data = user_data;
	NetworkInfo.wifi_state = _net_get_wifi_state();
	_net_init_service_state_table();

	NETWORK_LOG(NETWORK_HIGH, "Client Register Successfully\n");

	__NETWORK_FUNC_EXIT__;	
	return NET_ERR_NONE;
}


/**
 * @fn  EXPORT_API int net_deregister_client(void)
 *
 * This function deregisters with network client 
 * This is Sync API.
 *
 * @return       int - NET_ERR_NONE on success, negative values for errors
 * @param[in]    none
 * @param[out]   none
 */

EXPORT_API int net_deregister_client(void)
{
	__NETWORK_FUNC_ENTER__;

	net_err_t Error = NET_ERR_NONE;
	
	if (NetworkInfo.ClientEventCb == NULL) {
		NETWORK_LOG(NETWORK_ERROR, "Error!!! Application was not registered\n");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_APP_NOT_REGISTERED;
	}

	Error = _net_deregister_signal();	
	if (Error != NET_ERR_NONE) {
		NETWORK_LOG(NETWORK_ERROR, "Error!!! Failed to deregister signal\n");
		__NETWORK_FUNC_EXIT__;
		return Error;
	}

	_net_mutex_destroy();
	_net_clear_request_table();

	NetworkInfo.ClientEventCb = NULL;
	NetworkInfo.user_data = NULL;
	
	NETWORK_LOG(NETWORK_HIGH, "Client De-Register Successfull\n");
	
	__NETWORK_FUNC_EXIT__;	
	return NET_ERR_NONE;
}

/**
 * @fn  EXPORT_API int net_get_active_net_info(net_profile_info_t *active_profile_info)
 *
 * This API returns the information of active(default) network profile.
 * This is Sync API.
 *
 * @return       int - NET_ERR_NONE on success, negative values for errors
 * @param[in]    none
 * @param[out] 	 active_profile_info 	The information of active(default) network profile.
 */
EXPORT_API int net_get_active_net_info(net_profile_info_t *active_profile_info)
{
	__NETWORK_FUNC_ENTER__;

	net_err_t Error = NET_ERR_NONE;

	Error = __net_get_default_profile((void*)active_profile_info, active_profile_info);

	__NETWORK_FUNC_EXIT__;
	return Error;
}

/**
 * @fn  EXPORT_API int net_get_active_ipaddress(net_addr_t *ip_address)
 *
 * This API returns a specific information of active(default) network profile.
 * This is Sync API.
 *
 * @return       int - NET_ERR_NONE on success, negative values for errors
 * @param[in]    none
 * @param[out] 	 ip_address 	Ip address of active(default) network profile.
 */
EXPORT_API int net_get_active_ipaddress(net_addr_t *ip_address)
{
	__NETWORK_FUNC_ENTER__;

	net_err_t Error = NET_ERR_NONE;
	net_profile_info_t active_profile_info;
	net_dev_info_t *net_info = NULL;

	Error = __net_get_default_profile((void*)ip_address, &active_profile_info);
	if (Error != NET_ERR_NONE) {
		__NETWORK_FUNC_EXIT__;
		return Error;
	}

	if (active_profile_info.profile_type == NET_DEVICE_CELLULAR)
		net_info = &active_profile_info.ProfileInfo.Pdp.net_info;
	else if (active_profile_info.profile_type == NET_DEVICE_WIFI)
		net_info = &active_profile_info.ProfileInfo.Wlan.net_info;
	else
		Error = NET_ERR_UNKNOWN;

	if (net_info != NULL)
		memcpy(ip_address, &net_info->IpAddr, sizeof(net_addr_t));

	__NETWORK_FUNC_EXIT__;
	return Error;
}

/**
 * @fn  EXPORT_API int net_get_active_netmask(net_addr_t *netmask)
 *
 * This API returns a specific information of active(default) network profile.
 * This is Sync API.
 *
 * @return       int - NET_ERR_NONE on success, negative values for errors
 * @param[in]    none
 * @param[out] 	 netmask 	Netmask of active(default) network profile.
 */
EXPORT_API int net_get_active_netmask(net_addr_t *netmask)
{
	__NETWORK_FUNC_ENTER__;

	net_err_t Error = NET_ERR_NONE;
	net_profile_info_t active_profile_info;
	net_dev_info_t *net_info = NULL;

	Error = __net_get_default_profile((void*)netmask, &active_profile_info);
	if (Error != NET_ERR_NONE) {
		__NETWORK_FUNC_EXIT__;
		return Error;
	}

	if (active_profile_info.profile_type == NET_DEVICE_CELLULAR)
		net_info = &active_profile_info.ProfileInfo.Pdp.net_info;
	else if (active_profile_info.profile_type == NET_DEVICE_WIFI)
		net_info = &active_profile_info.ProfileInfo.Wlan.net_info;
	else
		Error = NET_ERR_UNKNOWN;

	if (net_info != NULL)
		memcpy(netmask, &net_info->SubnetMask, sizeof(net_addr_t));

	__NETWORK_FUNC_EXIT__;
	return Error;
}

/**
 * @fn  EXPORT_API int net_get_active_gateway(net_addr_t *gateway)
 *
 * This API returns a specific information of active(default) network profile.
 * This is Sync API.
 *
 * @return       int - NET_ERR_NONE on success, negative values for errors
 * @param[in]    none
 * @param[out] 	 gateway 	Gateway address of active(default) network profile.
 */
EXPORT_API int net_get_active_gateway(net_addr_t *gateway)
{
	__NETWORK_FUNC_ENTER__;

	net_err_t Error = NET_ERR_NONE;
	net_profile_info_t active_profile_info;
	net_dev_info_t *net_info = NULL;

	Error = __net_get_default_profile((void*)gateway, &active_profile_info);
	if (Error != NET_ERR_NONE) {
		__NETWORK_FUNC_EXIT__;
		return Error;
	}

	if (active_profile_info.profile_type == NET_DEVICE_CELLULAR)
		net_info = &active_profile_info.ProfileInfo.Pdp.net_info;
	else if (active_profile_info.profile_type == NET_DEVICE_WIFI)
		net_info = &active_profile_info.ProfileInfo.Wlan.net_info;
	else
		Error = NET_ERR_UNKNOWN;

	if (net_info != NULL)
		memcpy(gateway, &net_info->GatewayAddr, sizeof(net_addr_t));

	__NETWORK_FUNC_EXIT__;
	return Error;
}

/**
 * @fn  EXPORT_API int net_get_active_dns(net_addr_t *dns)
 *
 * This API returns a specific information of active(default) network profile.
 * This is Sync API.
 *
 * @return       int - NET_ERR_NONE on success, negative values for errors
 * @param[in]    none
 * @param[out] 	 dns 	DNS address of active(default) network profile.
 */
EXPORT_API int net_get_active_dns(net_addr_t *dns)
{
	__NETWORK_FUNC_ENTER__;

	net_err_t Error = NET_ERR_NONE;
	net_profile_info_t active_profile_info;
	net_dev_info_t *net_info = NULL;

	Error = __net_get_default_profile((void*)dns, &active_profile_info);
	if (Error != NET_ERR_NONE) {
		__NETWORK_FUNC_EXIT__;
		return Error;
	}

	if (active_profile_info.profile_type == NET_DEVICE_CELLULAR)
		net_info = &active_profile_info.ProfileInfo.Pdp.net_info;
	else if (active_profile_info.profile_type == NET_DEVICE_WIFI)
		net_info = &active_profile_info.ProfileInfo.Wlan.net_info;
	else
		Error = NET_ERR_UNKNOWN;

	if (net_info != NULL)
		memcpy(dns, &net_info->DnsAddr[0], sizeof(net_addr_t));

	__NETWORK_FUNC_EXIT__;
	return Error;
}

/**
 * @fn  EXPORT_API int net_get_active_essid(net_essid_t *essid)
 *
 * This API returns a specific information of active(default) network profile.
 * This is Sync API.
 *
 * @return       int - NET_ERR_NONE on success, negative values for errors
 * @param[in]    none
 * @param[out] 	 essid 	ESSID of active(default) network profile.
 */
EXPORT_API int net_get_active_essid(net_essid_t *essid)
{
	__NETWORK_FUNC_ENTER__;

	net_err_t Error = NET_ERR_NONE;
	net_profile_info_t active_profile_info;
	net_wifi_profile_info_t *wlan_info = NULL;

	Error = __net_get_default_profile((void*)essid, &active_profile_info);
	if (Error != NET_ERR_NONE) {
		__NETWORK_FUNC_EXIT__;
		return Error;
	}

	if (active_profile_info.profile_type == NET_DEVICE_CELLULAR) {
		NETWORK_LOG(NETWORK_ERROR, "Error!!! Active(default) network is cellular type.\n");
		Error = NET_ERR_NO_SERVICE;
	} else if (active_profile_info.profile_type == NET_DEVICE_WIFI) {
		wlan_info = &active_profile_info.ProfileInfo.Wlan;
		memcpy(essid->essid, wlan_info->essid, NET_WLAN_ESSID_LEN+1);
	} else
		Error = NET_ERR_UNKNOWN;

	__NETWORK_FUNC_EXIT__;
	return Error;
}

/**
 * @fn  EXPORT_API int net_get_active_proxy(net_proxy_t *proxy)
 *
 * This API returns a specific information of active(default) network profile.
 * This is Sync API.
 *
 * @return       int - NET_ERR_NONE on success, negative values for errors
 * @param[in]    none
 * @param[out] 	 proxy 	Proxy of active(default) network profile.
 */
EXPORT_API int net_get_active_proxy(net_proxy_t *proxy)
{
	__NETWORK_FUNC_ENTER__;

	net_err_t Error = NET_ERR_NONE;
	net_profile_info_t active_profile_info;
	net_dev_info_t *net_info = NULL;

	Error = __net_get_default_profile((void*)proxy, &active_profile_info);
	if (Error != NET_ERR_NONE) {
		__NETWORK_FUNC_EXIT__;
		return Error;
	}

	if (active_profile_info.profile_type == NET_DEVICE_CELLULAR)
		net_info = &active_profile_info.ProfileInfo.Pdp.net_info;
	else if (active_profile_info.profile_type == NET_DEVICE_WIFI)
		net_info = &active_profile_info.ProfileInfo.Wlan.net_info;
	else
		Error = NET_ERR_UNKNOWN;

	if (net_info != NULL)
		memcpy(proxy->proxy_addr, net_info->ProxyAddr, NET_PROXY_LEN_MAX+1);

	__NETWORK_FUNC_EXIT__;
	return Error;
}

/**
 * @fn  EXPORT_API int net_is_connected(void)
 *
 * This function check's whether connection manager is connected or not
 * This is Sync API.
 *
 * @return       int - TRUE if connected, else FALSE
 * @param[in]    none
 * @param[out]   none
 */
EXPORT_API int net_is_connected(void)
{
	char state[CONNMAN_MAX_BUFLEN] = ""; /** Possible value are "online", "offline" and "connected" */
	net_err_t Error = NET_ERR_NONE;

	__NETWORK_FUNC_ENTER__;
	
	if (NetworkInfo.ClientEventCb == NULL) {
		NETWORK_LOG(NETWORK_ERROR, "Error!!! Application was not registered\n");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_APP_NOT_REGISTERED;
	}

	if ((Error = _net_dbus_get_state(state)) != NET_ERR_NONE) {
		NETWORK_LOG(NETWORK_ERROR, "Error!!! failed to get state. Error [%s]\n",
				_net_print_error(Error));
		__NETWORK_FUNC_EXIT__;
		return FALSE;
	}

	if ((strcmp(state, "online") == 0) || (strcmp(state, "connected") == 0)) {
		NETWORK_LOG(NETWORK_HIGH, "State [%s]\n", state);
		__NETWORK_FUNC_EXIT__;
		return TRUE; 
	}

	__NETWORK_FUNC_EXIT__;	
	return FALSE;
}


/**
 * @fn   EXPORT_API int net_get_network_status(net_service_type_t network_type, net_cm_network_status_t* pNetworkStatus)
 *
 * This function requests wifi/pdp network status 
 * This is Sync API.
 *
 * @return       int - NET_ERR_NONE on success, negative values for errors
 * @param[in]    net_service_type_t network_type - Network type (wlan/pdp/default), of whose status to be checked. 
 * @param[out]   net_cm_network_status_t* pNetworkStatus - Status of the requested network.
 */

EXPORT_API int net_get_network_status(net_device_t device_type, net_cm_network_status_t* network_status)
{
	net_err_t Error = NET_ERR_NONE;

	__NETWORK_FUNC_ENTER__;

	if(NetworkInfo.ClientEventCb == NULL)
	{
		NETWORK_LOG( NETWORK_ERROR, "Error!!! Application was not registered\n");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_APP_NOT_REGISTERED;
	}
	
	if((Error = _net_dbus_get_network_status(device_type, network_status)) != NET_ERR_NONE)
	{
		NETWORK_LOG( NETWORK_ERROR, "Error!!! failed to get network status. Error [%s]\n",  
				_net_print_error(Error));
		__NETWORK_FUNC_EXIT__;
		return Error;
	}
	
	__NETWORK_FUNC_EXIT__;	
	return NET_ERR_NONE;
}


/*****************************************************************************
 * 	ConnMan Wi-Fi Client Interface Async Function Definition
 *****************************************************************************/


/**
 * @fn   EXPORT_API int net_open_connection_with_profile(const char *profile_name)
 *
 * This function request open connection for the given profile name.
 * This is Async API.
 *
 * @return       int - NET_ERR_NONE on success, negative values for errors
 * @param[in]    char *ProfileName - Profile Name to be connected
 * @param[out]   none
 */

EXPORT_API int net_open_connection_with_profile(const char *profile_name)
{
	__NETWORK_FUNC_ENTER__;

	net_err_t Error = NET_ERR_NONE;
		
	NETWORK_LOG(NETWORK_HIGH, "ProfileName [%s] passed\n", profile_name);

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
	
	if (request_table[NETWORK_REQUEST_TYPE_OPEN_CONNECTION].flag == TRUE) {
		NETWORK_LOG(NETWORK_ASSERT, "Error!! Request already in progress\n");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_INVALID_OPERATION;
	}
	
	request_table[NETWORK_REQUEST_TYPE_OPEN_CONNECTION].flag = TRUE;
	snprintf(request_table[NETWORK_REQUEST_TYPE_OPEN_CONNECTION].ProfileName,
			NET_PROFILE_NAME_LEN_MAX+1, "%s", profile_name);

	if ((Error = _net_dbus_open_connection(profile_name)) != NET_ERR_NONE) {
		NETWORK_LOG(NETWORK_ERROR,
				"Error!! Failed to request open connection, Error [%s]\n", 
				_net_print_error(Error));

		if(request_table[NETWORK_REQUEST_TYPE_OPEN_CONNECTION].flag == TRUE)
			memset(&request_table[NETWORK_REQUEST_TYPE_OPEN_CONNECTION],
					0, sizeof(network_request_table_t));

		__NETWORK_FUNC_EXIT__;
		return Error;
	}

	NETWORK_LOG(NETWORK_HIGH, "Connect Request Success for ProfileName[%s]\n", profile_name);
	__NETWORK_FUNC_EXIT__;	
	return NET_ERR_NONE;
}

/**
 * @fn   EXPORT_API int net_open_connection_with_preference(net_service_type_t service_type)
 *
 * This function request open connection for the given service type.
 * This is Async API.
 *
 * @return       int - NET_ERR_NONE on success, negative values for errors
 * @param[in]    net_service_type_t service_type - Service type to be connected
 * @param[out]   none
 */
EXPORT_API int net_open_connection_with_preference(net_service_type_t service_type)
{
	__NETWORK_FUNC_ENTER__;

	net_err_t Error = NET_ERR_NONE;
	net_profile_name_t profile_name;
	memset(&profile_name, 0, sizeof(net_profile_name_t));

	if (service_type != NET_SERVICE_INTERNET &&
	    service_type != NET_SERVICE_MMS &&
	    service_type != NET_SERVICE_WAP) {
		NETWORK_LOG(NETWORK_ERROR, "Error!!! Invalid Service Type passed\n");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_INVALID_PARAM;
	}

	if (NetworkInfo.ClientEventCb == NULL) {
		NETWORK_LOG(NETWORK_ERROR, "Error!!! Application was not registered\n");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_APP_NOT_REGISTERED;
	}

	if (request_table[NETWORK_REQUEST_TYPE_OPEN_CONNECTION].flag == TRUE) {
		NETWORK_LOG(NETWORK_ASSERT, "Error!! Request already in progress\n");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_INVALID_OPERATION;
	}

	Error = _net_get_service_profile(service_type, &profile_name);
	if (Error != NET_ERR_NONE) {
		NETWORK_LOG(NETWORK_ASSERT, "Error!! Failed to find service\n");
		__NETWORK_FUNC_EXIT__;
		return Error;
	}

	request_table[NETWORK_REQUEST_TYPE_OPEN_CONNECTION].flag = TRUE;
	snprintf(request_table[NETWORK_REQUEST_TYPE_OPEN_CONNECTION].ProfileName,
			NET_PROFILE_NAME_LEN_MAX+1, "%s", profile_name.ProfileName);

	if ((Error = _net_dbus_open_connection(profile_name.ProfileName)) != NET_ERR_NONE) {
		NETWORK_LOG(NETWORK_ERROR,
				"Error!! Failed to request open connection, Error [%s]\n",
				_net_print_error(Error));

		if(request_table[NETWORK_REQUEST_TYPE_OPEN_CONNECTION].flag == TRUE)
			memset(&request_table[NETWORK_REQUEST_TYPE_OPEN_CONNECTION],
					0, sizeof(network_request_table_t));

		__NETWORK_FUNC_EXIT__;
		return Error;
	}

	NETWORK_LOG(NETWORK_HIGH, "Connect Request Success for ProfileName[%s]\n",
			profile_name.ProfileName);
	__NETWORK_FUNC_EXIT__;
	return NET_ERR_NONE;
}

/**
 * @fn   EXPORT_API int net_close_connection(const char *profile_name)
 *
 * This function requests close connection for the given profile name.
 * This is Async API.
 *
 * @return       int - NET_ERR_NONE on success, negative values for errors
 * @param[in]    char *profile_name - Connected profile Name
 * @param[out]   none
 */

EXPORT_API int net_close_connection(const char *profile_name)
{
	__NETWORK_FUNC_ENTER__;
	
	net_err_t Error = NET_ERR_NONE;

	NETWORK_LOG(NETWORK_HIGH, "ProfileName [%s] passed\n", profile_name);

	if (_net_check_profile_name(profile_name) != NET_ERR_NONE) {
		 NETWORK_LOG(NETWORK_ERROR, "Error!! Invalid ProfileName parameter\n");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_INVALID_PARAM;
	}

	if (NetworkInfo.ClientEventCb == NULL) {
		NETWORK_LOG(NETWORK_ERROR, "Error!!! Application was not registered\n");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_APP_NOT_REGISTERED;
	}
	
	if (request_table[NETWORK_REQUEST_TYPE_CLOSE_CONNECTION].flag == TRUE) {
		NETWORK_LOG(NETWORK_ASSERT, "Error!!! Request already in progress\n");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_INVALID_OPERATION;
	}
	
	request_table[NETWORK_REQUEST_TYPE_CLOSE_CONNECTION].flag = TRUE;
	snprintf(request_table[NETWORK_REQUEST_TYPE_CLOSE_CONNECTION].ProfileName,
			NET_PROFILE_NAME_LEN_MAX+1, "%s", profile_name);

	if ((Error = _net_dbus_close_connection(profile_name)) != NET_ERR_NONE) {
		NETWORK_LOG(NETWORK_ERROR,
				"Error!! Failed to request close connection, Error [%s]\n", 
				_net_print_error(Error));
	
		if (request_table[NETWORK_REQUEST_TYPE_CLOSE_CONNECTION].flag == TRUE)
			memset(&request_table[NETWORK_REQUEST_TYPE_CLOSE_CONNECTION],
					0, sizeof(network_request_table_t));

		__NETWORK_FUNC_EXIT__;
		return Error;
	}
	
	__NETWORK_FUNC_EXIT__;	
	return NET_ERR_NONE;
}

#ifdef __cplusplus
}
#endif /* __cplusplus */
