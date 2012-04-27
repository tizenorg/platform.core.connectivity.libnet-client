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


#ifndef __NETWORK_WIFI_INTF_H_
#define __NETWORK_WIFI_INTF_H_

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @file network-wifi-intf.h
 * @brief This file defines the Wi-Fi specific interface with the application/Connection Manager.
*/

/**
 * \addtogroup  wifi_specific
 * \{
*/
/*****************************************************************************
 * 	Standard headers
 *****************************************************************************/

/*****************************************************************************
 * 	Platform headers
 *****************************************************************************/

#include "network-pm-wlan.h"
#include "network-cm-intf.h"

/*****************************************************************************
 * 	Macros and Typedefs
 *****************************************************************************/


/*****************************************************************************
 * 	Global Enums 
 *****************************************************************************/

/**
* @enum net_wifi_state_t
* This enum indicates wifi state
*/
typedef enum {
	/** Unknown state */
	WIFI_UNKNOWN = 0x00,
	/** Wi-Fi is Off */
	WIFI_OFF,
	/** Wi-Fi is On(idle/failure) */
	WIFI_ON,
	/** Trying to connect(association/configuration) */
	WIFI_CONNECTING,
	/** Wi-Fi is connected to an AP(ready/online) */
	WIFI_CONNECTED,
	/** Trying to disconnect(connected, but disconnecting process is on going) */
	WIFI_DISCONNECTING,
} net_wifi_state_t; 

/**
*@enum net_wifi_background_scan_mode_t
* This enum indicates background scanning mode.
*/
typedef enum {
	/** scan cycle : 300s */
	WIFI_BGSCAN_MODE_DEFAULT = 0x00,
	/** scan cycle : 10s */
	WIFI_BGSCAN_MODE_PERIODIC,
	/** scan cycle : 4, 8, 16, ...128s */
	WIFI_BGSCAN_MODE_EXPONENTIAL,
} net_wifi_background_scan_mode_t;

/**
*@enum net_wifi_wps_type_t
* This enum indicates WPS type.
*/
typedef enum
{
	/** WPS type is PBC */
	WIFI_WPS_PBC = 0x00,
	/** WPS type is PIN */
	WIFI_WPS_PIN
} net_wifi_wps_type_t;

/*****************************************************************************
 * 	Global Structures
 *****************************************************************************/

/**
 * This is the structure to connect with WPS network.
 */
typedef struct {
	/** PBC / PIN */
	net_wifi_wps_type_t type;
	
	/** Optional. This pin is needed when the user input PIN code */
	char pin[NET_WLAN_MAX_WPSPIN_LEN + 1];
} net_wifi_wps_info_t;

/**
 * This is the profile structure to connect hidden WiFi network.
 */
typedef struct {
	/** Basic feature */
	char essid[NET_WLAN_ESSID_LEN + 1];

	/** Infrastructure / ad-hoc / auto mode */
	wlan_connection_mode_type_t wlan_mode;

	/** Security mode and authentication info */
	wlan_security_info_t security_info;
} net_wifi_connection_info_t;

/*****************************************************************************
 * 	Typedefs 
 *****************************************************************************/


/*****************************************************************************
 * 	Global Functions 
 *****************************************************************************/

	
/*****************************************************************************
 * 	ConnMan Wi-Fi Client Interface Synchronous API Declaration
 *****************************************************************************/


/**
 * @fn   int net_get_wifi_state(net_wifi_state_t *current_state, net_profile_name_t *profile_name)
 *
 * This function requests current state of wifi.
 *
 * \par Sync (or) Async:
 * These is a Synchronous API.
 *
 * @param[in]    none
 * @param[out]   current_state  Current wifi state
 * @param[out]   profile_name   Profile name of current Wi-Fi state\n
 *                              (valid for WIFI_CONNECTING, WIFI_CONNECTED, WIFI_DISCONNECTING state only)
 *
 * @return       NET_ERR_NONE on success, negative values for errors
 */

int net_get_wifi_state(net_wifi_state_t *current_state, net_profile_name_t *profile_name);


/**
 * @fn   int net_wifi_set_background_scan_mode(net_wifi_background_scan_mode_t scan_mode)
 *
 * This function sends set background scan mode request to ConnMan daemon,
 * with background scan mode - default/periodic/exponential
 * Background scan trigger is restarted if the same mode is set again.
 *
 * \par Sync (or) Async:
 * These is a Synchronous API.
 *
 * @param[in]    scan_mode  default/periodic/exponential
 * @param[out]   none
 *
 * @return       NET_ERR_NONE on success, negative values for errors
 */

int net_wifi_set_background_scan_mode(net_wifi_background_scan_mode_t scan_mode);

/*****************************************************************************
 * 	ConnMan Wi-Fi Client Interface Asynchronous Function Declaration
 *****************************************************************************/

/**
 * @fn   int net_open_connection_with_wifi_info(const net_wifi_connection_info_t *wifi_info)
 *
 * This function requests Wi-Fi open connection. This should be used only for opening
 * connection with hidden ap
 *
 * \par Sync (or) Async:
 * This is an Asynchronous API.
 *
 * @param[in]    wifi_info  Pointer to connection information structure
 * @param[out]   none
 *
 * \par Async Response Message:
 *        NET_EVENT_OPEN_RSP: Connection Establishment response will be sent asynchronously to the App in the callback function registered.\n
 *        refer to net_event_cb_t()
 *
 * @return       NET_ERR_NONE on success, negative values for errors
 */

int net_open_connection_with_wifi_info(const net_wifi_connection_info_t *wifi_info);


/**
 * @fn   int net_scan_wifi(void)
 *
 * This function sends scan request to ConnMan daemon.\n
 * You can receive scan completion response(NET_EVENT_WIFI_SCAN_RSP) via the callback function registered,\n
 * and then get scan result by using net_get_profile_list().
 *
 *\par Sync (or) Async:
 * This is an Asynchronous API.
 *
 * @param[in]    none
 * @param[out]   none
 *
 * \par Async Response Message:
 *        NET_EVENT_WIFI_SCAN_RSP: Scan completion response will be sent asynchronously to the App in the callback function registered.\n
 *        refer to net_event_cb_t()
 *
 * @return       NET_ERR_NONE on success, negative values for errors
 */

int net_scan_wifi(void);


/**
 * @fn   int net_wifi_power_on(void)
 *
 * This function requests wifi power on.
 *
 * \par Sync (or) Async:
 * This is an Asynchronous API.
 *
 * @param[in]    none
 * @param[out]   none
 *
 * \par Async Response Message:
 *        NET_EVENT_WIFI_POWER_RSP: Wi-Fi Power on response will be sent asynchronously to the App in the callback function registered.\n
 *        refer to net_event_cb_t()
 *
 * @return       NET_ERR_NONE on success, negative values for errors
 */

int net_wifi_power_on(void);


/**
 * @fn   int net_wifi_power_off(void)
 *
 * This function requests wifi power off.
 *
 * \par Sync (or) Async:
 * This is an Asynchronous API.
 *
 * @param[in]    none
 * @param[out]   none
 *
 * \par Async Response Message:
 *        NET_EVENT_WIFI_POWER_RSP: Wi-Fi Power off response will be sent asynchronously to the App in the callback function registered.\n
 *        refer to net_event_cb_t()
 *
 * @return       NET_ERR_NONE on success, negative values for errors
 */

int net_wifi_power_off(void);


/**
 * @fn   int net_wifi_enroll_wps(const char *profile_name, net_wifi_wps_info_t *wps_info)
 *
 * This function sends enroll wps request to ConnMan daemon,
 * with profile name and wps information.
 *
 * \par Sync (or) Async:
 * This is an Asynchronous API.
 *
 * @param[in]    profile_name  Profile Name to be connected
 * @param[in]    wps_info      wps type and pin code for WPS PIN(optional)
 * @param[out]   none
 *
 * \par Async Response Message:
 *        NET_EVENT_WIFI_WPS_RSP : enroll wps response will be sent asynchronously to the App in the callback function registered.\n
 *        refer to net_event_cb_t()
 *
 * @return       NET_ERR_NONE on success, negative values for errors
 */

int net_wifi_enroll_wps(const char *profile_name, net_wifi_wps_info_t *wps_info);


/**
 * \}
 */

#ifdef __cplusplus
}
#endif

#endif /** __NETWORK_WIFI_INTF_H_ */
