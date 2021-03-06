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


#ifndef __NETWORK_INTERNAL_H_
#define __NETWORK_INTERNAL_H_

/*****************************************************************************
 * 	Standard headers
 *****************************************************************************/
#include <stdio.h> 
#include <errno.h> 
#include <stdlib.h> 
#include <string.h>
#include <glib.h>

#include <dbus/dbus.h> 

#include <net/if.h>			/** for IFNAMSIZ and co... */

/*****************************************************************************
 * 	Platform headers
 *****************************************************************************/
#include "network-pm-intf.h"
#include "network-cm-intf.h"
#include "network-wifi-intf.h"

/*****************************************************************************
 * 	Macros and Typedefs
 *****************************************************************************/

/** Maximum Profile Count */
#define NET_PROFILE_LIST_MAX 512

#define NET_TECH_LENGTH_MAX 64

#define CONNMAN_MAX_BUFLEN 512

#define	NET_MEMFREE(x)	{if(x != NULL) free(x); x = NULL;}

/** ConnMan Daemon Management interface */

#define CONNMAN_SERVICE                 "net.connman"

#define CONNMAN_MANAGER_INTERFACE		CONNMAN_SERVICE ".Manager"
#define CONNMAN_TECHNOLOGY_INTERFACE	CONNMAN_SERVICE ".Technology"
#define CONNMAN_SERVICE_INTERFACE		CONNMAN_SERVICE ".Service"
#define CONNMAN_PROFILE_INTERFACE		CONNMAN_SERVICE ".Profile"
#define CONNMAN_COUNTER_INTERFACE		CONNMAN_SERVICE ".Counter"
#define CONNMAN_ERROR_INTERFACE			CONNMAN_SERVICE ".Error"

#define CONNMAN_MANAGER_PATH			"/"
#define CONNMAN_PATH					"/net/connman"
#define CONNMAN_TECHNOLOGY_PATH			"/net/connman/technology"

/** Network related Daemon interfaces */

#define NETCONFIG_SERVICE				"net.netconfig"
#define NETCONFIG_WIFI_INTERFACE		NETCONFIG_SERVICE ".wifi"
#define NETCONFIG_STATISTICS_INTERFACE		NETCONFIG_SERVICE ".network_statistics"

#define NETCONFIG_WIFI_PATH				"/net/netconfig/wifi"
#define NETCONFIG_STATISTICS_PATH			"/net/netconfig/network_statistics"

#define TELEPHONY_SERVCE				"com.tcore.ps"
#define TELEPHONY_MASTER_INTERFACE		TELEPHONY_SERVCE ".master"
#define TELEPHONY_NETWORK_INTERFACE		TELEPHONY_SERVCE ".network"
#define TELEPHONY_PROFILE_INTERFACE		TELEPHONY_SERVCE ".context"
#define TELEPHONY_MASTER_PATH			"/"

/** Network related Daemon Signal Filters */

#define NETCONFIG_WIFI_FILTER			"type='signal',interface='net.netconfig.wifi'"

/** Network related Daemon Signals */

#define NETCONFIG_SIGNAL_POWERON_COMPLETED	"PowerOnCompleted"
#define NETCONFIG_SIGNAL_POWEROFF_COMPLETED	"PowerOffCompleted"
#define NETCONFIG_SIGNAL_SPECIFIC_SCAN_DONE	"SpecificScanCompleted"

/** ConnMan Daemon Signal Filters */

#define CONNMAN_MANAGER_SIGNAL_FILTER 		"type='signal',interface='net.connman.Manager'"
#define CONNMAN_TECHNOLOGY_SIGNAL_FILTER	"type='signal',interface='net.connman.Technology'"
#define CONNMAN_SERVICE_SIGNAL_FILTER		"type='signal',interface='net.connman.Service'"
#define CONNMAN_PROFILE_SIGNAL_FILTER		"type='signal',interface='net.connman.Profile'"
#define CONNMAN_NETWORK_COUNTER_FILTER		"type='signal',interface='net.connman.Counter'"

/** ConnMan Daemon Signals */

#define CONNMAN_SIGNAL_PROPERTY_CHANGED		"PropertyChanged"
#define CONNMAN_SIGNAL_STATE_CHANGED		"StateChanged"
#define CONNMAN_SIGNAL_SCAN_COMPLETED		"ScanCompleted"

/** ConnMan technology and profile prefixes for ConnMan 0.78 */

#define CONNMAN_CELLULAR_TECHNOLOGY_PREFIX		CONNMAN_PATH "/technology/cellular"
#define CONNMAN_WIFI_TECHNOLOGY_PREFIX			CONNMAN_PATH "/technology/wifi"
#define CONNMAN_ETHERNET_TECHNOLOGY_PREFIX		CONNMAN_PATH "/technology/ethernet"

#define CONNMAN_CELLULAR_SERVICE_PROFILE_PREFIX	CONNMAN_PATH "/service/cellular_"
#define CONNMAN_WIFI_SERVICE_PROFILE_PREFIX		CONNMAN_PATH "/service/wifi_"
#define CONNMAN_ETHERNET_SERVICE_PROFILE_PREFIX	CONNMAN_PATH "/service/ethernet_"


#ifdef VITA_FEATURE
#include <dlog.h>

#define CONNMAN_CLIENT_MID "network"

#define NETWORK_LOW 		LOG_VERBOSE
#define NETWORK_MED 		LOG_VERBOSE
#define NETWORK_HIGH 		LOG_VERBOSE
#define NETWORK_ERROR 		LOG_ERROR
#define NETWORK_EXCEPTION	LOG_WARN
#define NETWORK_ASSERT		LOG_WARN


#define NETWORK_LOG(log_level, format, args...) \
	SLOG(log_level,CONNMAN_CLIENT_MID, "[%s][Ln: %d] " format, __FILE__, __LINE__, ##args) 
#define __NETWORK_FUNC_ENTER__	/* NETWORK_LOG(NETWORK_HIGH, "Entering %s()\n", __func__) */
#define __NETWORK_FUNC_EXIT__	/* NETWORK_LOG(NETWORK_HIGH, "Quit: %s()\n", __func__) */

#else /** VITA_FEATURE */

#define NETWORK_LOG(log_level, format, args...) printf("[%s][Ln: %d] " format, __FILE__, __LINE__, ##args)
#define __NETWORK_FUNC_ENTER__	/* printf("Entering: %s:%d:%s()\n", __FILE__, __LINE__,__func__) */
#define __NETWORK_FUNC_EXIT__	/* printf("Quit: %s:%d:%s()\n", __FILE__, __LINE__,__func__) */

#endif /** VITA_FEATURE */


/*****************************************************************************
 * 	Global Enums
 *****************************************************************************/

typedef enum
{
	NETWORK_REQUEST_TYPE_SCAN = 0x00,
	NETWORK_REQUEST_TYPE_OPEN_CONNECTION,
	NETWORK_REQUEST_TYPE_CLOSE_CONNECTION,
	NETWORK_REQUEST_TYPE_WIFI_POWER,
	NETWORK_REQUEST_TYPE_ENROLL_WPS,
	NETWORK_REQUEST_TYPE_SPECIFIC_SCAN,
	NETWORK_REQUEST_TYPE_MAX
} network_async_request_type_t;


typedef struct
{
	int flag; /** TRUE/FALSE */
	char ProfileName[NET_PROFILE_NAME_LEN_MAX+1];
} network_request_table_t;

/*****************************************************************************
 * 	Global Structures
 *****************************************************************************/

typedef struct
{
	int num_of_services;
	char* ProfileName[NET_PROFILE_LIST_MAX];
} network_services_list_t;

typedef struct {
	net_wifi_state_t wifi_state;
	net_event_cb_t ClientEventCb;
	void* user_data;
	net_event_cb_t ClientEventCb_conn;
	void* user_data_conn;
	net_event_cb_t ClientEventCb_wifi;
	void* user_data_wifi;
	int ref_count;
} network_info_t;

typedef struct
{
	char technology[NET_TECH_LENGTH_MAX]; /** wifi, ethernet, cellular - strings */
	char AvailableTechnology;
	char EnabledTechnology;
	char ConnectedTechnology;
	char DefaultTechnology;
} network_get_tech_state_info_t;

/**
 * This is the profile structure exposed from modman.
 */
typedef struct
{
	/** Profile name */
	char			ProfileName[NET_PROFILE_NAME_LEN_MAX+1];
	/** Service type of this profile context */
	net_service_type_t	ServiceType;
	/** Network Access Point Name */
	char			Apn[NET_PDP_APN_LEN_MAX+1];
	/** Authentication info of the PDP profile */
	net_auth_info_t	AuthInfo;
	/**Proxy address */
	char			ProxyAddr[NET_PROXY_LEN_MAX+1];
	/** Browser Home URL or MMS server URL */
	char			HomeURL[NET_HOME_URL_LEN_MAX+1];
} net_telephony_profile_info_t;

/*****************************************************************************
 * 	Global Functions 
 *****************************************************************************/
net_device_t _net_get_tech_type_from_path(const char *profile_name);
char* _net_get_string(DBusMessage* msg);
unsigned long long _net_get_uint64(DBusMessage* msg);
char* _net_get_object(DBusMessage* msg);
int _net_get_boolean(DBusMessage* msg);
int _net_get_path(DBusMessage *msg, char *profile_name);
int _net_get_tech_state(DBusMessage* msg, network_get_tech_state_info_t* tech_state);
char* _net_print_error(net_err_t error);
int _net_open_connection_with_wifi_info(const net_wifi_connection_info_t* wifi_info);
int _net_check_profile_name(const char* ProfileName);
int _net_get_profile_list(net_device_t device_type, net_profile_info_t** profile_info, int* profile_count);
int _net_mutex_init(void);
void _net_mutex_destroy(void);
void _net_client_callback(net_event_info_t *event_data);
int _net_get_service_profile(net_service_type_t service_type, net_profile_name_t *profile_name);
int _net_get_default_profile_info(net_profile_info_t *profile_info);
net_wifi_state_t _net_get_wifi_state(void);
void _net_clear_request_table(void);

#endif /** __NETWORK_INTERNAL_H_ */
