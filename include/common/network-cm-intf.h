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

#ifndef __NETWORK_CM_INTF_H__
#define __NETWORK_CM_INTF_H__

#include "network-pm-intf.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#ifndef DEPRECATED
#define DEPRECATED __attribute__((deprecated))
#endif

/**
 * @file network-cm-intf.h
 * @brief This file defines the interface of Connection Manager with the application.
*/

/**
 * \addtogroup  common_basic
 * \{
*/

/*==================================================================================================
                                           CONSTANTS
==================================================================================================*/

/*==================================================================================================
                                             ENUMS
==================================================================================================*/

/**
 * @enum net_event_t
 * Callback Event
 */

typedef enum
{
	/** Open Connection Response Event*/
	NET_EVENT_OPEN_RSP,

	/** Close Connection Response Event*/
	NET_EVENT_CLOSE_RSP,

	/** Open connection Indication (auto join) */
	NET_EVENT_OPEN_IND,

	/** Connection Close Indication Event */
	NET_EVENT_CLOSE_IND,

	/** Network service(profile) state changed Indication Event*/
	NET_EVENT_NET_STATE_IND,

	/** Network IP change Indication Event\n
	 *  This is deprecated Event and maintained only for compatibility */
	NET_EVENT_IP_CHANGE_IND,

	/** Profile modify indication Event\n
	 *  This is deprecated Event and maintained only for compatibility */
	NET_EVENT_PROFILE_MODIFY_IND,

	/** Network configuration changed Event\n
	 *  This is deprecated Event and maintained only for compatibility */
	NET_EVENT_NET_CONFIGURE_RSP,

	/* Wi-Fi Specific events */

	/** Wi-Fi interface Scan Response Event */
	NET_EVENT_WIFI_SCAN_RSP,

	/** Wi-Fi interface Scan Indication Event(BG scan) */
	NET_EVENT_WIFI_SCAN_IND,

	/** Wi-Fi interface MAC changed Event\n
	 *  This is deprecated Event and maintained only for compatibility */
	NET_EVENT_WIFI_MAC_ID_IND,

	/** Wi-Fi interface Power On/Off Response Event */
	NET_EVENT_WIFI_POWER_RSP,

	/** Specific Scan Response Event */
	NET_EVENT_SPECIFIC_SCAN_RSP,

	/** Wi-Fi interface Scan Indication Event(Specific scan) */
	NET_EVENT_SPECIFIC_SCAN_IND,

	/** Wi-Fi interface Power On/Off Indication Event */
	NET_EVENT_WIFI_POWER_IND,

	/** Wi-Fi interface WPS Response Event */
	NET_EVENT_WIFI_WPS_RSP,

	/** Set default cellular profile Response Event */
	NET_EVENT_CELLULAR_SET_DEFAULT_RSP,

	/** Reset default cellular profile Response Event */
	NET_EVENT_CELLULAR_RESET_DEFAULT_RSP,

	/** Wi-Fi interface Scanning Indication Event */
	NET_EVENT_WIFI_SCANNING_IND,

	/** Wi-Fi interface Scan Indication Event(WPS scan) */
	NET_EVENT_WPS_SCAN_IND,

	/** Ethernet Cable Attached Event */
	NET_EVENT_ETHERNET_CABLE_ATTACHED,

	/** Ethernet Cable Detached Event */
	NET_EVENT_ETHERNET_CABLE_DETACHED,

	/** Wi-Fi TDLS Peer Connected EVENT */
	NET_EVENT_TDLS_CONNECTED_IND,

	/** Wi-Fi TDLS Peer Disconnect EVENT */
	NET_EVENT_TDLS_DISCONNECTED_IND,
} net_event_t;

/**
 * \}
 */

/**
 * \addtogroup  common_info
 * \{
*/

/**
* @enum net_cm_network_status_t
* This enum indicates network status
*/
typedef enum
{
	/** Service unknown */
	NET_STATUS_UNKNOWN,
	/** Not connected / Suspended / Idle / Connecting/ Disconnecting/ Killing*/
	NET_STATUS_UNAVAILABLE,
	/** Active */
	NET_STATUS_AVAILABLE,
} net_cm_network_status_t;

/**
 * @brief Enumerations of statistics type.
 */
typedef enum
{
	NET_STATISTICS_TYPE_LAST_RECEIVED_DATA = 0,		/**< Last received data */
	NET_STATISTICS_TYPE_LAST_SENT_DATA = 1,			/**< Last sent data */
	NET_STATISTICS_TYPE_TOTAL_RECEIVED_DATA = 2,	/**< Total received data */
	NET_STATISTICS_TYPE_TOTAL_SENT_DATA = 3,		/**< Total sent data */
} net_statistics_type_e;

/**
 * \}
 */

/**
 * \addtogroup  common_basic
 * \{
*/

/*==================================================================================================
                                 STRUCTURES AND OTHER TYPEDEFS
==================================================================================================*/

/**
 * Event Info with Event on callback
 */

typedef struct
{
	/** CM Asynchronous event */
	net_event_t	Event;
	/** Profile Identifier corresponding to the event */
	char		ProfileName[NET_PROFILE_NAME_LEN_MAX+1];
	/** Event Status */
	net_err_t	Error;
	/** Event data length */
	int 		Datalength;
	/** Event data: Depending on the event, Event Data will be
	type-casted to the appropriate event info data structure */
	void *		Data;
} net_event_info_t;

/**
 * Technology properties
 */

typedef struct
{
	/** powered state */
	char		powered;
	/** connected state */
	char		connected;
} net_tech_info_t;


/*****************************************************************************************/
/* Callback function prototype
 * typedef void (*net_event_cb_t)(const net_event_info_t* net_event, void* user_data);
 */

/**
 * \brief callback function: used to notify client application about Asynchronous events.
 * This callback function will be called in the Network Client Library(NCL) context.
 *
 * \par Important Notes:
 * NCL will allocate the memory for event data.
 * Once Context will return from callback then NCL will free the memory allocated to event data.
 * Application is not supposed to free the memory pointed by net_event
 *
 * \param[out] net_event    Pointer to net_event_info_t structure
 * \param[out] user_data    User can transfer the user specific data in callback
 *
 * \par Description of each event type(net_event->Event) :
 *
 * - NET_EVENT_OPEN_RSP \n
 *     Response event for (net_open_connection_with_profile(), net_open_connection_with_preference(), net_open_connection_with_wifi_info())
 *     to notify the result of open connection request.
 *   - net_event->ProfileName : Profile Identifier corresponding to the event
 *   - net_event->Error       : Its value will be NET_ERR_NONE in case of success and error cause in case of failure
 *   - net_event->Data        : Pointer to net_profile_info_t (valid at NET_ERR_NONE, NET_ERR_ACTIVE_CONNECTION_EXISTS)
 *     - If the connection open successfully or already exists for the given profile name,\n
 *       application can get the connected profile information \n
 *       If the connection is failed to establish, net_profile_info_t also contains NULL value
 *
 * - NET_EVENT_CLOSE_RSP \n
 *     Response event for net_close_connection() to notify the result of close connection request.
 *   - net_event->ProfileName : Profile Identifier corresponding to the event
 *   - net_event->Error       : Its value will be NET_ERR_NONE in case of success and error cause in case of failure
 *   - net_event->Data        : NULL (not used in this event)
 *
 * - NET_EVENT_OPEN_IND \n
 *     Indication to notify the activation of a connection by any other application or auto-connection.
 *   - net_event->ProfileName : Profile Identifier corresponding to the event
 *   - net_event->Error       : Its value will be NET_ERR_NONE in case of success and error cause in case of failure
 *   - net_event->Data        : Pointer to net_profile_info_t
 *     - If NCL can't get profile info from ConnMan, net_profile_info_t contains NULL value
 *
 * - NET_EVENT_CLOSE_IND \n
 *     Indication to notify the closure of an active connection due to network initiated termination or any other transport connectivity loss.
 *   - net_event->ProfileName : Profile Identifier corresponding to the event
 *   - net_event->Error       : Its value will be NET_ERR_NONE always
 *   - net_event->Data        : NULL (not used in this event)
 *
 * - NET_EVENT_NET_STATE_IND \n
 *     Indication to notify that state of each serivce(profile) changed.\n
 *     You can use this event to get more detailed state, but should be used carefully.\n
 *     This event comes from ConnMan daemon via NCL, so you have to understand ConnMan's state.\n
 *     There is no need to handle this event except under special circumstances.
 *   - net_event->ProfileName : Profile Identifier corresponding to the event
 *   - net_event->Error       : Its value will be NET_ERR_NONE always
 *   - net_event->Data        : Pointer to net_state_type_t
 *
 * - NET_EVENT_WIFI_SCAN_RSP \n
 *     Response event for net_scan_wifi() to notify the result of scan request.
 *   - net_event->ProfileName : NULL (not used in this event)
 *   - net_event->Error       : NET_ERR_NONE on success, negative values for errors
 *   - net_event->Data        : NULL (not used in this event)
 *
 * - NET_EVENT_WIFI_SCAN_IND \n
 *     Indication to notify that BG scan has been completed.
 *   - net_event->ProfileName : NULL (not used in this event)
 *   - net_event->Error       : NET_ERR_NONE on success, negative values for errors
 *   - net_event->Data        : NULL (not used in this event)
 *
 * - NET_EVENT_WIFI_POWER_RSP \n
 *     Response event for (net_wifi_power_on(), net_wifi_power_off()) to notify the result of Wi-Fi power on request.
 *   - net_event->ProfileName : NULL (not used in this event)
 *   - net_event->Error       : NET_ERR_NONE on success, negative values for errors
 *   - net_event->Data        : Pointer to net_wifi_state_t (only WIFI_OFF/WIFI_ON/WIFI_UNKNOWN will be set)
 *
 * - NET_EVENT_WIFI_POWER_IND \n
 *     Indication to notify that Wi-Fi power state has been changed.
 *   - net_event->ProfileName : NULL (not used in this event)
 *   - net_event->Error       : NET_ERR_NONE on success, negative values for errors
 *   - net_event->Data        : Pointer to net_wifi_state_t (only WIFI_OFF/WIFI_ON/WIFI_UNKNOWN will be set)
 *
 * - NET_EVENT_WIFI_WPS_RSP \n
 *     Response event for net_wifi_enroll_wps() to notify the result of enroll wps request.
 *   - net_event->ProfileName : Profile Identifier corresponding to the event
 *   - net_event->Error       : Its value will be NET_ERR_NONE in case of success and error cause in case of failure
 *   - net_event->Data        : Pointer to net_profile_info_t
 *     - If the connection open successfully, application can get the connected profile information \n
 *       If the connection is failed to establish, net_profile_info_t also contains NULL value
 *
 * - NET_EVENT_SPECIFIC_SCAN_IND \n
 *     Response event for net_specific_scan_wifi() to notify the BSSs which are found.
 *   - net_event->ProfileName : NULL (not used in this event)
 *   - net_event->Error       : Its value will be NET_ERR_NONE in case of success and error cause in case of failure
 *   - net_event->Data        : Pointer to GSList of struct ssid_scan_bss_info_t
 *   - net_event->Datalength  : The number of BSSs which are found
 *     - Do not delete and modify Data and Datalength and they are destroyed automatically
 *
 */

typedef void (*net_event_cb_t)(const net_event_info_t* net_event, void* user_data);

/*==================================================================================================
                                     FUNCTION PROTOTYPES
==================================================================================================*/

/*****************************************************************************************/
/* net_register_client API function prototype
 * int net_register_client(net_event_cb_t event_cb, void *user_data);
 */

/**
 * \brief 	This API shall register the client application with the ConnMan.
 *
 * \par Sync (or) Async:
 * This is a Synchronous API.
 *
 * \par Important Notes:
 *        It is mandatory for the client application to register with ConnMan with this API before using any of its services.\n
 *        The value of event_cb cannot be NULL. Otherwise, error NET_ERR_INVALID_PARAM will be returned by the API.\n
 *        All the Asynchronous Events from ConnMan will be sent to the client App through the callback function (event_cb) registered with this API.
 *
 * \warning
 *  None
 *
 * \param[in] event_cb     Application Callback function pointer to receive ConnMan events
 * \param[in] user_data    user data
 *
 * \par Async Response Message:
 *        None.
 * \par Precondition:
 *        None.
 *
 * \return Return Type (int) \n
 * - NET_ERR_NONE  - indicating that the operation has completed successfully.\n
 * - NET_ERR_INVALID_PARAM - indicating that API parameter value is invalid.\n
 * - NET_ERR_APP_ALREADY_REGISTERED - indicating that client application is already registered,it can't be registered again.\n
 * - NET_ERR_UNKNOWN - indicating that registration has failed.\n
 *
 * \par Prospective Clients:
 * External Apps.
 *
 * \par Example Program:
 *
 * int result;
 *
 * result = net_register_client(event_cb , user_data);
 *
 * if(result == NET_ERR_NONE).........
 *
 *
 *
******************************************************************************************/
int net_register_client(net_event_cb_t event_cb, void *user_data);

/*****************************************************************************************/
/* net_deregister_client API function prototype
* int net_deregister_client(void);
*/

/**
 * \brief This API shall deregister the client application with the ConnMan.
 *
 * \par Sync (or) Async:
 * This is a Synchronous API.
 *
 * \par Important Notes:
 *        After deregistration, Application will be restricted from using other ConnMan APIs/Services.\n
 *        De-register is not allowed when any connection is in active or transition state (activation or deactivation in progress).
 *
 * \warning
 *  None
 *
 *
 * \par Async Response Message:
 *        None
 *
 * \par Precondition:
 *        Application must already be registered with the ConnMan.
 *
 * \return Return Type (int) \n
 * - NET_ERR_NONE  - indicating that the operation has completed successfully. \n
 * - NET_ERR_APP_NOT_REGISTERED - indicating that client is not registered with CM and it cannot use CM services.\n
 * - NET_ERR_UNKNOWN - indicating that an unknown error has occurred.\n
 *
 *
 * \par Prospective Clients:
 * External Apps.
 *
 * \par Example Program:
 *
 * int result;
 *
 * result = net_deregister_client();
 *
 * if(result == NET_ERR_NONE).........
 *
 *
 *
******************************************************************************************/
int net_deregister_client(void);

/*****************************************************************************************/
/* net_open_connection_with_profile API function prototype
 * int net_open_connection_with_profile(const char *profile_name);
 */

/**
 * \brief  This API will establish a data connection with specific profile name
 *
 * \par Sync (or) Async:
 * This is an Asynchronous API.
 *
 * \par Important Notes:
 *        This API is a Non-Blocking API. Return value only implies whether the request is sent successfully or not. \n
 *            Return value Success does not imply that the connection is established successfully. \n
 *	      If application needs to make a connection with specific profile name, it can make a connection with this api. \n
 *	      Get the profile name is referred to net_get_profile_list(). \n
 * 	      If Connection is already existed, this API will share the active connection with the calling application. \n
 *	      If Connection is already existed, and same application is trying to open connection, this API will return error.
 *
 * \par Notes :
 *
 *	ConnMan requests transport plug-in interface to open a new connection only if connection is not already established. \n
 *      If there is already a connection , then same connection will be shared.
 *
 * \warning
 *  None
 *
 * \param [in]	profile_name     specific profile name
 *
 * \par Async Response Message:
 *        NET_EVENT_OPEN_RSP: Connection Establishment response will be sent asynchronously to the App in the callback function registered.\n
 *        refer to net_event_cb_t()
 *
 * \par Precondition:
 *        Application must already be registered with the ConnMan.
 *
 * \return Return Type (int) \n
 * - NET_ERR_NONE  - indicating that the operation has completed successfully. \n
 * - NET_ERR_APP_NOT_REGISTERED -indicating that client is not registered with CM and it cannot use CM services.\n
 * - NET_ERR_INVALID_PARAM - indicating that API parameter value is invalid.\n
 * - NET_ERR_INVALID_OPERATION  - indicating that open connection operation is not allowed in the current state.\n
 * - NET_ERR_UNKNOWN - indicating that an unknown error has occurred.\n
 *
 *
 * \par Prospective Clients:
 * External Apps.
 *
 * \par Example Program:
 *
 * int result;
 *
 * result = net_open_connection_with_profile(profile_name);
 *
 * if(result == NET_ERR_NONE)......
 *
 *
 *
******************************************************************************************/
int net_open_connection_with_profile(const char *profile_name);

/*****************************************************************************************/
/* net_open_connection_with_preference API function prototype
 * int net_open_connection_with_preference(net_service_type_t service_type);
 */

/**
 * \brief  This API will establish a data connection with specific service type
 *
 * \par Sync (or) Async:
 * This is an Asynchronous API.
 *
 * \par Important Notes:
 *        This API is a Non-Blocking API. Return value only implies whether the request is sent successfully or not. \n
 *            Return value Success does not imply that the connection is established successfully. \n
 *	      If application needs to make a connection with specific service type, it can make a connection with this api. \n
 * 	      If Connection is already existed, this API will share the active connection with the calling application. \n
 *	      If Connection is already exited, and same application is trying to open connection, this API will return error.
 *
 * \par Notes :
 *
 *	ConnMan requests transport plug-in interface to open a new connection only if connection is not already established. \n
 *      If there is already a connection , then same connection will be shared.
 *
 * \warning
 *  None
 *
 * \param [in]	service_type     specific service type
 *
 * \par Async Response Message:
 *        NET_EVENT_OPEN_RSP: Connection Establishment response will be sent asynchronously to the App in the callback function registered.\n
 *        refer to net_event_cb_t()
 *
 * \par Precondition:
 *        Application must already be registered with the ConnMan.
 *
 * \return Return Type (int) \n
 * - NET_ERR_NONE - indicating that the operation has completed successfully. \n
 * - NET_ERR_APP_NOT_REGISTERED - indicating that client is not registered with CM and it cannot use CM services.\n
 * - NET_ERR_INVALID_PARAM - indicating that API parameter value is invalid.\n
 * - NET_ERR_INVALID_OPERATION - indicating that open connection operation is not allowed in the current state.\n
 * - NET_ERR_NO_SERVICE - indicating that service is not found.\n
 * - NET_ERR_UNKNOWN - indicating that an unknown error has occurred.\n
 *
 *
 * \par Prospective Clients:
 * External Apps.
 *
 * \par Example Program:
 *
 * int result;
 *
 * result = net_open_connection_with_preference(service_type);
 *
 * if(result == NET_ERR_NONE)......
 *
 *
 *
******************************************************************************************/
int net_open_connection_with_preference(net_service_type_t service_type);

/*****************************************************************************************/
/* net_close_connection API function prototype
 * int net_close_connection(const char *profile_name);
 */

/**
 * \brief 	This API will terminate the connection. This API can also be used to abort a connection in progress.
 *
 * \par Sync (or) Async:
 * This is an Asynchronous API.
 *
 * \par Important Notes:
 *        This API is an Asynchronous API. Return value only implies whether the request is sent successfully or not. Return value Success doesn't imply that the connection is disconnected successfully.\n
 *
 * \warning
 *  None
 *
 * \par Notes :
 *		Application must be already registered with the ConnMan. \n
 *
 * \param [in]	profile_name     specific profile name
 *
 * \par Async Response Message:
 *        NET_EVENT_CLOSE_RSP: Connection Close response will be sent asynchronously to the App in the callback function registered\n
 *        refer to net_event_cb_t()
 *
 * \par Precondition:
 *        Application must have an active data connection
 *
 * \return Return Type (int) \n
 * - NET_ERR_NONE  - indicating that the operation has completed successfully. \n
 * - NET_ERR_APP_NOT_REGISTERED - indicating that client is not registered with CM and it cannot use CM services.\n
 * - NET_ERR_INVALID_OPERATION  - indicating that close connection operation is not allowed in the current state.\n
 * - NET_ERR_UNKNOWN - indicating that an unknown error has occurred.\n
 *
 * \par Prospective Clients:
 * External Apps.
 *
 * \par Example Program:
 *
 * int result;
 *
 * result = net_close_connection(profile_name);
 *
 * if(result == NET_ERR_NONE).........
 *
 *
 *
******************************************************************************************/
int net_close_connection(const char *profile_name);

/**
 * \}
 */

/**
 * \addtogroup  common_info
 * \{
*/

/*****************************************************************************************/
/* net_get_active_net_info API function prototype
 * int net_get_active_net_info(net_profile_info_t *active_profile_info);
 */

/**
 * \brief  This API returns the information of active(default) network profile.
 *
 * \par Sync (or) Async:
 * This is a Synchronous API.
 *
 * \par Important Notes:
 *  		On success, profile information shall be copied to active_profile_info parameter in net_profile_info_t format.
 *
 * \par Notes :
 *  None
 *
 * \warning
 *  None
 *
 * \param[out] 	active_profile_info 	The information of active(default) network profile.
 *
 * \par Async Response Message:
 *  None
 *
 * \par Precondition:
 *        Application must already be registered with the CM server.
 *
 * \return Return Type (int) \n
 * - NET_ERR_NONE  - indicating that the status of queried network interface is retrieved. \n
 * - NET_ERR_APP_NOT_REGISTERED - indicating that client is not registered with CM and it cannot use CM services.\n
 * - NET_ERR_UNKNOWN - indicating that an unknown error has occurred.\n
 * - NET_ERR_INVALID_PARAM - indicating that API parameter value is invalid.\n
 * - NET_ERR_NO_SERVICE - indicating that there is no active network.\n
 *
 * \par Prospective Clients:
 * External Apps.
 *
 * \par Example Program:
 *
 * net_profile_info_t active_profile_info;
 *
 * int result = net_get_active_net_info(&active_profile_info);
 *
 * if(result == NET_ERR_NONE)......
 *
 *
 *
******************************************************************************************/
int net_get_active_net_info(net_profile_info_t *active_profile_info);

/*****************************************************************************************/
/**
 * \brief  This API returns ip address of active(default) network profile.
 *
 * \par Sync (or) Async:
 * These is a Synchronous API.
 *
 * \par Important Notes:
 *  		On success, the information shall be copied to the parameter in each format.
 *
 * \param[out] 	ip_address  ip address of active(default) network profile.
 *
 * \par Precondition:
 *        Application must already be registered with the CM server.
 *
 * \return Return Type (int) \n
 * - NET_ERR_NONE  - indicating that the status of queried network interface is retrieved. \n
 * - NET_ERR_APP_NOT_REGISTERED - indicating that client is not registered with CM and it cannot use CM services.\n
 * - NET_ERR_UNKNOWN - indicating that an unknown error has occurred.\n
 * - NET_ERR_INVALID_PARAM - indicating that API parameter value is invalid.\n
 * - NET_ERR_NO_SERVICE - indicating that there is no active network.\n
 *
 * \par Prospective Clients:
 * External Apps.
 *
 * \par Example Program:
 *
 * net_addr_t ip_address;
 *
 * int result = net_get_active_ipaddress(&ip_address);
 *
 * if(result == NET_ERR_NONE)......
 *
******************************************************************************************/
int net_get_active_ipaddress(net_addr_t *ip_address);

/*****************************************************************************************/
/**
 * \brief  This API returns netmask address of active(default) network profile.
 *
 * \par Sync (or) Async:
 * These is a Synchronous API.
 *
 * \par Important Notes:
 *  		On success, the information shall be copied to the parameter in each format.
 *
 * \param[out] 	netmask  netmask address of active(default) network profile.
 *
 * \par Precondition:
 *        Application must already be registered with the CM server.
 *
 * \return Return Type (int) \n
 * - NET_ERR_NONE  - indicating that the status of queried network interface is retrieved. \n
 * - NET_ERR_APP_NOT_REGISTERED - indicating that client is not registered with CM and it cannot use CM services.\n
 * - NET_ERR_UNKNOWN - indicating that an unknown error has occurred.\n
 * - NET_ERR_INVALID_PARAM - indicating that API parameter value is invalid.\n
 * - NET_ERR_NO_SERVICE - indicating that there is no active network.\n
 *
 * \par Prospective Clients:
 * External Apps.
 *
 * \par Example Program:
 *
 * net_addr_t netmask;
 *
 * int result = net_get_active_netmask(&netmask);
 *
 * if(result == NET_ERR_NONE)......
 *
******************************************************************************************/
int net_get_active_netmask(net_addr_t *netmask);

/*****************************************************************************************/
/**
 * \brief  This API returns ipv6 address of active(default) network profile.
 *
 * \par Sync (or) Async:
 * These is a Synchronous API.
 *
 * \par Important Notes:
 *  		On success, the information shall be copied to the parameter in each format.
 *
 * \param[out] 	ip_address6  ipv6 address of active(default) network profile.
 *
 * \par Precondition:
 *        Application must already be registered with the CM server.
 *
 * \return Return Type (int) \n
 * - NET_ERR_NONE  - indicating that the status of queried network interface is retrieved. \n
 * - NET_ERR_APP_NOT_REGISTERED - indicating that client is not registered with CM and it cannot use CM services.\n
 * - NET_ERR_UNKNOWN - indicating that an unknown error has occurred.\n
 * - NET_ERR_INVALID_PARAM - indicating that API parameter value is invalid.\n
 * - NET_ERR_NO_SERVICE - indicating that there is no active network.\n
 *
 * \par Prospective Clients:
 * External Apps.
 *
 * \par Example Program:
 *
 * net_addr_t ip_address6;
 *
 * int result = net_get_active_ipaddress6(&ip_address6);
 *
 * if(result == NET_ERR_NONE)......
 *
******************************************************************************************/
int net_get_active_ipaddress6(net_addr_t *ip_address6);

/*****************************************************************************************/
/**
 * \brief  This API returns Prefix Length of IPv6 address of active(default) network profile.
 *
 * \par Sync (or) Async:
 * These is a Synchronous API.
 *
 * \par Important Notes:
 *  		On success, the information shall be copied to the parameter in each format.
 *
 * \param[out] 	prefixlen6  Prefix Length of IPv6 address of active(default) network profile.
 *
 * \par Precondition:
 *        Application must already be registered with the CM server.
 *
 * \return Return Type (int) \n
 * - NET_ERR_NONE  - indicating that the status of queried network interface is retrieved. \n
 * - NET_ERR_APP_NOT_REGISTERED - indicating that client is not registered with CM and it cannot use CM services.\n
 * - NET_ERR_UNKNOWN - indicating that an unknown error has occurred.\n
 * - NET_ERR_INVALID_PARAM - indicating that API parameter value is invalid.\n
 * - NET_ERR_NO_SERVICE - indicating that there is no active network.\n
 *
 * \par Prospective Clients:
 * External Apps.
 *
 * \par Example Program:
 *
 * int prefixlen6;
 *
 * int result = net_get_active_prefixlen6(&prefixlen6);
 *
 * if(result == NET_ERR_NONE)......
 *
******************************************************************************************/
int net_get_active_prefixlen6(int *prefixlen6);

/*****************************************************************************************/
/**
 * \brief  This API returns gateway address of active(default) network profile.
 *
 * \par Sync (or) Async:
 * These is a Synchronous API.
 *
 * \par Important Notes:
 *  		On success, the information shall be copied to the parameter in each format.
 *
 * \param[out] 	gateway  gateway address of active(default) network profile.
 *
 * \par Precondition:
 *        Application must already be registered with the CM server.
 *
 * \return Return Type (int) \n
 * - NET_ERR_NONE  - indicating that the status of queried network interface is retrieved. \n
 * - NET_ERR_APP_NOT_REGISTERED - indicating that client is not registered with CM and it cannot use CM services.\n
 * - NET_ERR_UNKNOWN - indicating that an unknown error has occurred.\n
 * - NET_ERR_INVALID_PARAM - indicating that API parameter value is invalid.\n
 * - NET_ERR_NO_SERVICE - indicating that there is no active network.\n
 *
 * \par Prospective Clients:
 * External Apps.
 *
 * \par Example Program:
 *
 * net_addr_t gateway;
 *
 * int result = net_get_active_gateway(&gateway);
 *
 * if(result == NET_ERR_NONE)......
 *
******************************************************************************************/
int net_get_active_gateway(net_addr_t *gateway);

/*****************************************************************************************/
/**
 * \brief  This API returns gateway IPv6 address of active(default) network profile.
 *
 * \par Sync (or) Async:
 * These is a Synchronous API.
 *
 * \par Important Notes:
 *  		On success, the information shall be copied to the parameter in
 *  		each format.
 *
 * \param[out] 	gateway6  gateway IPv6 address of active(default) network profile.
 *
 * \par Precondition:
 *        Application must already be registered with the CM server.
 *
 * \return Return Type (int) \n
 * - NET_ERR_NONE  - indicating that the status of queried network interface is
 *   retrieved. \n
 * - NET_ERR_APP_NOT_REGISTERED - indicating that client is not registered with
 *   CM and it cannot use CM services.\n
 * - NET_ERR_UNKNOWN - indicating that an unknown error has occurred.\n
 * - NET_ERR_INVALID_PARAM - indicating that API parameter value is invalid.\n
 * - NET_ERR_NO_SERVICE - indicating that there is no active network.\n
 *
 * \par Prospective Clients:
 * External Apps.
 *
 * \par Example Program:
 *
 * net_addr_t gateway6;
 *
 * int result = net_get_active_gateway6(&gateway6);
 *
 * if(result == NET_ERR_NONE)......
 *
******************************************************************************************/
int net_get_active_gateway6(net_addr_t *gateway6);

/*****************************************************************************************/
/**
 * \brief  This API returns DNS address of active(default) network profile.
 *
 * \par Sync (or) Async:
 * These is a Synchronous API.
 *
 * \par Important Notes:
 *  		On success, the information shall be copied to the parameter in each format.
 *
 * \param[out] 	dns  DNS address of active(default) network profile.
 *
 * \par Precondition:
 *        Application must already be registered with the CM server.
 *
 * \return Return Type (int) \n
 * - NET_ERR_NONE  - indicating that the status of queried network interface is retrieved. \n
 * - NET_ERR_APP_NOT_REGISTERED - indicating that client is not registered with CM and it cannot use CM services.\n
 * - NET_ERR_UNKNOWN - indicating that an unknown error has occurred.\n
 * - NET_ERR_INVALID_PARAM - indicating that API parameter value is invalid.\n
 * - NET_ERR_NO_SERVICE - indicating that there is no active network.\n
 *
 * \par Prospective Clients:
 * External Apps.
 *
 * \par Example Program:
 *
 * net_addr_t dns;
 *
 * int result = net_get_active_dns(&dns);
 *
 * if(result == NET_ERR_NONE)......
 *
******************************************************************************************/
int net_get_active_dns(net_addr_t *dns);

/*****************************************************************************************/
/**
 * \brief  This API returns ESSID of active(default) network profile.
 *
 * \par Sync (or) Async:
 * These is a Synchronous API.
 *
 * \par Important Notes:
 *  		On success, the information shall be copied to the parameter in each format.
 *
 * \param[out] 	essid  ESSID of active(default) network profile.
 *
 * \par Precondition:
 *        Application must already be registered with the CM server and wifi is connected.
 *
 * \return Return Type (int) \n
 * - NET_ERR_NONE  - indicating that the status of queried network interface is retrieved. \n
 * - NET_ERR_APP_NOT_REGISTERED - indicating that client is not registered with CM and it cannot use CM services.\n
 * - NET_ERR_UNKNOWN - indicating that an unknown error has occurred.\n
 * - NET_ERR_INVALID_PARAM - indicating that API parameter value is invalid.\n
 * - NET_ERR_NO_SERVICE - indicating that there is no active network.\n
 *
 * \par Prospective Clients:
 * External Apps.
 *
 * \par Example Program:
 *
 * net_essid_t essid;
 *
 * int result = net_get_active_essid(&essid);
 *
 * if(result == NET_ERR_NONE)......
 *
******************************************************************************************/
int net_get_active_essid(net_essid_t *essid);

/*****************************************************************************************/
/**
 * \brief  This API returns proxy string of active(default) network profile.
 *
 * \par Sync (or) Async:
 * These is a Synchronous API.
 *
 * \par Important Notes:
 *  		On success, the information shall be copied to the parameter in each format.
 *
 * \param[out] 	proxy  proxy string of active(default) network profile.
 *
 * \par Precondition:
 *        Application must already be registered with the CM server.
 *
 * \return Return Type (int) \n
 * - NET_ERR_NONE  - indicating that the status of queried network interface is retrieved. \n
 * - NET_ERR_APP_NOT_REGISTERED - indicating that client is not registered with CM and it cannot use CM services.\n
 * - NET_ERR_UNKNOWN - indicating that an unknown error has occurred.\n
 * - NET_ERR_INVALID_PARAM - indicating that API parameter value is invalid.\n
 * - NET_ERR_NO_SERVICE - indicating that there is no active network.\n
 *
 * \par Prospective Clients:
 * External Apps.
 *
 * \par Example Program:
 *
 * net_proxy_t proxy;
 *
 * int result = net_get_active_proxy(&proxy);
 *
 * if(result == NET_ERR_NONE)......
 *
******************************************************************************************/
int net_get_active_proxy(net_proxy_t *proxy);

/*****************************************************************************************/
/* net_get_network_status API function prototype
 * int net_get_network_status(net_device_t device_type, net_cm_network_status_t* network_status);
 */

/**
 * \brief  This API returns The status of a specific network interface passed as a parameter.
 *
 * \par Sync (or) Async:
 * This is a Synchronous API.
 *
 * \par Important Notes:
 *  None
 *
 * \par Notes :
 *  None
 *
 * \warning
 *  None
 *
 * \param[in] 	device_type    	Queried network interface.
 * \param[out] 	network_status 	The status of Queried network interface.
 *
 * \par Async Response Message:
 *  None
 *
 * \par Precondition:
 *        Application must already be registered with the CM server.
 *
 * \return Return Type (int) \n
 * - NET_ERR_NONE  - indicating that the status of queried network interface is retrieved. \n
 * - NET_ERR_APP_NOT_REGISTERED - indicating that client is not registered with CM and it cannot use CM services.\n
 * - NET_ERR_UNKNOWN - indicating that an unknown error has occurred.\n
 * - NET_ERR_INVALID_PARAM - indicating that API parameter value is invalid.\n
 *
 * \par Prospective Clients:
 * External Apps.
 *
 * \par Example Program:
 *
 * net_cm_network_status_t status;
 *
 * int result = net_get_network_status(NET_MOBILE_TYPE, &status);
 *
 * if(result == TRUE)......
 *
 *
 *
******************************************************************************************/
int net_get_network_status(net_device_t device_type, net_cm_network_status_t* network_status);

/*****************************************************************************************/
/* net_is_connected API function prototype
 * int net_is_connected(void);
 */

/**
 * \brief  This API returns the connection status of process
 *
 * \par Sync (or) Async:
 * This is a Synchronous API.
 *
 * \par Important Notes:
 *  None
 *
 * \par Notes :
 *  None
 *
 * \warning
 *  None
 *
 *
 * \par Async Response Message:
 *  None
 *
 * \par Precondition:
 *        Application must already be registered with the CM server.
 *
 * \return Return Type (int) \n
 * - 1  - connected
 * - 0 - not connected
 *
 * \par Prospective Clients:
 * External Apps.
 *
 * \par Example Program:
 *
 * int result = net_is_connected();
 *
 * if(result == 1)......
 *
 *
 *
******************************************************************************************/
int net_is_connected(void);

/**
 * \}
 */

/**
 * \addtogroup  pdp_specific
 * \{
*/

/**
 * \}
 */

/**
 * \addtogroup  common_extended
 * \{
*/

/**
 * \brief 	This API is only for Connection/Wi-Fi CAPI. Don't use this.
 *
 * \param[in] event_cb     Application Callback function pointer to receive ConnMan events
 * \param[in] client_type  NET_DEVICE_DEFAULT : Connection CAPI, NET_DEVICE_WIFI : Wi-Fi CAPI
 * \param[in] user_data    user data
 *
 ******************************************************************************************/
int net_register_client_ext(net_event_cb_t event_cb, net_device_t client_type, void *user_data);

/**
 * \brief 	This API is only for Connection/Wi-Fi CAPI. Don't use this.
 *
 * \param[in] client_type  NET_DEVICE_DEFAULT : Connection CAPI, NET_DEVICE_WIFI : Wi-Fi CAPI
 *
 ******************************************************************************************/
int net_deregister_client_ext(net_device_t client_type);

/**
 * \brief 	This API is only for Connection/Wi-Fi CAPI. Don't use this.
 *
 * \param[in]  service_type specific service type
 * \param[out] prof_name    The name of profile for the service type.
 *
 ******************************************************************************************/
int net_open_connection_with_preference_ext(net_service_type_t service_type, net_profile_name_t *prof_name);

/**
 * \brief 	This API is only for Connection CAPI. Don't use this.
 *
 * \param[in]  ip_addr     ip address to route.
 * \param[in]  interface   interface name.
 * \param[in]  address_family address family of ip address.
 *
 ******************************************************************************************/
int net_add_route(const char *ip_addr, const char *interface, int address_family);

/**
 * \brief 	This API is only for Connection CAPI. Don't use this.
 *
 * \param[in]  ip_addr     ip address to route.
 * \param[in]  interface   interface name.
 * \param[in]  address_family address family of ip address.
 *
 ******************************************************************************************/
int net_remove_route(const char *ip_addr, const char *interface, int address_family);

/**
 * \brief 	This API is only for Connection CAPI. Don't use this.
 *
 * \param[in]  ip_addr     ipv6 address to route.
 * \param[in]  interface   interface name.
 * \param[in]  address_family address family of ip address.
 * \param[in]  gateway  gateway address.
 *
 ******************************************************************************************/
int net_add_route_ipv6(const char *ip_addr, const char *interface, int address_family, const char *gateway);

/**
 * \brief 	This API is only for Connection CAPI. Don't use this.
 *
 * \param[in]  ip_addr     ipv6 address to route.
 * \param[in]  interface   interface name.
 * \param[in]  address_family address family of ip address.
 * \param[in]  gateway  gateway address.
 *
 ******************************************************************************************/
int net_remove_route_ipv6(const char *ip_addr, const char *interface, int address_family, const char *gateway);

/*****************************************************************************************/
/* net_get_ethernet_cable_state API function prototype
 * int net_get_ethernet_cable_state(int *state);
 */

/**
 * \brief  This API returns the ethernet cable status, 1 = Attached, 0 = Deatached.
 *
 * \param[out] state - Specifies the State of ethernet cable
 *
 * \par Sync (or) Async:
 * This is a Synchronous API.
 *
 * \par Important Notes:
 *  None
 *
 * \par Notes :
 *  None
 *
 * \warning
 *  None
 *
 *
 * \par Async Response Message:
 *  None
 *
 * \return Return Type (int) \n
 * - NET_ERR_NONE - indicating that the status of ethernet plug in/out retrieved successfully.\n
 * - NET_ERR_INVALID_PARAM - indicating that API parameter value is invalid.\n
 * - NET_ERR_INVALID_OPERATION - indicating that the API failed to retrieve the status of ethernet plug.\n
 *
 * \par Prospective Clients:
 * External Apps.
 *
 *
******************************************************************************************/
int net_get_ethernet_cable_state(int *state);

/**
 * \brief 	This API is only for Connection CAPI. Don't use this.
 *
 * \param[in]  tech_type    specific technology type
 * \param[out]  tech_info   technology info.
 *
 ******************************************************************************************/
int net_get_technology_properties(net_device_t tech_type, net_tech_info_t *tech_info);

/**
 * \}
 */

/**
 * \addtogroup  common_info
 * \{
*/

/**
 * \brief 	Gets the statistics information.
 *
 * \param[in]  device_type     specific device type(cellular/wifi).
 * \param[in]  statistics_type specific statistics type.
 * \param[out] statistics_type statistics value requested.
 *
 ******************************************************************************************/
int net_get_statistics(net_device_t device_type, net_statistics_type_e statistics_type, unsigned long long *size);

/**
 * \brief 	Resets the statistics information.
 *
 * \param[in]  device_type     specific device type(cellular/wifi).
 * \param[in]  statistics_type specific statistics type.
 *
 ******************************************************************************************/
int net_set_statistics(net_device_t device_type, net_statistics_type_e statistics_type);

/**
 * \}
 */

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
