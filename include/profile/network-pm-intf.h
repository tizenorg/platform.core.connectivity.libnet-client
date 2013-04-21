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

#ifndef __NETWORK_PM_INTF_H__
#define __NETWORK_PM_INTF_H__

#include "network-pm-wlan.h"

#ifdef __cplusplus
extern "C"
{
#endif /* __cplusplus */

#ifndef DEPRECATED
#define DEPRECATED __attribute__((deprecated))
#endif

/**
 * @file network-pm-intf.h
 * @brief This file defines the interface of Profile Manager with the application/Connection Manager.
*/

/**
 * \addtogroup  profile_managing
 * \{
*/

/*==================================================================================================
                                           CONSTANTS
==================================================================================================*/

/*==================================================================================================
                                             ENUMS
==================================================================================================*/

/**
 * @enum net_pdp_type_t
 * This enumeration defines the pdp protocol type.
 */
typedef enum
{
	/** Not defined */
	NET_PDP_TYPE_NONE	= 0x00,
	/** PDP-GPRS type */
	NET_PDP_TYPE_GPRS,
	/** PDP-EDGE type */
	NET_PDP_TYPE_EDGE,
	/** PDP-UMTS type */
	NET_PDP_TYPE_UMTS,
} net_pdp_type_t;

/**
 * @enum net_state_type_t
 * This enumeration defines the service state type.
 */
typedef enum
{
	/** Not defined */
	NET_STATE_TYPE_UNKNOWN	= 0x00,
	/** Idle state */
	NET_STATE_TYPE_IDLE,
	/** Failure state */
	NET_STATE_TYPE_FAILURE,
	/** Association state */
	NET_STATE_TYPE_ASSOCIATION,
	/** Configuration state */
	NET_STATE_TYPE_CONFIGURATION,
	/** Ready state */
	NET_STATE_TYPE_READY,
	/** Online state */
	NET_STATE_TYPE_ONLINE,
	/** Login state */
	NET_STATE_TYPE_DISCONNECT,
} net_state_type_t;


/*==================================================================================================
                                 STRUCTURES AND OTHER TYPEDEFS
==================================================================================================*/


/**
 * Profile data structures: Used between Application and PM Plug-in Interface
 */
typedef struct
{
	/** Specifies a protocol type */
	net_pdp_type_t  ProtocolType;
	/** Specifies a service type(Internet, MMS, WAP, etc...) */
	net_service_type_t ServiceType;
	/** Network Access Point Name */
	char            Apn[NET_PDP_APN_LEN_MAX+1];
	/** Authentication info of the PDP profile */
	net_auth_info_t	AuthInfo;
	/** Browser Home URL or MMS server URL */
	char            HomeURL[NET_HOME_URL_LEN_MAX+1];
	/** Sim Info Mcc */
	char Mcc[NET_SIM_INFO_LEN+1];
	/** Sim Info Mnc */
	char Mnc[NET_SIM_INFO_LEN+1];
	/** Indicates whether the use of static IP or not */
	char IsStatic;

	/** Indicates Roaming mode */
	char Roaming;
	/** This will be deprecated */
	char SetupRequired;

	char Keyword[NET_PDP_APN_LEN_MAX+1];
	char Hidden;
	char Editable;
	char DefaultConn;

	/** network information */
	net_dev_info_t net_info;
} net_pdp_profile_info_t;

/**
 * Profile data structures: Ethernet Interface
 */
typedef struct
{
	/** network information */
	net_dev_info_t net_info;
} net_eth_profile_info_t;

/**
 * Profile data structures: Bluetooth Interface
 */
typedef struct
{
	/** network information */
	net_dev_info_t net_info;
} net_bt_profile_info_t;

/**
 * Specific profile information related to each technology type
 */
typedef union
{
	/** PDP Profile Information */
	net_pdp_profile_info_t       Pdp;
	/** Wifi Profile Information */
	net_wifi_profile_info_t      Wlan;
	/** Ethernet Profile Information */
	net_eth_profile_info_t       Ethernet;
	/** Bluetooth Profile Information */
	net_bt_profile_info_t        Bluetooth;
} net_specific_profile_info_t;

/**
 * This is the profile structure exposed to applications.
 */
typedef struct
{
	/** Device Type of the profile */
	net_device_t  	profile_type;
	/** Profile name */
	char	ProfileName[NET_PROFILE_NAME_LEN_MAX+1];
	/** Specific profile information */
	net_specific_profile_info_t ProfileInfo;
	/** Service state */
	net_state_type_t        ProfileState;
	/** Favourite flag */
	char Favourite;
} net_profile_info_t;

/*
==================================================================================================
                                     FUNCTION PROTOTYPES
==================================================================================================
*/

/*****************************************************************************************/
/* net_add_profile API function prototype
 * int net_add_profile(net_service_type_t network_type, net_profile_info_t *prof_info);
 */

/**
 * \brief 	Add new Profile.
 *
 * \par Sync (or) Async:
 * This is a Synchronous API.
 *
 * \par Important Notes:
 *
 * \warning
 *  None
 *
 * \param[in]   network_type  A type of network service.
 * \param[in]   prof_info     A pointer of New created Profile Information to be added.
 *
 * \par Async Response Message:
 *        None.
 *
 * \return Return Type (int) \n
 * - NET_ERR_NONE  - indicating that the operation has completed successfully. \n
 * - NET_ERR_INVALID_PARAM - Invalid parameter\n
 * - NET_ERR_UNKNOWN - Any other error\n
 * - NET_ERR_APP_NOT_REGISTERED - Client is invalid may be unregistered\n
 *
 * \par Prospective Clients:
 * Network Connection Setting Applet, WLAN Setting UI Applet.
 *
 * \par Example of how this function would be called:
 *
 * net_profile_info_t prof_info;\n
 * int result;\n
 * result = net_add_profile(NET_SERVICE_MMS, &prof_info);\n
 * if(result == NET_ERR_NONE)
 *
******************************************************************************************/
int net_add_profile(net_service_type_t network_type, net_profile_info_t *prof_info);

/*****************************************************************************************/
/* net_delete_profile API function prototype
 * int net_delete_profile(const char* profile_name);
 */

/**
 * \brief 	Delete a specific existing Profile.
 *              (cellular : Delete profile, wifi : forgot AP)
 *
 * \par Sync (or) Async:
 * This is a Synchronous API.
 *
 * \par Important Notes:
 *
 * \warning
 *  None
 *
 * \param[in]   profile_name        Profile name to be deleted.
 *
 * \par Async Response Message:
 *        None.
 *
 * \return Return Type (int) \n
 * - NET_ERR_NONE  - indicating that the operation has completed successfully.
 * - NET_ERR_INVALID_PARAM - Invalid parameter
 * - NET_ERR_UNKNOWN - Any other error
 * - NET_ERR_APP_NOT_REGISTERED - Client is invalid may be unregistered
 *
 * \par Prospective Clients:
 * Network Connection Setting Applet, WLAN Setting UI Applet.
 *
 * \par Example of how this function would be called:
 *
 * int result;\n
 *
 * result = net_delete_profile(profile_name);
 *
 * if (result == NET_ERR_NONE)
 *
******************************************************************************************/
int net_delete_profile(const char *profile_name);

/*****************************************************************************************/
/* net_get_profile_info API function prototype
 * int net_get_profile_info(const char *profile_name, net_profile_info_t *prof_info);
 */

/**
 * \brief 	Return the profile information referred by Profile Name.
 *
 * \par Sync (or) Async:
 * This is a Synchronous API.
 *
 * \par Important Notes:
 *		On success, profile information shall be copied to prof_info parameter in net_profile_info_t format.
 *		If profile doesn't exist, error shall be returned.
 *
 * \warning
 *  None
 *
 * \param[in]   profile_name  Profile Identifier.
 * \param[out]  prof_info     Buffer containing the profile.
 *
 * \par Async Response Message:
 *        None.
 *
 * \return Return Type (int) \n
 * - NET_ERR_NONE  - indicating that the operation has completed successfully. \n
 * - NET_ERR_INVALID_PARAM - Invalid parameter\n
 * - NET_ERR_UNKNOWN - Any other error\n
 * - NET_ERR_APP_NOT_REGISTERED - Client is invalid may be unregistered\n
 *
 * \par Prospective Clients:
 * Profile Manager.
 *
 * \par Example of how this function would be called:
 *
 * net_profile_info_t prof_info;\n
 * int result;\n
 *
 * result = net_get_profile_info(profile_name, &prof_info);\n
 *
 * if (result == NET_ERR_NONE)\n
 *
******************************************************************************************/
int net_get_profile_info(const char *profile_name, net_profile_info_t *prof_info);

/*****************************************************************************************/
/* net_modify_profile API function prototype
 * int net_modify_profile(const char* profile_name, net_profile_info_t* prof_info);
 */

/**
 * \brief 	Edit a specific existing Profile.
 *
 * \par Sync (or) Async:
 * This is a Synchronous API.
 *
 * \par Important Notes:
 *
 * \warning
 *  None
 *
 * \param[in]  profile_name  Profile Identifier.
 * \param[in]  prof_info     Changed Profile Information to be updated.
 *
 *
 * \par Async Response Message:
 *        None.
 *
 * \return Return Type (int) \n
 * - NET_ERR_NONE  - indicating that the operation has completed successfully. \n
 * - NET_ERR_INVALID_PARAM - Invalid parameter\n
 * - NET_ERR_UNKNOWN - Any other error\n
 * - NET_ERR_APP_NOT_REGISTERED - Client is invalid may be unregistered\n
 *
 * \par Prospective Clients:
 * Network Connection Setting Applet.
 *
 * \par Example of how this function would be called:
 *
 * net_profile_info_t prof_info;\n
 * int result;\n
 *
 * result = net_get_profile_info(profile_name, &prof_info);\n
 * ......(Modifying ProfInfo)\n
 *
 * result = net_modify_profile(profile_name, &prof_info);\n
 *
 * if (result == NET_ERR_NONE)\n
 *
******************************************************************************************/
int net_modify_profile(const char *profile_name, net_profile_info_t *prof_info);

/*****************************************************************************************/
/**
 * @fn   int net_get_profile_list(net_device_t device_type, net_profile_info_t **profile_list, int *count)
 *
 * This function request service list to ConnMan through dbus.
 *
 * \par Sync (or) Async:
 * This is a Synchronous API.
 *
 * \param[in]	device_type     Type of device
 * \param[out]	profile_list    Profile list. After use this, it should be free()
 * \param[out]	count           Number of profile
 *
 * \return Return Type (int) \n
 * - NET_ERR_NONE  - indicating that the operation has completed successfully. \n
 * - NET_ERR_INVALID_PARAM - Invalid parameter\n
 * - NET_ERR_UNKNOWN - Any other error\n
 * - NET_ERR_APP_NOT_REGISTERED - Client is invalid may be unregistered\n
 *
 * \par Prospective Clients:
 * External Apps.
 *
******************************************************************************************/
int net_get_profile_list(net_device_t device_type, net_profile_info_t **profile_list, int *count);

/*****************************************************************************************/
/**
 * This function sets the default profile which provides the given cellular service.
 *
 * \par Sync (or) Async:
 * This is a Synchronous API.
 *
 * \param[in]	profile_name    Profile Identifier.
 *
 * \par Prospective Clients:
 * External Apps.
 *
******************************************************************************************/
int net_set_default_cellular_service_profile(const char *profile_name);

/*****************************************************************************************/
/**
 * This function sets the default profile which provides the given cellular service.
 *
 * \par Sync (or) Async:
 * This is a Asynchronous API.
 *
 * \param[in]	profile_name    Profile Identifier.
 *
 * \par Prospective Clients:
 * External Apps.
 *
******************************************************************************************/
int net_set_default_cellular_service_profile_async(const char *profile_name);

/**
 * \}
 */

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
