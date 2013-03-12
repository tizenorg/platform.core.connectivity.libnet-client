/*
 *  Network Client Library
 *
 * Copyright 2011-2013 Samsung Electronics Co., Ltd

 * Licensed under the Flora License, Version 1.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at

 * http://floralicense.org/license/

 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */


#ifndef __NETWORK_SIGNAL_HANDLER_H_
#define __NETWORK_SIGNAL_HANDLER_H_

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

/*****************************************************************************
 * 	Macros and Typedefs
 *****************************************************************************/

/*****************************************************************************
 * 	Global Structures
 *****************************************************************************/

/*****************************************************************************
 * 	Global Functions 
 *****************************************************************************/
int _net_deregister_signal(void);
int network_register_and_recieve_signal(void);
int _net_register_signal(void);
int _net_init_service_state_table(void);


#endif /** __NETWORK_SIGNAL_HANDLER_H_ */

