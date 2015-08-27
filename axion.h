/*
 *  AxionVPN -- OpenVPN auto-configuration for
 *  use on the Axion networks
 *
 * Copyright (C) 2015 Axion
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program (see the file COPYING included with this
 *  distribution); if not, write to the Free Software Foundation, Inc.,
 *  59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#ifndef AXION_H
#define AXION_H

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <tchar.h>

/* Define this to enable DEBUG build */
//#define DEBUG
#define DEBUG_FILE	"Axion_debug.txt"

/* Define this to disable Change Password support */
//#define DISABLE_CHANGE_PASSWORD

/* Registry key for User Settings */
#define GUI_REGKEY_HKCU	_T("Software\\Axion\\AxionVPN")

/* Registry key for Global Settings */
#define GUI_REGKEY_HKLM	_T("SOFTWARE\\AxionVPN")

#define MAX_LOG_LENGTH      1024/* Max number of characters per log line */
#define MAX_LOG_LINES		500	/* Max number of lines in LogWindow */
#define DEL_LOG_LINES		10	/* Number of lines to delete from LogWindow */



/* bool definitions */
#define bool int
#define true 1
#define false 0

/* GCC function attributes */
#define UNUSED __attribute__ ((unused))
#define NORETURN __attribute__ ((noreturn))



#ifdef DEBUG
/* Print Debug Message */
#define PrintDebug(...) \
        { \
           TCHAR x_msg[256]; \
           _sntprintf_0(x_msg, __VA_ARGS__); \
           PrintDebugMsg(x_msg); \
        }

void PrintDebugMsg(TCHAR *msg);
void PrintErrorDebug(TCHAR *msg);
bool init_security_attributes_allow_all (struct security_attributes *obj);
#endif

DWORD GetDllVersion(LPCTSTR lpszDllName);




void CreateNetworksWindow(void);




//
//Void ProcessConfig(HWND hDlg, LPSTR *results)
//
//Now we got results, lets handle them
//0 - Success (bubble over icon "Connecting" maybe part of OpenVPN
//1 - Failed creds, pop up
//2 - Not activated, different pop up message
//
//void ProcessConfig(HWND hDlg, char *configname, char *results);


void ShowNetworksDialog();

#endif
