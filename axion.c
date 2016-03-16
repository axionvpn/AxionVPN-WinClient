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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <windows.h>
#include <process.h>
#include <tlhelp32.h>
#include <shlwapi.h>
#include <wtsapi32.h>
#include <prsht.h>
#include <pbt.h>
#include <windowsx.h>
#include <winhttp.h>
#include <richedit.h>
#include <commctrl.h>
#include <shellapi.h>

#include "tray.h"
#include "openvpn.h"
#include "openvpn_config.h"
#include "viewlog.h"
#include "service.h"
#include "main.h"
#include "options.h"
#include "passphrase.h"
#include "proxy.h"
#include "registry.h"
#include "openvpn-gui-res.h"
#include "localization.h"
#include "manage.h"
#include "misc.h"
#include "axion.h"
#include "jsmn.h"
#include "winsparkle.h"

#define MAX_SITES 1024
#define MAX_RETRIES 5 //Number of times we will attempt the web connection

//#define DEBUG

//AXION - Eventually allocate on the heap in the 
//function
#define MAX_POSTVARS_SIZE 4096
unsigned char PostVars[MAX_POSTVARS_SIZE];

void CloseApplication(HWND hwnd);
void ShowPasswordDialog();
static DWORD WINAPI ConnectToVPN(void *p);


extern options_t o;



//
// Display a message box when we can't reach the server
//
// Since we can't reach the server, we will give up on the
// entire program
void CantReachServer(BOOL bExitProgram){

	//PrintDebug(_T("[CantReachServer] Called"));

		int msgboxID = MessageBox(
			NULL,
			(LPCWSTR)L"AxionVPN can't connect to the server. Please check your Internet connection and try again",
			(LPCWSTR)L"Can't Reach AxionVPN",
			MB_ICONEXCLAMATION | MB_OK
		);


	if(bExitProgram){
		//PrintDebug(_T("[CantReachServer] Exiting the program\n"));
		ExitProcess(1);
	}

}

/* Converts a hex character to its integer value */
char from_hex(char ch) {
	return isdigit(ch) ? ch - '0' : tolower(ch) - 'a' + 10;
}

/* Converts an integer value to its hex character*/
char to_hex(char code) {
	static char hex[] = "0123456789abcdef";
	return hex[code & 15];
}

/* Returns a url-encoded version of str */
/* IMPORTANT: be sure to free() the returned string after use */
char *url_encode(char *str) {
	char *pstr = str, *buf = malloc(strlen(str) * 3 + 1), *pbuf = buf;
	while (*pstr) {
		if (isalnum(*pstr) || *pstr == '-' || *pstr == '_' || *pstr == '.' || *pstr == '~' || *pstr == '&' || *pstr == '=' || *pstr == '\r' || *pstr == '\n')
			*pbuf++ = *pstr;
		else if (*pstr == ' ')
			*pbuf++ = '+';
		else
			*pbuf++ = '%', *pbuf++ = to_hex(*pstr >> 4), *pbuf++ = to_hex(*pstr & 15);
		pstr++;
	}
	*pbuf = '\0';
	return buf;
}

//
//Kills all processes with a given name - we need this to clear out any openvpn instances
//"other" VPN tools may have left behind.
//
void killProcessByName(const WCHAR *filename)
{
    HANDLE hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPALL, NULL);
    PROCESSENTRY32 pEntry;
	//PrintDebug(L"[killProcessByName] Called with %s", filename);

    pEntry.dwSize = sizeof (pEntry);
    BOOL hRes = Process32First(hSnapShot, &pEntry);
    while (hRes)
    {

		//PrintDebug(L"[killProcessByName]Proc %s", pEntry.szExeFile);

        if (_wcsicmp(pEntry.szExeFile, filename) == 0)
        {
            HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, 0,
                                          (DWORD) pEntry.th32ProcessID);
            if (hProcess != NULL)
            {
                TerminateProcess(hProcess, 9);
                CloseHandle(hProcess);
            }
        }
        hRes = Process32Next(hSnapShot, &pEntry);
    }
    CloseHandle(hSnapShot);
}





//
// Set the connectin info, namely the public IP
// and account type into the options.
//

void SetConnInfo(char *json){
	//PrintDebug(L"[SetConnInfo] Called with %S", json);

	//Prepare JSON parser
	int r;
	size_t jslen = 0;
	jsmn_parser p;
	jsmntok_t tokens[8];


	//Clear the fields of interest
	memset(o.conn[0].pubIP, 0, 16);
	memset(o.conn[0].acctType, 0, 16);
	

	if (json == NULL){

		//And set defaults
		strcpy(o.conn[0].acctType, "VPN Service");
		strcpy(o.conn[0].pubIP, "0.0.0.0");

		//PrintDebug(L"[SetConnInfo] NULL json input");
		return;
	}

	// Prepare parser
	jsmn_init(&p);

	jslen = strlen(json);
	r = jsmn_parse(&p, json, jslen, tokens, 8);
	//PrintDebug(_T("[SetConnInfo] There are %d elements\n"), r);

	//We got an error or not enough elements regardless
	if (r < 7){
		//PrintDebug(L"[SetConnInfo] Not enough elements\n");
		return;
	}
	else{

		//We had valid results, so we clear out the fields of interest
		memset(o.conn[0].pubIP, 0, 16);
		memset(o.conn[0].acctType, 0, 16);


		DWORD dwLen = 0;
		//Parse out external IP address and assign it
		//we know its element [4] on the array
		dwLen = tokens[4].end - tokens[4].start;
		memcpy(o.conn[0].acctType, json + tokens[4].start, dwLen);


		//Parse out account type and assign it, we know
		//its element [6] on the array
		dwLen = tokens[6].end - tokens[6].start;
		memcpy(o.conn[0].pubIP, json + tokens[6].start, dwLen);

	}




	//PrintDebug(L"o.pubIP: %S\n",o.conn[0].pubIP);
	//PrintDebug(L"o.acctType: %S\n",o.conn[0].acctType);


}




//
// char *GetConnInfo(char *username, char *password)
//
// Get the connection information for the current connection, using
// the Axion get-info call from their website
//
//

char *GetConnInfo(char *username, char *password){
	//PrintDebug(L"[GetConnInfo] Called with %S and %S",username,password);

 
	//Get the contents of the URL

	char *encodedVars = NULL;

	DWORD dwSize = 0;

	DWORD dwBufSize = 0;
	DWORD dwDownloaded = 0;
	LPSTR pszOutBuffer = NULL;
	CHAR *currPtr = NULL;


	BOOL  bResults = FALSE;
	HINTERNET hSession = NULL,
		hConnect = NULL,
		hRequest = NULL;



	// Use WinHttpOpen to obtain a session handle.
	hSession = WinHttpOpen(L"AxionVPN /1.0",
		WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
		WINHTTP_NO_PROXY_NAME,
		WINHTTP_NO_PROXY_BYPASS, 0);

	if (!hSession){
		//PrintDebug(_T("[GetConnInfo] WinHttpOpen Failed\n"));
		goto exit;
	}
	else{
		//PrintDebug(_T("[GetConnInfo] WinHttpOpen Success\n"));
	}

	//Create a valid session, now connect
	hConnect = WinHttpConnect(hSession, L"axionvpn.com", INTERNET_DEFAULT_HTTPS_PORT, 0);

	if (!hConnect){
		//PrintDebug(_T("[GetConnInfo] WinHttpConnect Failed\n"));
		goto exit;
	}
	else{
		//PrintDebug(_T("[GetConnInfo] WinHttpConnect Success\n"));
	}


	hRequest = WinHttpOpenRequest(hConnect, L"POST", L"/api/SoftwareVPN/getInfo", NULL, NULL, NULL, WINHTTP_FLAG_SECURE | WINHTTP_FLAG_BYPASS_PROXY_CACHE);
	if (!hRequest){
		//PrintDebug(_T("[GetConnInfo] WinHttpOpenRequest Failed\n"));
		goto exit;
	}
	else{
		//PrintDebug(_T("[GetConnInfo] WinHttpOpenRequest Success\n"));
	}


	//Create JSON structure with params, yes we use a global value here, but
	//its safe as this approach is single threaded, and we can have a BIG buffer
	//thats statically allocated and we  don't have to worry about burning stack space
	memset(PostVars, 0, MAX_POSTVARS_SIZE);
	sprintf((char *)PostVars, "username=%s&password=%s",username, password);

	//PrintDebug(_T("PostVars: %S\n"), PostVars);
	encodedVars = (char *)url_encode((char *) PostVars);
	//encodedVars = PostVars;
	//PrintDebug(_T("encodedVars: %S\n"), encodedVars);


	//Set up post headers
	WCHAR* szHeaders = L"Content-Type:application/x-www-form-urlencoded\r\n";
	//DWORD dwTotalSize = ( (strlen(encodedVars) + 1) * sizeof(char))  + ( (wcslen(szHeaders) + 1) * sizeof(WCHAR));



	//Request was successful, send it
	bResults = WinHttpSendRequest(hRequest,
		szHeaders, -1L,
		//WINHTTP_NO_ADDITIONAL_HEADERS,0,
		encodedVars, (strlen(encodedVars) + 1) * sizeof(char),
		(strlen(encodedVars) + 1)* sizeof(char), 0);


	// End the request.
	if (!bResults){
		//PrintDebug(_T("[GetConnInfo] Error in WinHttpSendRequest\n"));
		goto exit;
	}
	else{
		//PrintDebug(_T("[GetConnInfo] WinHttpSendRequest Success\n"));
	}


	bResults = WinHttpReceiveResponse(hRequest, NULL);


	// Keep checking for data until there is nothing left.
	if (bResults){

		//PrintDebug(_T("[GetConnInfo] WinHttpReceiveResponse Success\n"));

		//First make sure we got a good response, HTTP response code
		// < 400
		DWORD dwStatusCode = 0;
		dwSize = sizeof(dwStatusCode);

		WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
			WINHTTP_HEADER_NAME_BY_INDEX, &dwStatusCode, &dwSize, WINHTTP_NO_HEADER_INDEX);

		//PrintDebug(_T("Http response: %d\n"), dwStatusCode);


		do
		{
			// Check for available data.
			dwSize = 0;
			if (!WinHttpQueryDataAvailable(hRequest, &dwSize)){
				//PrintDebug(_T("Error in WinHttpQueryDataAvailable.\n"));
				goto exit;
			}

			//PrintDebug(_T("%d bytes of data\n"), dwSize);
			if (dwSize == 0){
				break;
			}

			// Allocate space for the buffer if its our first time around, otherwise
			// we re-allocate the buffer to accomodate
			dwBufSize += dwSize;
			if (!pszOutBuffer){
				pszOutBuffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwBufSize + 1);
				currPtr = pszOutBuffer;
			}
			else{

				pszOutBuffer = HeapReAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, pszOutBuffer,dwBufSize + 1);

				//Figure how much we've read and where we read into now
				DWORD dwOffset = dwBufSize - dwSize;
				currPtr = (pszOutBuffer + (dwOffset));
			}

			if (!pszOutBuffer)
			{
				//PrintDebug(_T("Out of memory\n"));
				dwSize = 0;
			}
			else
			{
				// Read the Data.
				//ZeroMemory(pszOutBuffer, dwSize + 1);

				if (!WinHttpReadData(hRequest, (LPVOID)currPtr,
					dwSize, &dwDownloaded)){
					//PrintDebug(_T("Error %u in WinHttpReadData.\n"), GetLastError());
				}
				else{
					//PrintDebug(_T("%S\n"), pszOutBuffer);
				}


			}

		} while (dwSize > 0);

	}
	else{
		//PrintDebug(_T("Error %d has occurred.\n"), GetLastError());
	}


exit:

	// Close any open handles.
	if (hRequest) WinHttpCloseHandle(hRequest);
	if (hConnect) WinHttpCloseHandle(hConnect);
	if (hSession) WinHttpCloseHandle(hSession);


	//PrintDebug(L"[GetConnInfo] Returning %S", pszOutBuffer);


	return pszOutBuffer;

}

//
//LPWSTR GetRegionName(char *json){
//
// Given a JSON VPN region object, 
// get the name and return a wide character
// buffer with the region name. The user
// is responsible for calling HeapFree() on
// the buffer
//
LPWSTR GetRegionName(char *json){
	LPWSTR lpRetVal = NULL;
	char *scratchBuf;

	//PrintDebug(L"[GetRegionName] Called with %S",json);

	int r;
	size_t jslen = 0;
	jsmn_parser p;
	jsmntok_t tokens[8];

	// Prepare parser
	jsmn_init(&p);
		
	jslen = strlen(json);
	r = jsmn_parse(&p, json, jslen, tokens, 8);
	//PrintDebug(_T("[GetRegionName] There are %d elements\n"), r);

	//We're going to play clever and know its the last element
	DWORD nameLen = tokens[4].end - tokens[4].start;
	//PrintDebug(_T("[GetRegionName] Region name is %d chars long\n"), nameLen);


	//Allocate space for the final and scratch buffer
	scratchBuf = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (nameLen +1) * sizeof(char));
	if (!scratchBuf){
		//PrintDebug(L"[GetRegionName] Failed to allocate scratchBuf\n");
		goto exit;
	}


	lpRetVal = (LPWSTR) HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (nameLen +1) * sizeof(WCHAR));
	if (!lpRetVal){
		//PrintDebug(L"[GetRegionName] Failed to allocate lpRetVal\n");
		goto exit;
	}

	//Copy the memory into the scratch buffer
	memcpy(scratchBuf, json + tokens[4].start, nameLen);

	//PrintDebug(L"scratchBuf: %S",scratchBuf);
	//Now print it as a wchar string
	swprintf(lpRetVal, nameLen,L"%S",scratchBuf);
	




exit:

	if (scratchBuf){
		HeapFree(GetProcessHeap(), 0, scratchBuf);		
	}

	//PrintDebug(L"[GetRegionName] Returning %s",lpRetVal);
	return lpRetVal;
}



void ClearListBox(HWND hDlg){
	//PrintDebug(_T("[ClearListBox] Called\n"));

	DWORD index = 0;
	char *data;


	//Get a handle to the LISTBOX control 
	HWND hwndList = GetDlgItem(hDlg, IDC_LISTBOX);
	DWORD count = (DWORD)SendMessage(hwndList, LB_GETCOUNT, 0, 0);
	//PrintDebug(L"[ClearListBox] There are %d items in the list box\n",count);
	
	//Keep getting the data for each element,
	//free it, then delete the element
	//until we're done
	//for (index = 0; index < count; index++){
	index = count;
	while(index){
		//
		index--;

		// Get item data.
		data = (char *)SendMessage(hwndList, LB_GETITEMDATA, index, 0);
		if (data){
			//PrintDebug(L"[ClearListBox] data: %S\n",data);
			HeapFree(GetProcessHeap(), 0, data);
			SendMessage(hwndList, LB_DELETESTRING, index, 0);
			//break;
		}
		else{
			//break;
		}

	}


	//PrintDebug(_T("[ClearListBox] Returning\n"));
}



//
// void parseSites()
//
// Take the list of sites returned by the server
// and add them to the listbox
//
//
void parseSites(HWND hDlg, char *json){
	//Parse out the sites and populate the listbox
	
	unsigned char *sitePtr;
	LPWSTR regionName;
	DWORD objSize = 0;

	int r;
	size_t jslen = 0;
	jsmn_parser p;
	jsmntok_t tokens[MAX_SITES];
	
	/* Prepare parser */
	jsmn_init(&p);

	//PrintDebug(_T("[parseSites] %S\n"), json);


	//Get a handle to the LISTBOX control 
    HWND hwndList = GetDlgItem(hDlg, IDC_LISTBOX);


	// break the elements into an array

	jslen = strlen(json);
	r = jsmn_parse(&p, json, jslen, tokens, MAX_SITES);
	//PrintDebug(_T("[parseSites] There are %d elements\n"), r);

	//Error Parsing JSON
	if (r < 0){
		//PrintDebug(L"Error Parsing JSON\n");
		return;
	}

	/* Assume the top-level element is an object */
	if (r < 1 || tokens[0].type != JSMN_OBJECT) {
		//PrintDebug(L"Object expected\n");
		return;
	}

	//There is only one top-level object, and its
	//and array of geographic locations

	for (int i = 2; i < r; i++){

		//If we find an object
		if ( tokens[i].type == JSMN_OBJECT) {
			//PrintDebug(L"Object Found\n");	
			objSize = tokens[i].end - tokens[i].start;
			//PrintDebug(L"Object Size: %d", tokens[i].start);
			//PrintDebug(L"Object Size: %d", objSize);

			
			//Allocate memory
			  
			  sitePtr = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, objSize);
			  if (sitePtr == NULL){
				  //PrintDebug(L"Allocation Failed");
				  continue;
			  }
			//Copy the object
			  memcpy(sitePtr, json + tokens[i].start,objSize);
			  //PrintDebug(L"object: %S\n", sitePtr);

		    //Get a region string
		      regionName = GetRegionName(sitePtr);
			  //PrintDebug(L"regionName: %s\n", regionName);

			//Add it to the list box
			  //Add the site to the Listbox
			  int pos = (int)SendMessage(hwndList, LB_ADDSTRING, 0,
				  (LPARAM)regionName);
			  // Set the array index of the player as item data.
			  // This enables us to retrieve the item from the array
			  // even after the items are sorted by the list box.
			  SendMessage(hwndList, LB_SETITEMDATA, pos, (LPARAM) sitePtr);


		}


	}


	//Make the first entry explicitly the default one
	SendMessage(hwndList, LB_SETSEL, TRUE, (LPARAM)0);

	
	return;
}




void ConnectWithConfig(HWND hDlg, LPWSTR configname,char *json,char *username, char *password){
	//PrintDebug(L"[ConnectWithConfig] Called with %s and %S",configname, json);

	WCHAR outpath[MAX_PATH];

	//Parse out the config file
	int r;
	size_t jslen = 0;
	jsmn_parser p;
	jsmntok_t tokens[8];

	//Since we're about to connect close any pre-existing connection
	 //StopOpenVPN(&o.conn[0]);

	// Prepare parser
	jsmn_init(&p);

	jslen = strlen(json);
	r = jsmn_parse(&p, json, jslen, tokens, 8);
	//PrintDebug(_T("[ConnectWithConfig] There are %d elements\n"), r);

	//We're going to play clever and know its the last element
	DWORD buffLen = tokens[4].end - tokens[4].start;
	//PrintDebug(_T("[ConnectWithConfig] Buffer is %S\n"), json + tokens[4].start);
	//PrintDebug(_T("[ConnectWithConfig] Buffer size is %d\n"), buffLen);

	//Before we write our buffer out, lets clean up the config folder
	WipeFileList();


	//Convert our buffer to an escape encoded one


	//Write it out
	_sntprintf_0(outpath, _T("%s\\%s.ovpn"), o.config_dir,configname);

	//PrintDebug(L"[ConnectWithConfig] path: %s\n",outpath);

	char * inBuf = (char *)(json + tokens[4].start);
	char * outBuf = NULL;
	outBuf = (char *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, buffLen);


	int incount = 0;
	int outcount = 0;
	while (incount < buffLen){

		if (inBuf[incount] == '\\' && inBuf[incount + 1] == 'n'){
			outBuf[outcount++] = '\n';
			incount += 2;
		}
		else if (inBuf[incount] == '\\' && inBuf[incount + 1] == '/'){
			outBuf[outcount++] = '/';
			incount += 2;
	    }
		else{
			outBuf[outcount++] = inBuf[incount++];
		}

	}



	//PrintDebug(L"outBuf: %S\n",outBuf);

	
	
	HANDLE confFile = CreateFile(outpath, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL,NULL); ///FILE_ATTRIBUTE_TEMPORARY
	if (confFile == INVALID_HANDLE_VALUE){
		//PrintDebug(L"[ConnectWithConfig] Failed to create conf file");
		goto exit;
	}

	DWORD dwBytesWritten;
	WriteFile(confFile, outBuf, outcount, &dwBytesWritten, NULL);

	CloseHandle(confFile);

	//Connect to it
	  BuildFileList();
	  
    //Set the username and password for the connection
	  memset(o.conn[0].username, 0, 64);
	  memset(o.conn[0].password, 0, 64);
	  strcpy(o.conn[0].username, username);
	  strcpy(o.conn[0].password, password);

    //Start the connection
	  StartOpenVPN(&o.conn[0]);


    //Now close our network selection window
	  SendMessage(hDlg, WM_CLOSE, 0, (LPARAM)0);




	//PrintDebug(L"[ConnectWithConfig] Returning");
exit:
	if (outBuf){
		HeapFree(GetProcessHeap(), 0, outBuf);
	}


}

//Code to change the Messagebox Yes and No Buttons

    HOOKPROC hkprc; 
    HHOOK hhook;

static bool MessageBoxEnumProc(HWND hWnd, LPARAM lParam)
{
    TCHAR ClassName[32];
	memset(ClassName,0,sizeof(TCHAR));
    GetClassName(hWnd, ClassName, 32);
	//PrintDebug(_T("[MessageBoxHookProc] classname: %s \n"),ClassName);

        int ctlId = GetDlgCtrlID(hWnd);
		
        switch (ctlId)
        {
        case IDYES:
            SetWindowText(hWnd, L"Upgrade");
            break;
        case IDNO:
            SetWindowText(hWnd, L"Continue");
            break;
        }
		

		//PrintDebug(_T("[MessageBoxHookProc] ctlId: %d \n"),ctlId);
    
    return true;
}




static LRESULT CALLBACK MessageBoxHookProc(int nCode, WPARAM wParam, LPARAM lParam)
{

	//PrintDebug(_T("[MessageBoxHookProc] Called \n"));
    if (nCode < 0)
        return CallNextHookEx(hhook, nCode, wParam, lParam);


		
    PCWPRETSTRUCT msg = (PCWPRETSTRUCT)lParam ;
 
	TCHAR ClassName[32];
	
    if (msg->message == WM_INITDIALOG)
    {
		//PrintDebug(_T("[MessageBoxHookProc] WM_INITDIALOG \n"));
		
        int nLength = GetWindowTextLength(msg->hwnd);
		


        GetClassName(msg->hwnd, ClassName,32);
        if (wcscmp(ClassName,L"#32770") == 0)
        {

			//PrintDebug(_T("[MessageBoxHookProc] Found MessageBox\n"));
            EnumChildWindows(msg->hwnd, MessageBoxEnumProc, NULL);
        }

    }
	
    return CallNextHookEx(hhook, nCode, wParam, lParam);
}



//End Messagebox dialog code






//
//Void ProcessConfig(HWND hDlg, LPWSTR configname,char *results)
//
//Now we got results, lets handle them
//0 - Success (bubble over icon "Connecting" maybe part of OpenVPN
//1 - Failed creds, pop up
//2 - Not activated, different pop up message
//
void ProcessConfig(HWND hDlg, LPWSTR configname, char *json,char *username, char* password){
	//PrintDebug(_T("[ProcessConfig] Called with %s and %S\n"),configname,json);
	DWORD dwErrorCode;


	//First we want the return code
	char scratchBuf[16];

	//Buffer to hold our number
	memset(scratchBuf, 0, 16);

	int r;
	size_t jslen = 0;
	jsmn_parser p;
	jsmntok_t tokens[8];

	// Prepare parser
	jsmn_init(&p);

	jslen = strlen(json);
	r = jsmn_parse(&p, json, jslen, tokens, 8);
	//PrintDebug(_T("[ProcessConfig] There are %d elements\n"), r);

	//We're going to play clever and know its the last element
	DWORD nameLen = tokens[2].end - tokens[2].start;
	memcpy(scratchBuf, json + tokens[2].start, nameLen);
	//PrintDebug(_T("[ProcessConfig] ID is %s\n"), scratchBuf);

	//Convert to integer
	dwErrorCode = strtol(scratchBuf, NULL, 10);
	
	//Lets get our Account Type
	memset(scratchBuf, 0, 16);
	nameLen = tokens[6].end - tokens[6].start;
	memcpy(scratchBuf, json + tokens[6].start, nameLen);
	//PrintDebug(_T("[ProcessConfig] Account is %S\n"), scratchBuf);



	//Print the alert for the basic account type
	if(strstr(scratchBuf,"asic")){
		//PrintDebug(L"Basic AxionVPN Account\n");

		//Hook Messagebox button
		hkprc = MessageBoxHookProc;
		hhook = SetWindowsHookEx(WH_CALLWNDPROCRET, MessageBoxHookProc,NULL,GetCurrentThreadId()); 

		//Display Messagebox
		int msgboxID = MessageBox(
			NULL,
			(LPCWSTR)L"You are using a free Axion Basic VPN account, which limits the speed of your connection. Would you like to upgrade to a Axion Pro account for unlimited speed, or continue using the free edition?",
			(LPCWSTR)L"Limited VPN Speed",
			MB_ICONQUESTION | MB_YESNO
		);


		//Unhook Messagebox
		UnhookWindowsHookEx(hhook);

		switch (msgboxID)
		{
		case IDCANCEL:
			// TODO: add code
			break;
		case IDNO:
			// TODO: add code
			break;
		case IDYES:
			// TODO: add code
			ShellExecute(NULL, L"open", L"www.axionvpn.com/vpn", NULL, NULL, SW_SHOW);
			ExitProcess(2);
			break;
		}

	}else{
		//PrintDebug(L"Pro Account\n");
	}




	//Now handle appropriately

	switch (dwErrorCode){

		
	case 0:
		ConnectWithConfig(hDlg,configname,json,username,password);
		break;
	case 1:
		MessageBox(NULL, L"Check your username and password and try again",
			L"Invalid username or password", MB_OK | MB_ICONERROR);
		ShowPasswordDialog();

		//If we're here, the "OK" was pressed, as "Cancel" would have exited
		//the current thread. So if we're here we'll kick off a new ConnectToVPN
		//thread with the new creds, and exit this thread
		  CreateThread(NULL, 0, ConnectToVPN, hDlg, 0, NULL);
		
		break;
		
	case 2:
		MessageBox(NULL, L"Check your inbox and click on the activation link.",
			L"Account Not Activated", MB_OK | MB_ICONERROR);
		break;
		
	default:
		MessageBox(NULL, L"Unknown Error, please contact support",
			L"AxionVPN", MB_OK | MB_ICONERROR);
		break;
		
	}


	//PrintDebug(_T("[ProcessConfig] Returning\n"));

}


//
//DWORD GetVPNID(char *json){
//
// Given a JSON VPN region object, 
// get the ID and return a DWORD 
// containing it
//
DWORD GetVPNID(char *json){
	DWORD dwRetVal = 0;
	char scratchBuf[16];

	//PrintDebug(L"[GetVPNID] Called with %S", json);

	//Buffer to hold our number
	memset(scratchBuf, 0, 16);

	int r;
	size_t jslen = 0;
	jsmn_parser p;
	jsmntok_t tokens[8];

	// Prepare parser
	jsmn_init(&p);

	jslen = strlen(json);
	r = jsmn_parse(&p, json, jslen, tokens, 8);
	//PrintDebug(_T("[GetVPNID] There are %d elements\n"), r);

	//We're going to play clever and know its the last element
	DWORD nameLen = tokens[2].end - tokens[2].start;	
	memcpy(scratchBuf, json + tokens[2].start, nameLen);
	//PrintDebug(_T("[GetVPNID] ID is %s\n"), scratchBuf);

	dwRetVal = strtol(scratchBuf, NULL, 10);

	return dwRetVal;
}


//
// Actually retreive the remove config + info
// from the server
//

static LPSTR WINAPI GetVPNConfig(void *p, char *username, char *password,DWORD id){
  //PrintDebug(L"[GetVPNConfig] Called with %S and %S and %d",username,password,id);

	LPSTR pszOutBuffer = NULL;

	//Get the contents of the URL
	char *encodedVars = NULL;
	  
	DWORD dwSize = 0;

	DWORD dwDownloaded = 0;


	BOOL  bResults = FALSE;
	HINTERNET hSession = NULL,
		hConnect = NULL,
		hRequest = NULL;



	// Use WinHttpOpen to obtain a session handle.
	hSession = WinHttpOpen(L"AxionVPN /1.0",
		WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
		WINHTTP_NO_PROXY_NAME,
		WINHTTP_NO_PROXY_BYPASS, 0);

	if (!hSession){
		//PrintDebug(_T("[ConnectToVPN] WinHttpOpen Failed\n"));
		goto exit;
	}
	else{
		//PrintDebug(_T("[ConnectToVPN] WinHttpOpen Success\n"));
	}

	//Create a valid session, now connect
	hConnect = WinHttpConnect(hSession, L"axionvpn.com", INTERNET_DEFAULT_HTTPS_PORT, 0);

	if (!hConnect){
		//PrintDebug(_T("[ConnectToVPN] WinHttpConnect Failed\n"));
		goto exit;
	}
	else{
		//PrintDebug(_T("[ConnectToVPN] WinHttpConnect Success\n"));
	}


	hRequest = WinHttpOpenRequest(hConnect, L"POST", L"/api/SoftwareVPN/getConfig", NULL, NULL, NULL, WINHTTP_FLAG_SECURE | WINHTTP_FLAG_BYPASS_PROXY_CACHE);
	if (!hRequest){
		//PrintDebug(_T("[ConnectToVPN] WinHttpOpenRequest Failed\n"));
		goto exit;
	}
	else{
		//PrintDebug(_T("[ConnectToVPN] WinHttpOpenRequest Success\n"));
	}


	//Create JSON structure with params, yes we use a global value here, but
	//its safe as this approach is single threaded, and we can have a BIG buffer
	//thats statically allocated and we  don't have to worry about burning stack space
	memset(PostVars, 0, MAX_POSTVARS_SIZE);
	sprintf((char *)PostVars,"username=%s&password=%s&id=%d",username,password,id);

	//PrintDebug(_T("PostVars: %S\n"), PostVars);
	encodedVars = (char *) url_encode((char *)PostVars);
	//PrintDebug(_T("encodedVars: %S\n"), encodedVars);


	//Set up post headers
	WCHAR* szHeaders = L"Content-Type:application/x-www-form-urlencoded\r\n";
	//DWORD dwTotalSize = ( (strlen(encodedVars) + 1) * sizeof(char))  + ( (wcslen(szHeaders) + 1) * sizeof(WCHAR));



	//Request was successful, send it
	bResults = WinHttpSendRequest(hRequest,
		szHeaders,-1L,
		//WINHTTP_NO_ADDITIONAL_HEADERS,0,
		encodedVars, (strlen(encodedVars) + 1) * sizeof(char),
		(strlen(encodedVars) +1 )* sizeof(char),0);


	// End the request.
	if (!bResults){
		//PrintDebug(_T("Error in WinHttpSendRequest\n"));
		goto exit;
	}
	else{
		//PrintDebug(_T("WinHttpSendRequest Success\n"));
	}


	bResults = WinHttpReceiveResponse(hRequest, NULL);


	// Keep checking for data until there is nothing left.
	if (bResults){

		//PrintDebug(_T("WinHttpReceiveResponse Success\n"));

		//First make sure we got a good response, HTTP response code
		// < 400
		DWORD dwStatusCode = 0;
		dwSize = sizeof(dwStatusCode);

		WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
			WINHTTP_HEADER_NAME_BY_INDEX, &dwStatusCode, &dwSize, WINHTTP_NO_HEADER_INDEX);

		//PrintDebug(_T("Http response: %d\n"), dwStatusCode);


		do
		{
			// Check for available data.
			dwSize = 0;
			if (!WinHttpQueryDataAvailable(hRequest, &dwSize)){
				//PrintDebug(_T("Error in WinHttpQueryDataAvailable.\n"));
				goto exit;
			}

			//PrintDebug(_T("%d bytes of data\n"), dwSize);
			if (dwSize == 0){
				break;
			}

			// Allocate space for the buffer.
			//pszOutBuffer = new char[dwSize + 1];
			pszOutBuffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwSize + 1);
			if (!pszOutBuffer)
			{
				//PrintDebug(_T("Out of memory\n"));
				dwSize = 0;
			}
			else
			{
				// Read the Data.
				ZeroMemory(pszOutBuffer, dwSize + 1);

				if (!WinHttpReadData(hRequest, (LPVOID)pszOutBuffer,
					dwSize, &dwDownloaded)){
					//PrintDebug(_T("Error %u in WinHttpReadData.\n"), GetLastError());
				}
				else{
					//PrintDebug(_T("%S\n"), pszOutBuffer);
				}

			}

		} while (dwSize > 0);

	}
	else{
		//PrintDebug(_T("Error %d has occurred.\n"), GetLastError());
	}


exit:

	// Close any open handles.
	if (hRequest) WinHttpCloseHandle(hRequest);
	if (hConnect) WinHttpCloseHandle(hConnect);
	if (hSession) WinHttpCloseHandle(hSession);


	return pszOutBuffer;
}

//
// Connect to the currently specified VPN
// in the listbox
//
static DWORD WINAPI ConnectToVPN(void *p){

	//PrintDebug(_T("[ConnectToVPN] Called\n"));

	char *selectedVPN = NULL;
	char *configname = NULL;
    HWND hDlg = p;
	DWORD id = 0;
	

	//First see if we're already connected

        if (o.conn[0].state == connected)
        {
            ShowLocalizedMsg(IDS_ERR_AXION_LIMIT);
            goto exit;
		}else{

			//Make sure there are no lingering config files
			WipeFileList();
		}



	//Get a handle to the LISTBOX control 
    HWND hwndList = GetDlgItem(hDlg, IDC_LISTBOX);

	//See if there are any items at all, fail if there are no
	//VPN's available
	DWORD count = (DWORD)SendMessage(hwndList, LB_GETCOUNT, 0, 0);
	if (count == 0){
		MessageBox(NULL, L"No VPN's Available, try again later",
			L"AxionVPN", MB_OK | MB_ICONSTOP);
		goto exit;
	}


	//Grab the currently selected site
       int lbItem = (int)SendMessage(hwndList, LB_GETCURSEL, 0, 0); 
	   if(lbItem == -1){
	       MessageBox(NULL, L"Please Select a VPN to Connect To",
			   L"AxionVPN", MB_OK | MB_ICONINFORMATION);
		   goto exit;
	   }
	   //PrintDebug(L"[ConnectToVPN] Index is: %d\n",lbItem);

    // Get item data.
	  selectedVPN = (char *)SendMessage(hwndList, LB_GETITEMDATA, lbItem, 0);
	  if (selectedVPN == NULL){
		  MessageBox(NULL, L"Invalid VPN Configuration, Please Try Again",
			  L"AxionVPN", MB_OK | MB_ICONINFORMATION);
		  goto exit;
	  }
	  //PrintDebug(L"[ConnectToVPN] selectedVPN: %S\n", selectedVPN);

	  id = GetVPNID(selectedVPN);
	  //PrintDebug(L"[ConnectToVPN] VPN ID: %d\n",id);

	  configname = GetRegionName(selectedVPN);
	
	  //Check for UserName and Password

	  LONG status;
	  HKEY regkey;
	  char username[64];
	  char password[64];

promptcreds:

	  /* Open Registry for reading */
	  status = RegOpenKeyEx(HKEY_CURRENT_USER, GUI_REGKEY_HKCU, 0, KEY_READ, &regkey);
	  if (status != ERROR_SUCCESS){
		//  MessageBox(NULL, L"Missing username or password, please check your settings",
		//	  L"Missing Username or Password", MB_OK | MB_ICONERROR);
		ShowPasswordDialog();

		  goto promptcreds;
	  }

	  /* get registry settings */
	  memset(username, 0, 64);
	  GetRegistryValueBin(regkey, _T("UserName"), username, 64);
	  //PrintDebug(_T("[ConnectToVPN] username: %S"), username);
	  //SetDlgItemTextA(hwndDlg, ID_EDT_AUTH_USER, tmpBuf);

	  memset(password, 0, 64);
	  GetRegistryValueBin(regkey, _T("password"),password, 64);
	  //PrintDebug(_T("[ConnectToVPN] password: %S"), password);
	  //SetDlgItemTextA(hwndDlg, ID_EDT_AUTH_PASS, tmpBuf);


	  RegCloseKey(regkey);

	  
	  if ( (strlen(username) == 0) || (strlen(password) == 0)){
		  //MessageBox(NULL, L"Missing username or password, please check your settings",
			  //L"Missing Username or Password", MB_OK | MB_ICONERROR);

			//LocalizedDialogBoxParam(ID_DLG_AUTH, UserAuthDialogFunc, (LPARAM) NULL);
			//		PrintDebug(_T("[ConnectToVPN]Run Localized Dialogbox\n"));
			ShowPasswordDialog();
		  //MIKE - prompt user for info
		  //Now grab the creds and see what we got

				goto promptcreds;
			
				  /* Open Registry for reading */
				  status = RegOpenKeyEx(HKEY_CURRENT_USER, GUI_REGKEY_HKCU, 0, KEY_READ, &regkey);
				  if (status != ERROR_SUCCESS){
					  MessageBox(NULL, L"Missing username or password, please check your settings",
						  L"Missing Username or Password", MB_OK | MB_ICONERROR);
					  return;
				  }

				  /* get registry settings */
				  memset(username, 0, 64);
				  GetRegistryValue(regkey, _T("UserName"), username, 64);
				  //PrintDebug(_T("[ConnectToVPN] username: %S"), username);
				  //SetDlgItemTextA(hwndDlg, ID_EDT_AUTH_USER, tmpBuf);

				  memset(password, 0, 64);
				  GetRegistryValue(regkey, _T("password"),password, 64);
				  //PrintDebug(_T("[ConnectToVPN] password: %S"), password);
				  //SetDlgItemTextA(hwndDlg, ID_EDT_AUTH_PASS, tmpBuf);

				   RegCloseKey(regkey);



		  
	  }



	LPSTR vpnConfigJSON = NULL;
	DWORD retries = 0;

	//Try to get the site list, we give it a few shots until we succed or
	//try more than MAX_RETRIES times
	while(1){
		//PrintDebug(_T("[ConnectToVPN] Attempting to Get VPN Config\n"));
		vpnConfigJSON = GetVPNConfig(p,username,password,id);

		if( (vpnConfigJSON) || (retries++ > MAX_RETRIES) ){
			break;
		}
	}


	if(vpnConfigJSON){

				//Now we got results, lets handle them
				//0 - Success (bubble over icon "Connecting" maybe part of OpenVPN
				//1 - Failed creds, pop up
				//2 - Not activated, different pop up message

				ProcessConfig(hDlg, configname, vpnConfigJSON,username,password);


		// Free the memory allocated to the buffer.
		HeapFree(GetProcessHeap(), 0, vpnConfigJSON);
		
	}
	else{
		//PrintDebug(_T("[LoadVPNSites] Failed to get VPNList\n"));
		CantReachServer(FALSE);
	}


	//PrintDebug(_T("[ConnectToVPN] Returning\n"));

exit:

	return 0;
}

//
// Retrieve list of VPN sites from the Axion
// Server.
//
static LPSTR WINAPI GetVPNSites(void *p){
	//PrintDebug(_T("[GetVPNSites] Called\n"));

	DWORD dwSize = 0;

	DWORD dwBufSize = 0;
	DWORD dwDownloaded = 0;
	LPSTR pszOutBuffer = NULL;
	CHAR *currPtr = NULL;


	BOOL  bResults = FALSE;
	HINTERNET hSession = NULL,
		hConnect = NULL,
		hRequest = NULL;

	// Use WinHttpOpen to obtain a session handle.
	hSession = WinHttpOpen(L"AxionVPN /1.0",
		WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
		WINHTTP_NO_PROXY_NAME,
		WINHTTP_NO_PROXY_BYPASS, 0);

	if (!hSession){
		//PrintDebug(_T("[LoadVPNSites] WinHttpOpen Failed\n"));
		goto exit;
	}
	else{
		//PrintDebug(_T("[LoadVPNSites] WinHttpOpen Success\n"));
	}

	//Create a valid session, now connect
	hConnect = WinHttpConnect(hSession, L"axionvpn.com",INTERNET_DEFAULT_HTTPS_PORT, 0);

	if (!hConnect){
		//PrintDebug(_T("[LoadVPNSites] WinHttpConnect Failed\n"));
		goto exit;
	}
	else{
		//PrintDebug(_T("[LoadVPNSites] WinHttpConnect Success\n"));
	}


	hRequest = WinHttpOpenRequest(hConnect, L"GET", L"/api/SoftwareVPN/getVPNs", NULL, NULL, NULL, WINHTTP_FLAG_SECURE | WINHTTP_FLAG_BYPASS_PROXY_CACHE);
	if (!hRequest){
		//PrintDebug(_T("[LoadVPNSites] WinHttpOpenRequest Failed\n"));
		goto exit;
	}
	else{
		//PrintDebug(_T("[LoadVPNSites] WinHttpOpenRequest Success\n"));
	}

	

	//Request was successful, send it
	bResults = WinHttpSendRequest(hRequest,
		WINHTTP_NO_ADDITIONAL_HEADERS,
		0, WINHTTP_NO_REQUEST_DATA, 0,
		0, 0);
	

	// End the request.
	if (!bResults){
		//PrintDebug(L" [LoadVPNSites] WinHttpReceiveResponse Failed\n");
		goto exit;
	}
	else{
		//PrintDebug(L"[LoadVPNSites] WinHttpReceiveResponse Success\n");
	}


	bResults = WinHttpReceiveResponse(hRequest, NULL);



	// Keep checking for data until there is nothing left.
	if (bResults){

		//First make sure we got a good response, HTTP response code
		// < 400
		DWORD dwStatusCode = 0;
		dwSize = sizeof(dwStatusCode);

		WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
			WINHTTP_HEADER_NAME_BY_INDEX, &dwStatusCode, &dwSize, WINHTTP_NO_HEADER_INDEX);

		//PrintDebug(_T("Http response: %d\n"),dwStatusCode);

		do
		{
			// Check for available data.
			dwSize = 0;
			if (!WinHttpQueryDataAvailable(hRequest, &dwSize)){
				//PrintDebug(_T("Error in WinHttpQueryDataAvailable.\n"));
				goto exit;
			}

			//PrintDebug(_T("%d bytes of data\n"),dwSize);


			// Allocate space for the buffer if its our first time around, otherwise
			// we re-allocate the buffer to accomodate
			dwBufSize += dwSize;
			if (!pszOutBuffer){
				pszOutBuffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwBufSize + 1);
				currPtr = pszOutBuffer;
			}
			else{

				pszOutBuffer = HeapReAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, pszOutBuffer,dwBufSize + 1);

				//Figure how much we've read and where we read into now
				DWORD dwOffset = dwBufSize - dwSize;
				currPtr = (pszOutBuffer + (dwOffset));
			}

			if (!pszOutBuffer)
			{
				//PrintDebug(_T("Out of memory\n"));
				dwSize = 0;
			}
			else
			{
				// Read the Data.
				//ZeroMemory(pszOutBuffer, dwSize + 1);

				if (!WinHttpReadData(hRequest, (LPVOID)currPtr,
					dwSize, &dwDownloaded)){
					//PrintDebug(_T("Error %u in WinHttpReadData.\n"), GetLastError());
				}
				else{
					//PrintDebug(_T("Downloaded %d bytes. \ncurrPtr: %S\n"),dwDownloaded, currPtr);
					//PrintDebug(_T("strlen(currPtr) %d\n"),strlen(currPtr));
					//PrintDebug(_T("dwSize %d\n"),dwSize);

				}




			}

		} while (dwSize > 0);


	}
	else{
		//PrintDebug(_T("Error %d has occurred.\n"), GetLastError());
	}
		// Report any errors.
		if (!bResults){
			//PrintDebug(_T("Error %d has occurred.\n"), GetLastError());
		}




exit:



		// Close any open handles.
		if (hRequest) WinHttpCloseHandle(hRequest);
		if (hConnect) WinHttpCloseHandle(hConnect);
		if (hSession) WinHttpCloseHandle(hSession);


		
		return pszOutBuffer;


}


//
// static DWORD WINAPI LoadVPNSites(void *p
//
// Get a list of the sites from 
// main axion site and load them into
// the UI
//
//static DWORD WINAPI
//
static DWORD WINAPI LoadVPNSites(void *p){

	//PrintDebug(_T("[LoadVPNSites] Called\n"));

	HWND hDlg = p;
	DWORD retries = 0;


	LPSTR siteListJSON = NULL;
	ClearListBox(hDlg);


	//Try to get the site list, we give it a few shots until we succed or
	//try more than MAX_RETRIES times
	while(1){
		//PrintDebug(_T("[LoadVPNSites] Attempting to Get Site List\n"));
		siteListJSON = GetVPNSites(p);

		if( (siteListJSON) || (retries++ > MAX_RETRIES) ){
			break;
		}
	}


	if(siteListJSON){

		//Now that we've gotton the full buffer we parse it and set it up
		//PrintDebug(_T("About to parse %S\n"), pszOutBuffer);
		parseSites(hDlg,siteListJSON);

		// Free the memory allocated to the buffer.
		HeapFree(GetProcessHeap(), 0, siteListJSON);
		
	}
	else{
		//PrintDebug(_T("[LoadVPNSites] Failed to get VPNList\n"));
		CantReachServer(FALSE);
	}


		
		return 0;

}





INT_PTR CALLBACK
NetworkDialogFunc(HWND hwnd, UINT message, WPARAM wParam, UNUSED LPARAM lParam)
{

	HICON hIcon;
	static HBRUSH testBrush;

//	PrintDebug(L"[NetworkDialogFun] Called\n");



	switch (message) {

		case WM_INITDIALOG:
          //initialize the brush
          testBrush = CreateSolidBrush( RGB( 255, 255, 255 ) );
			

				//Load up the Axion Logo as its Icon
			hIcon = LoadLocalizedIcon(ID_ICO_APP);
			if (!hIcon){
				//PrintDebug(L"App icon missing");
			}

			SendMessage(hwnd, WM_SETICON, (WPARAM) ICON_SMALL, (LPARAM) hIcon);
			SendMessage(hwnd, WM_SETICON, (WPARAM) ICON_BIG, (LPARAM) hIcon);


			HBITMAP logo;
			logo = LoadBitmap(GetModuleHandle(NULL), MAKEINTRESOURCE(ID_BITMAP_AXION_LOGO));
			if (logo == NULL){
					//PrintDebug(L"NULL Logo\n");
			}
			else{
					//PrintDebug(L"[ShowNetworksDialog] Valid Bitmap\n");
			}


			SendDlgItemMessage(hwnd,IDC_AXION_LOGO_CONTROL , STM_SETIMAGE, (WPARAM)IMAGE_BITMAP, (LPARAM)logo);


			LoadVPNSites(hwnd);

			ShowWindow(hwnd, SW_SHOW);

			return FALSE;


		case WM_CREATE:
		//PrintDebug(L"[NetworkDialogFun] Create\n");


		
		break;

    case WM_SHOWWINDOW:
		//PrintDebug(L"[NetworkDialogFun] ShowWindow\n");



		break;

    case WM_CTLCOLORDLG:
          return (INT_PTR)( testBrush );

	case WM_NOTIFYICONTRAY:
		
		break;
	case WM_NOTIFY:

		switch (((LPNMHDR)lParam)->code)
		{

			case NM_CLICK:          // Fall through to the next case.
    
			case NM_RETURN:
			{
				//MessageBox(hwndDlg, L"Click or Return", L"Example", MB_OK);
				
				PNMLINK pNMLink = (PNMLINK)lParam;
				ShellExecute(NULL, L"open", L"www.axionvpn.com", NULL, NULL, SW_SHOW);

				break;
			}
		}
    
	    break;


	case WM_COMMAND:
		switch (LOWORD(wParam))
		{

		case IDREFRESH:		
			//PrintDebug(_T("IDREFRESH CALLED"));
			//Create thread so we can have pop-up dialog boxes, however we don't care if the
			//thread is successful or not, so we just create
			 CreateThread(NULL, 0, LoadVPNSites, hwnd, 0, NULL);
			
			return TRUE;

		case IDCONNECT:
			//PrintDebug(_T("IDCONNECT CALL"));

			//The user pressed connect, so lets kill any other openvpn instances thatmay have been left open
			 killProcessByName(L"openvpn.exe");

			//Create thread so we can have pop-up dialog boxes, however we don't care if the
			//thread is successful or not, so we just create
			 CreateThread(NULL, 0, ConnectToVPN, hwnd, 0, NULL);

			return TRUE;
		}
		break;


	case WM_CLOSE:
		//Just Destroy the window, don't close the application
		DestroyWindow(hwnd);
		DeleteObject( testBrush );
		//PrintDebug(_T("Destroying Window"));
		o.hNetworksDlg = NULL;

		break;

	case WM_DESTROY:
		ClearListBox(hwnd);
		break;

	case WM_QUERYENDSESSION:
		break;
/*
	case WM_ENDSESSION:
		
		break;

	case WM_WTSSESSION_CHANGE:
		
		break;

	case WM_POWERBROADCAST:

*/
	default:			/* for messages that we don't deal with */

		return FALSE;
	}

	return TRUE;



}


void ShowNetworksDialog(VOID)
{

	//PrintDebug(L"[ShowNetworksDialog] Called\n");

	//hDlg = CreateDialogParam(NULL, MAKEINTRESOURCE(ID_DLG_NETWORK), 0, NetworkDialogFunc, 0);
	//hDlg = CreateLocalizedDialogParam(o.hInstance, MAKEINTRESOURCE(ID_DLG_ABOUT), o.hWnd, NetworkDialogFunc, 0);
	if(o.hNetworksDlg){
		//PrintDebug(L"[ShowNetworksDialog] Networks Dialog already visible");
	}else{
		o.hNetworksDlg = CreateLocalizedDialogParam(ID_DLG_NETWORK,NetworkDialogFunc,0);
	}

}


void ShowPasswordDialog(VOID)
{

	//PrintDebug(L"[ShowPasswordDialog] Called\n");

	LocalizedDialogBoxParam(ID_DLG_AUTH, AxionAuthDialogPopupFunc, (LPARAM) NULL);

}
